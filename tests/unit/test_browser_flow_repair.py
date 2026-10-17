"""Exercise the actual shell repair across persistent/restarted CLI state.

The fake transport makes interruption and no-policy-change assertions
deterministic. It is not evidence that a mock issuer authenticates users.
"""
import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def state_for(legacy=True):
    realm = json.loads((ROOT/'config/realm/baobab-realm.json').read_text())
    flows = realm['authenticationFlows']
    if legacy:
        browser = next(f for f in flows if f['alias'] == 'Baobab browser')
        primary = next(f for f in flows if f['alias'] == 'Baobab - Primary Authentication')
        browser['authenticationExecutions'] = [e for e in primary['authenticationExecutions'] if e['requirement']=='ALTERNATIVE'] + browser['authenticationExecutions'][1:]
        flows.remove(primary)
    if legacy:
        passkey = next(f for f in flows if f['alias']=='Baobab - Passkey Step-Up')
        passkey['authenticationExecutions'] = [e for e in passkey['authenticationExecutions'] if e.get('authenticator')!='conditional-user-configured']
        realm['authenticatorConfig'] = [c for c in realm['authenticatorConfig'] if c['alias'] != 'baobab-primary-loa-silver']
    configs = [dict(c, id='config-'+str(i)) for i, c in enumerate(realm['authenticatorConfig'])]
    ids = {flow['alias']: 'flow-'+str(i) for i, flow in enumerate(flows)}
    models = []
    for flow in flows:
        for entry in flow['authenticationExecutions']:
            model = {k: v for k, v in entry.items() if k != 'flowAlias'}
            model.update(id='execution-'+str(len(models)), parentFlow=ids[flow['alias']])
            if entry.get('authenticatorFlow'):
                model['flowId'] = ids[entry['flowAlias']]
            if entry.get('authenticatorConfig'):
                model['authenticatorConfig'] = next(c['id'] for c in configs if c['alias'] == entry['authenticatorConfig'])
            models.append(model)
    return {'browserFlow': realm['browserFlow'], 'flows': [
        {'id': ids[f['alias']], 'alias': f['alias'], 'builtIn': False, 'topLevel': f['topLevel']} for f in flows],
        'executions': models, 'configs': configs}


class BrowserRepairTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'state.json'

    def invoke(self, state=None, fail=False, fail_config=False):
        if state is not None:
            self.path.write_text(json.dumps(state))
        env = dict(os.environ, BROWSER_FIXTURE_STATE=str(self.path), BROWSER_FIXTURE_FAIL_COPY='1' if fail else '0',
                   BROWSER_FIXTURE_FAIL_CONFIG='1' if fail_config else '0')
        shell = ('set -euo pipefail\nsource '+shlex.quote(str(ROOT/'scripts/reconcile_browser_primary.sh'))+'\n'
                 'kcadm() { python3 '+shlex.quote(str(ROOT/'tests/unit/browser_flow_kcadm_fixture.py'))+' "$@"; }\n'
                 'trap \'if [ -n "${BROWSER_REPAIR_DIR:-}" ]; then rm -rf -- "$BROWSER_REPAIR_DIR"; fi\' EXIT\n'
                 'reconcile_browser_primary\n')
        result = subprocess.run(['bash', '-c', shell], env=env, capture_output=True, text=True, timeout=30)
        return result, json.loads(self.path.read_text())

    def test_legacy_repair_retains_all_existing_policy_records(self):
        before = state_for()
        result, after = self.invoke(before)
        self.assertEqual(result.returncode, 0, result.stderr)
        old = {e['id']: e for e in before['executions']}
        root_id = next(f['id'] for f in before['flows'] if f['alias'] == 'Baobab browser')
        for model in after['executions']:
            if model['id'] not in old:
                continue
            expected = copy.deepcopy(old[model['id']])
            if expected['parentFlow'] == root_id and expected['requirement'] == 'ALTERNATIVE':
                expected['requirement'] = 'DISABLED'
            self.assertEqual(model, expected)  # OTP/passkey/configuration identities untouched.
        self.assertEqual(len(after['flows']), len(before['flows'])+1)
        self.assertEqual(len(after['executions']), len(before['executions'])+6)

    def test_repeated_repair_is_idempotent(self):
        first, state = self.invoke(state_for())
        self.assertEqual(first.returncode, 0, first.stderr)
        second, again = self.invoke()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(state, again)

    def test_failed_copy_never_attaches_partial_primary_and_retry_resumes(self):
        before = state_for()
        failed, partial = self.invoke(before, fail=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(before['executions'], partial['executions'])
        success, after = self.invoke()
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(len(after['executions']), len(before['executions'])+6)

    def test_operator_disabled_identification_is_not_reactivated(self):
        state = state_for()
        next(e for e in state['executions'] if e.get('authenticator') == 'auth-cookie')['requirement'] = 'DISABLED'
        failed, after = self.invoke(state)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(state, after)

    def test_fresh_import_is_a_noop(self):
        state = state_for(legacy=False)
        result, after = self.invoke(state)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state, after)

    def test_custom_browser_binding_is_not_overridden(self):
        state = state_for()
        state['browserFlow'] = 'Operator reviewed custom browser'
        failed, after = self.invoke(state)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(state, after)

    def test_keycloak_omitted_primitive_defaults_keep_false_and_zero_semantics(self):
        for legacy in (False, True):
            state = state_for(legacy=legacy)
            state['omitDefaults'] = True
            result, after = self.invoke(state)
            self.assertEqual(result.returncode, 0, result.stderr)
            result, again = self.invoke()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(after, again)

    def test_previous_required_wrapper_migrates_without_copying_policy(self):
        state = state_for(legacy=False)
        primary_id = next(f['id'] for f in state['flows'] if f['alias']=='Baobab - Primary Authentication')
        state['executions'] = [e for e in state['executions'] if not (e['parentFlow']==primary_id and e.get('authenticator')=='conditional-level-of-authentication')]
        next(e for e in state['executions'] if e.get('flowId')==primary_id)['requirement']='REQUIRED'
        state['configs'] = [c for c in state['configs'] if c['alias']!='baobab-primary-loa-silver']
        result, after = self.invoke(state)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(next(e for e in after['executions'] if e.get('flowId')==primary_id)['requirement'],'CONDITIONAL')
        self.assertEqual(len(after['executions']),len(state['executions'])+1)

    def test_interrupted_baseline_config_keeps_primary_required_and_retry_resumes(self):
        failed, partial = self.invoke(state_for(), fail_config=True)
        self.assertNotEqual(failed.returncode,0)
        primary_id = next(f['id'] for f in partial['flows'] if f['alias']=='Baobab - Primary Authentication')
        self.assertEqual(next(e for e in partial['executions'] if e.get('flowId')==primary_id)['requirement'],'REQUIRED')
        success, final = self.invoke()
        self.assertEqual(success.returncode,0,success.stderr)
        self.assertEqual(next(e for e in final['executions'] if e.get('flowId')==primary_id)['requirement'],'CONDITIONAL')

    def test_inflated_or_persistent_baseline_is_refused(self):
        for field,value in [('loa-condition-level','2'),('loa-max-age','300')]:
            state = state_for(legacy=False)
            next(c for c in state['configs'] if c['alias']=='baobab-primary-loa-silver')['config'][field]=value
            failed, after = self.invoke(state)
            self.assertNotEqual(failed.returncode,0)
            self.assertEqual(state,after)

    def test_custom_passkey_strength_is_not_changed(self):
        state=state_for(legacy=False)
        next(c for c in state['configs'] if c['alias']=='baobab-passkey-step-up-loa-3')['config']['loa-condition-level']='2'
        result,after=self.invoke(state)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(state,after)
