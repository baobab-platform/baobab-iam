"""Preparation is least-privilege and cannot stand in for registry activation."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('int03_fixture', ROOT / 'scripts/int03_cms_fixture.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.deadline = self.now + timedelta(minutes=30)
        self.registry = {'workloads': copy.deepcopy(m.EXPECTED)}

    def clients(self):
        return m.build_clients(self.registry, self.deadline, self.now)

    def test_all_row_fields_and_extra_authority_are_closed(self):
        for name, row in m.EXPECTED.items():
            self.assertTrue(m.fixture_only(name, row))
            for key in row:
                changed = copy.deepcopy(row)
                changed[key] = ['unexpected'] if isinstance(changed[key], list) else 'unexpected'
                self.assertFalse(m.fixture_only(name, changed))
                del changed[key]
                self.assertFalse(m.fixture_only(name, changed))
            self.assertFalse(m.fixture_only(name, dict(row, extra_authority=True)))
        self.assertFalse(m.fixture_only('nabhold-backend', m.EXPECTED[m.CALLER]))
        for name in m.EXPECTED:
            for file in (ROOT / 'config/clients').glob('*.json'):
                self.assertNotEqual(json.loads(file.read_text()).get('clientId'), name)

    def test_absent_or_half_pair_cannot_prepare(self):
        for registry in ({}, None, {'workloads': None}, {'workloads': {m.CALLER: m.EXPECTED[m.CALLER]}}):
            with self.assertRaises(ValueError):
                m.build_clients(registry, self.deadline, self.now)

    def test_deadline_is_bounded_and_timezone_aware(self):
        for deadline in (None, self.now, self.now + timedelta(seconds=60), self.now + timedelta(seconds=5401), self.now.replace(tzinfo=None)):
            with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                m.build_clients(self.registry, deadline, self.now)
        self.assertEqual(len(m.build_clients(self.registry, self.now + timedelta(seconds=5400), self.now)), 2)

    def test_independent_secrets_and_separate_optional_scopes(self):
        clients = self.clients()
        next_clients = self.clients()
        self.assertNotEqual(clients[m.CALLER]['secret'], clients[m.VALIDATOR]['secret'])
        self.assertNotEqual(clients[m.CALLER]['secret'], next_clients[m.CALLER]['secret'])
        self.assertEqual(clients[m.CALLER]['optionalClientScopes'], ['context:resolve', 'content:entry:resolve'])
        self.assertEqual(clients[m.VALIDATOR]['optionalClientScopes'], ['context:validate'])
        for client in clients.values():
            self.assertFalse(client['fullScopeAllowed'])
            self.assertEqual(client['attributes']['access.token.lifespan'], '60')
            self.assertEqual(client['defaultClientScopes'], ['basic', 'actor-type-workload'])
        with patch.object(m.secrets, 'token_urlsafe', return_value='s' * 64), self.assertRaises(ValueError):
            self.clients()

    def test_readback_security_fields_and_secret_are_independent(self):
        for expected in self.clients().values():
            observed = copy.deepcopy(expected)
            observed['id'] = 'issuer-managed-id'
            observed['secret'] = '**********'
            secret = {'type': 'secret', 'value': expected['secret']}
            self.assertTrue(m.verify_readback(expected, observed, secret))
            for key in expected:
                if key == 'secret':
                    continue
                changed = copy.deepcopy(observed)
                changed[key] = ['unapproved'] if isinstance(expected[key], list) else None
                self.assertFalse(m.verify_readback(expected, changed, secret), key)
            for changed in (dict(observed, protocolMappers=[{'name': 'extra'}]), dict(observed, attributes=dict(observed['attributes'], extra='true')), dict(observed, enabled=1)):
                self.assertFalse(m.verify_readback(expected, changed, secret))
            for value in ('wrong', None, [], 'nonascii\N{SNOWMAN}'):
                self.assertFalse(m.verify_readback(expected, observed, {'type': 'secret', 'value': value}))
            tampered = dict(expected, fullScopeAllowed=True)
            self.assertFalse(m.verify_readback(tampered, tampered, secret))
        self.assertFalse(m.verify_readback(None, {}, {}))

    def test_runtime_readback_reads_actual_endpoint_shapes_and_denies_extra_authority(self):
        for expected in self.clients().values():
            client_id = '00000000-0000-4000-8000-000000000001'
            user_id = '00000000-0000-4000-8000-000000000002'
            client_path = 'clients/' + client_id
            user_path = 'users/' + user_id
            # Actual service-account endpoint omits serviceAccountClientId.
            account = {'id': user_id, 'enabled': True, 'username': 'service-account-' + expected['clientId']}
            # Realm and client-scope reads prove the reader's view is unfiltered.
            responses = {client_path: dict(expected, id=client_id),
                         client_path + '/client-secret': {'type': 'secret', 'value': expected['secret']},
                         '': {'realm': 'baobab', 'adminPermissionsEnabled': False},
                         'default-default-client-scopes': [{'name': 'basic'}],
                         client_path + '/service-account-user': account,
                         user_path + '/role-mappings': {}, user_path + '/groups/count': {'count': 0},
                         user_path + '/federated-identity': []}
            calls = []
            def read(path):
                calls.append(path)
                return responses[path]
            self.assertTrue(m.verify_runtime_readback(expected, client_id, read))
            self.assertEqual(calls, list(responses))
            for field, values in {
                '/role-mappings': [{'realmMappings': [{'name': 'offline_access'}]},
                                  {'clientMappings': {'realm-management': {'mappings': [{'name': 'realm-admin'}]}}},
                                  {'realmMappings': None}, {'clientMappings': []}, {'unreviewed': []}, None],
                '/groups/count': [{'count': 1}, {'count': True}, {'count': '0'}, {'count': 0, 'extra': 0}, [], None],
                '/federated-identity': [[{'identityProvider': 'broker'}], None],
            }.items():
                for value in values:
                    original = responses[user_path + field]
                    responses[user_path + field] = value
                    self.assertFalse(m.verify_runtime_readback(expected, client_id, read), field)
                    responses[user_path + field] = original
            for key, value in (('id', client_id), ('id', 'not-a-uuid'), ('enabled', False), ('enabled', 1),
                               ('username', 'service-account-unrelated'), ('serviceAccountClientId', 'unrelated'),
                               ('realmRoles', ['offline_access']), ('clientRoles', {'realm-management': ['realm-admin']}),
                               ('groups', ['admin']), ('federationLink', 'external-store')):
                responses[client_path + '/service-account-user'] = dict(account, **{key: value})
                self.assertFalse(m.verify_runtime_readback(expected, client_id, read), key)
            responses[client_path + '/service-account-user'] = account
            # A fine-grained admin sees filtered mappings: without proof of an
            # unfiltered view, empty reads must not pass.
            for path, value in (('', {'realm': 'baobab'}), ('', {'realm': 'baobab', 'adminPermissionsEnabled': True}),
                                ('', {'realm': 'baobab', 'adminPermissionsEnabled': None}), ('', None),
                                ('default-default-client-scopes', None), ('default-default-client-scopes', {})):
                original = responses[path]
                responses[path] = value
                self.assertFalse(m.verify_runtime_readback(expected, client_id, read), (path, value))
                responses[path] = original
            def forbidden(path):
                if path == 'default-default-client-scopes':
                    raise PermissionError('403')
                return read(path)
            self.assertFalse(m.verify_runtime_readback(expected, client_id, forbidden))
            responses[client_path]['id'] = user_id
            self.assertFalse(m.verify_runtime_readback(expected, client_id, read))
            self.assertFalse(m.verify_runtime_readback(expected, '../clients/other', read))
            def failed_read(_path):
                raise OSError('private peer failure')
            self.assertFalse(m.verify_runtime_readback(expected, client_id, failed_read))

    def test_duplicate_json_fields_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"status":"ACTIVE","status":"REVOKED"}', object_pairs_hook=m.unique)

    def test_private_exclusive_files_and_no_write_on_pin_refusal(self):
        import yaml
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp) / 'shared'
            registry = checkout / 'contracts/identity/v1/workload-registry.yaml'
            registry.parent.mkdir(parents=True)
            registry.write_text(yaml.safe_dump(self.registry))
            output = Path(temp) / 'private'
            with patch.object(m, 'load_registry', side_effect=ValueError('pin refusal')):
                with self.assertRaises(ValueError):
                    m.prepare(checkout, output, self.deadline)
            self.assertFalse(output.exists())
            with patch.object(m, 'load_registry', return_value=self.registry) as authority:
                documents = m.prepare(checkout, output, self.deadline)
                authority.assert_called_once_with(checkout)
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                for name, document in documents.items():
                    file = output / (name + '.json')
                    self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(json.loads(file.read_text()), document)
                with self.assertRaises(FileExistsError):
                    m.prepare(checkout, output, self.deadline)

    def test_local_lock_edit_cannot_authorize_proposed_registry(self):
        import yaml
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
            git('init', '-q')
            git('config', 'user.name', 'Fixture Test')
            git('config', 'user.email', 'fixture@example.invalid')
            lock = repo / 'contracts.lock.yaml'
            source = {'source': {'repository': 'baobab-platform/shared', 'commit': 'original'}}
            lock.write_text(yaml.safe_dump(source))
            git('add', 'contracts.lock.yaml')
            git('commit', '-qm', 'Committed authority')
            source['source']['commit'] = 'proposed'
            lock.write_text(yaml.safe_dump(source))
            with patch('provider_publication.load_shared') as verify:
                with self.assertRaisesRegex(ValueError, 'committed authority'):
                    m.load_registry(repo, repository=repo)
                verify.assert_not_called()
            git('checkout', '--', 'contracts.lock.yaml')
            with patch('provider_publication.load_shared', return_value=(None, 'proposed')):
                with self.assertRaisesRegex(ValueError, 'committed IAM lock'):
                    m.load_registry(repo, repository=repo)

    def test_native_plan_exact_profiles_and_no_secrets(self):
        from build_workload_token_profiles import build
        commit = 'a' * 40
        plan = m.build_native_plan(self.registry, commit)
        self.assertEqual(plan['token_profiles'], build(commit, self.registry, list(m.EXPECTED), {}, 'development'))
        self.assertFalse(plan['identities_created'])
        self.assertFalse(plan['qualified'])
        def assert_secret_free(value):
            if isinstance(value, dict):
                self.assertTrue(set(value).isdisjoint({"client_secret", "secret", "access_token", "refresh_token"}))
                for child in value.values():
                    assert_secret_free(child)
            elif isinstance(value, list):
                for child in value:
                    assert_secret_free(child)
        assert_secret_free(plan)
        self.assertEqual(len(plan['provisioning_specs']), 2)
        for spec in plan['provisioning_specs']:
            row = m.EXPECTED[spec['logical_client_id']]
            self.assertEqual(spec['allowed_scopes'], row['allowed_scopes'])
            self.assertEqual(spec['audiences'], row['allowed_audiences'])
            self.assertEqual(spec['metadata']['owner'], row['owner'])
            self.assertTrue(spec['require_new'])
            self.assertEqual(spec['access_token_ttl_seconds'], 60)
        for invalid in (None, '', 'proposed', 'A' * 40, 'a' * 41):
            with self.assertRaises(ValueError):
                m.build_native_plan(self.registry, invalid)
        for name in m.EXPECTED:
            changed = copy.deepcopy(self.registry)
            del changed['workloads'][name]
            with self.assertRaises(ValueError):
                m.build_native_plan(changed, commit)
            changed = copy.deepcopy(self.registry)
            changed['workloads'][name]['allowed_scopes'].append('admin:*')
            with self.assertRaises(ValueError):
                m.build_native_plan(changed, commit)

    def test_native_plan_exclusive_private_and_pin_refusal_before_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            checkout, output = Path(temp) / 'shared', Path(temp) / 'native'
            with patch.object(m, 'load_registry', side_effect=ValueError('held')):
                with self.assertRaises(ValueError):
                    m.prepare_native_plan(checkout, output)
            self.assertFalse(output.exists())
            with patch.object(m, 'load_registry', return_value=(self.registry, 'a' * 40)) as authority:
                plan = m.prepare_native_plan(checkout, output)
                authority.assert_called_once_with(checkout, with_commit=True)
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                file = output / 'native-plan.json'
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(file.read_text()), plan)
                with self.assertRaises(FileExistsError):
                    m.prepare_native_plan(checkout, output)
                self.assertEqual(json.loads(file.read_text()), plan)
            output2 = Path(temp) / 'failed'
            with patch.object(m, 'load_registry', return_value=(self.registry, 'a' * 40)), patch.object(m.json, 'dump', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    m.prepare_native_plan(checkout, output2)
            self.assertFalse(output2.exists())

    def test_partial_write_is_cleaned(self):
        import yaml
        with tempfile.TemporaryDirectory() as temp:
            checkout = Path(temp) / 'shared'
            registry = checkout / 'contracts/identity/v1/workload-registry.yaml'
            registry.parent.mkdir(parents=True)
            registry.write_text(yaml.safe_dump(self.registry))
            output = Path(temp) / 'private'
            original = m.os.open
            count = 0
            def fail_second(*args):
                nonlocal count
                count += 1
                if count == 2:
                    raise OSError('simulated disk failure')
                return original(*args)
            with patch.object(m, 'load_registry', return_value=self.registry), patch.object(m.os, 'open', side_effect=fail_second):
                with self.assertRaises(OSError):
                    m.prepare(checkout, output, self.deadline)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
