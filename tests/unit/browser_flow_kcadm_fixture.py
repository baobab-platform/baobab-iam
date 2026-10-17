"""Stateful CLI fixture for repair interruption/order tests, never a runtime IAM.

Implements only the Admin API operations used by the hierarchy repair. The
separate live suite checks those operations and credential HTML in Keycloak.
"""
import json
import os
from pathlib import Path
import sys
from urllib.parse import unquote

path = Path(os.environ['BROWSER_FIXTURE_STATE'])
state = json.loads(path.read_text())
args = sys.argv[1:]
verb, resource = args[:2]


def info(flow_id, level=0):
    out = []
    for model in sorted((e for e in state['executions'] if e['parentFlow'] == flow_id), key=lambda e: e['priority']):
        row = {key: model[key] for key in ['id', 'priority', 'requirement']}
        row['level'] = level
        if model.get('authenticatorFlow'):
            flow = next(f for f in state['flows'] if f['id'] == model['flowId'])
            row.update(displayName=flow['alias'], flowId=flow['id'])
        else:
            row.update(displayName=model['authenticator'], providerId=model['authenticator'])
        out.append(row)
        if model.get('authenticatorFlow'):
            out.extend(info(model['flowId'], level+1))
    return out


if verb == 'get':
    if resource == 'realms/baobab':
        result = {'browserFlow': state['browserFlow']}
    elif resource == 'authentication/flows':
        # Match AuthenticationManagementResource.getFlows exactly: children
        # are discoverable through execution references, never this list.
        result = [flow for flow in state['flows'] if flow['topLevel']]
    elif resource.startswith('authentication/config/'):
        result = next(c for c in state['configs'] if c['id'] == resource.rsplit('/', 1)[1])
    elif resource.startswith('authentication/executions/'):
        result = next(e for e in state['executions'] if e['id'] == resource.rsplit('/', 1)[1])
    else:
        alias = unquote(resource[len('authentication/flows/'):-len('/executions')])
        result = info(next(f['id'] for f in state['flows'] if f['alias'] == alias))
    # Keycloak's JSON transport may omit primitive defaults. Preserve the
    # typed model's false/zero semantics rather than inventing a new policy.
    def omit_defaults(value):
        if isinstance(value, list):
            return [omit_defaults(item) for item in value]
        if isinstance(value, dict):
            return {key: omit_defaults(item) for key, item in value.items()
                    if item is not None and item is not False and not (type(item) is int and item == 0)}
        return value
    print(json.dumps(omit_defaults(result) if state.get('omitDefaults') else result))
elif verb == 'create' and resource == 'authentication/flows':
    values = dict(args[i+1].split('=', 1) for i, value in enumerate(args) if value == '-s')
    state['flows'].append({'id': 'new-primary', 'alias': values['alias'], 'description': values['description'],
                          'builtIn': False, 'topLevel': values['topLevel'] == 'true'})
elif verb == 'create' and resource.endswith('/config'):
    if os.environ.get('BROWSER_FIXTURE_FAIL_CONFIG') == '1':
        raise SystemExit(1)
    model = json.loads(Path(args[args.index('-f')+1]).read_text())
    model['id'] = 'config-'+str(1+max((int(c['id'].split('-')[-1]) for c in state['configs']), default=-1))
    state['configs'].append(model)
    next(e for e in state['executions'] if e['id'] == resource.split('/')[-2])['authenticatorConfig'] = model['id']
elif verb == 'create' and resource == 'authentication/executions':
    model = json.loads(Path(args[args.index('-f')+1]).read_text())
    if os.environ.get('BROWSER_FIXTURE_FAIL_COPY') == '1' and model['parentFlow'] == 'new-primary':
        raise SystemExit(1)
    model['id'] = 'new-execution-'+str(len(state['executions']))
    state['executions'].append(model)
elif verb == 'update' and resource.endswith('/executions'):
    update = json.loads(Path(args[args.index('-f')+1]).read_text())
    model = next(e for e in state['executions'] if e['id'] == update['id'])
    model.update(requirement=update['requirement'], priority=update['priority'])
else:
    raise SystemExit('Unsupported fixture operation')
if verb != 'get':
    path.write_text(json.dumps(state))
