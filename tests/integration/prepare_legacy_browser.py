#!/usr/bin/env python3
"""Mount an isolated old browser graph without altering the built image/source.

Only the integration job opts into this fixture. Credentials remain generated
separately; the ordinary source image and production realm declaration retain
the corrected graph. The real product bootstrap must repair this old graph.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
realm = json.loads((ROOT/'config/realm/baobab-realm.json').read_text())
flows = realm['authenticationFlows']
browser = next(f for f in flows if f['alias'] == 'Baobab browser')
primary = next(f for f in flows if f['alias'] == 'Baobab - Primary Authentication')
variant = sys.argv[1] if len(sys.argv)>1 else 'legacy'
if variant not in {'legacy', 'primary'}:
    raise SystemExit('Unknown historical browser fixture')
primary['authenticationExecutions'] = [e for e in primary['authenticationExecutions'] if e['requirement']=='ALTERNATIVE']
if variant == 'legacy':
    browser['authenticationExecutions'] = primary['authenticationExecutions'] + [
        e for e in browser['authenticationExecutions'] if e.get('flowAlias') != primary['alias']]
    flows.remove(primary)
else:
    # #118 repaired the hierarchy but recorded no LoA. Exercise that deployed
    # intermediate state as well as the original mixed-level historical root.
    next(e for e in browser['authenticationExecutions'] if e.get('flowAlias')==primary['alias'])['requirement']='REQUIRED'
realm['authenticatorConfig'] = [c for c in realm['authenticatorConfig'] if c['alias'] != 'baobab-primary-loa-silver']
directory = ROOT/'tests/integration/.runtime'
directory.mkdir(exist_ok=True)
fixture = directory/'browser-legacy-realm.json'
fixture.write_text(json.dumps(realm)+'\n')
# Public synthetic realm policy only, no users/credentials. The non-root
# Keycloak process needs to read this host bind mount; secrets are elsewhere.
fixture.chmod(0o644)
(directory/'browser.override.json').write_text(json.dumps({'services': {'keycloak': {
    'volumes': [str(fixture)+':/opt/keycloak/config/realm/baobab-realm.json:ro']}}})+'\n')
print('Prepared synthetic legacy browser fixture; no credential values emitted.')
