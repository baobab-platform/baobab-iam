#!/usr/bin/env python3
"""Check actual Go records and exact synthetic fixtures against pinned Shared."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / '.shared-contracts'
lock = yaml.safe_load((ROOT / 'contracts.lock.yaml').read_text())
pin = lock['source']['commit']
assert re.fullmatch('[0-9a-f]{40}', pin)
assert subprocess.check_output(['git', '-C', str(SHARED), 'rev-parse', 'HEAD'], text=True).strip() == pin
assert f'const SharedCommit = "{pin}"' in (ROOT / 'internal/federation/consume.go').read_text()
for path in lock['contracts']:
    assert (SHARED / path).is_file(), 'missing pinned contract'
for protocol in ('oidc', 'saml2'):
    source = SHARED / f'contracts/identity/v1/examples/federation-{protocol}.json'
    fixture = ROOT / f'internal/federation/testdata/federation-{protocol}.json'
    assert hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256(fixture.read_bytes()).digest(), 'fixture provenance mismatch'
spec = importlib.util.spec_from_file_location('shared_federation', SHARED / 'scripts/validate-federation-contracts.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
validator.main()
with tempfile.TemporaryDirectory() as directory:
    env = dict(os.environ, FEDERATION_CONTRACT_OUTPUT_DIR=directory)
    subprocess.run(['go', 'test', './internal/federation', '-run', '^TestExportContractRecords$', '-count=1'], cwd=ROOT, env=env, check=True)
    for protocol in ('oidc', 'saml2'):
        record = json.loads((Path(directory) / f'{protocol}.json').read_text())
        assert not validator.validate_bundle(record), 'Go wire record differs from pinned Shared contract'
    # The runtime dispatch consumes existing canonical CP resolution, never a
    # locally invented provider-selection schema. Validate actual Go wire types.
    resolution_id = 'https://contracts.baobab-platform.com/capability/v1/resolution.schema.json'
    for name, definition in (('resolution-request', 'resolutionRequest'), ('resolution-response', 'resolution')):
        record = json.loads((Path(directory) / f'{name}.json').read_text())
        schema = {'$ref': resolution_id + '#/$defs/' + definition}
        errors = list(validator.Draft202012Validator(schema, registry=validator.registry(),
                      format_checker=validator.FormatChecker()).iter_errors(record))
        assert not errors, 'Go CP resolution wire differs from pinned Shared contract: ' + str(errors)
print('Pinned Shared federation/resolution schemas, Go records and exact fixtures agree')
