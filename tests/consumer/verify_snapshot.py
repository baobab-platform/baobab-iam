"""Validate the reviewed CP verifier snapshot before compiling it."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).parent / 'cp'
manifest = json.loads((root / 'provenance.json').read_text())
if manifest['repository'] != 'baobab-platform/baobab-cp' or manifest['commit'] != '20235ac2c4e1c0285e747a5a4b41c1eefb3a4dd7':
    raise SystemExit('Unexpected reviewed consumer revision')
expected = {'internal/auth/oidc.go', 'go.mod', 'go.sum', 'LICENSE'}
if set(manifest['files']) != expected:
    raise SystemExit('Incomplete consumer snapshot')
for name, digest in manifest['files'].items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
        raise SystemExit(f'Consumer snapshot changed: {name}')
print('Pinned unchanged CP verifier and dependency locks verified')
