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
# The verifier remains upstream source. Only the reviewed vulnerable indirect
# module is overridden; reversing that exact change must recover upstream locks.
if set(manifest['dependency_overrides']) != {'golang.org/x/text'}:
    raise SystemExit('Unexpected additional consumer dependency override')
override = manifest['dependency_overrides']['golang.org/x/text']
if override['upstream'] != 'v0.39.0' or override['selected'] != 'v0.42.0' or override['advisory'] != 'GO-2026-6629':
    raise SystemExit('Unexpected consumer dependency override')
original_mod = (root/'go.mod').read_bytes().replace(b'golang.org/x/text v0.42.0', b'golang.org/x/text v0.39.0')
original_sum = b''.join(line for line in (root/'go.sum').read_bytes().splitlines(keepends=True)
                        if not line.startswith(b'golang.org/x/text v0.42.0'))
for data, key in ((original_mod, 'upstream_go_mod_sha256'), (original_sum, 'upstream_go_sum_sha256')):
    if hashlib.sha256(data).hexdigest() != override[key]:
        raise SystemExit('Unreviewed consumer dependency changes')
print('Unchanged CP verifier and exact reviewed security dependency override verified')
