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
# The verifier and licence remain exact upstream bytes. Only these two
# reviewed security dependency overrides may differ from the immutable lock.
for name, digest in {
    'internal/auth/oidc.go': '741c8c9d7e17c16b592034085cdebf26cef9865f3ce8a8b0f30eaa22baefd162',
    'LICENSE': 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4',
}.items():
    if manifest['files'][name] != digest:
        raise SystemExit('Unreviewed upstream source change: ' + name)
expected_overrides = {
    'golang.org/x/text': ('v0.39.0', 'v0.42.0', 'GO-2026-6629'),
    'github.com/go-jose/go-jose/v4': ('v4.1.5', 'v4.1.6', 'GHSA-mgcc-cww5-fp2q'),
}
if set(manifest['dependency_overrides']) != set(expected_overrides):
    raise SystemExit('Unexpected consumer dependency override')
original_mod = (root/'go.mod').read_bytes()
original_sum = (root/'go.sum').read_bytes()
mod_hash = '7b459debbb3d8bbcda56ed7fc75f500af6496b13878d2e50a67472b8debb5556'
sum_hash = '97f140bfffba71a7bd8248b0b731800012e0ecd89961bb892cc7291666b54e1b'
for module, (upstream, selected, advisory) in expected_overrides.items():
    override = manifest['dependency_overrides'][module]
    if override != {'upstream': upstream, 'selected': selected, 'advisory': advisory,
                    'upstream_go_mod_sha256': mod_hash, 'upstream_go_sum_sha256': sum_hash}:
        raise SystemExit('Unexpected consumer dependency override metadata')
    old, new = (module + ' ' + upstream).encode(), (module + ' ' + selected).encode()
    if original_mod.count(new) != 1:
        raise SystemExit('Missing or duplicate reviewed consumer override')
    original_mod = original_mod.replace(new, old)
    original_sum = b''.join(line for line in original_sum.splitlines(keepends=True)
                            if not line.startswith(new))
for data, digest in ((original_mod, mod_hash), (original_sum, sum_hash)):
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit('Unreviewed consumer dependency changes')
print('Unchanged CP verifier and both exact reviewed security dependency overrides verified')
