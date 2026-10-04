"""Fail closed before overlaying the harness into the immutable CP checkout."""
import json
from pathlib import Path
import subprocess
import sys

COMMIT = 'c84063cb07dce76e1ffac4b12fa29c5e4e5ec855'


def verify(root):
    manifest = json.loads((Path(__file__).parent / 'current/provenance.json').read_text())
    if manifest['repository'] != 'baobab-platform/baobab-cp' or manifest['commit'] != COMMIT:
        raise ValueError('Unexpected reviewed consumer revision')
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
    if git('rev-parse', 'HEAD') != COMMIT:
        raise ValueError('CP checkout revision differs from the reviewed pin')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('CP checkout must be clean before the test-only overlay')
    if (root / 'cmd/iam-m4-route').exists():
        raise ValueError('Harness must not replace upstream source')


if __name__ == '__main__':
    verify(Path(sys.argv[1]))
    print('Immutable clean CP source verified before test-only overlay')
