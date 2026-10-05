from pathlib import Path
from datetime import datetime, timezone
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import build_authority_admission as admission


class AdmissionTests(unittest.TestCase):
    def test_canonical_lifecycle_never_promoted(self):
        registry = {'workloads': {'service': {'environment': 'staging', 'status': 'PROVISIONED',
                    'allowed_audiences': ['cp'], 'allowed_scopes': ['federation-authority:read']}}}
        result = admission.build('a' * 40, registry, 'staging', datetime.now(timezone.utc), 300)
        self.assertEqual(result['workloads']['service']['status'], 'PROVISIONED')
        self.assertEqual(admission.build('a' * 40, registry, 'production', datetime.now(timezone.utc), 300)['workloads'], {})
        with self.assertRaises(ValueError):
            admission.build('a' * 40, registry, 'staging', datetime.now(timezone.utc), 901)

    def test_publication_private_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'snapshot.json'
            admission.publish(path, {'version': 1})
            admission.publish(path, {'version': 2})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertIn('2', path.read_text())
            self.assertEqual(len(list(Path(directory).iterdir())), 1)
