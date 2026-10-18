"""The named bootstrap exclusion cannot expand authority or create a client."""
import copy
import json
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('int02_identity', ROOT/'scripts/check_int02_fixture_identity.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FixtureIdentityTests(unittest.TestCase):
    def test_exact_approved_profile(self):
        self.assertTrue(module.fixture_only(copy.deepcopy(module.EXPECTED)))
        for path in (ROOT/'config/clients').glob('*.json'):
            self.assertNotEqual(json.loads(path.read_text()).get('clientId'), module.CLIENT_ID)

    def test_every_boundary_rejects_mutation(self):
        for key in module.EXPECTED:
            with self.subTest(key=key):
                entry = copy.deepcopy(module.EXPECTED)
                entry[key] = ['unexpected'] if isinstance(entry[key], list) else 'unexpected'
                self.assertFalse(module.fixture_only(entry))
                del entry[key]
                self.assertFalse(module.fixture_only(entry))
        extra = dict(module.EXPECTED, privileged=True)
        self.assertFalse(module.fixture_only(extra))
        self.assertFalse(module.fixture_only(None))
