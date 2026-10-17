"""Regression coverage for the real browser failure exposed by INT-02."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('browser_flow', ROOT/'scripts/check_browser_flow.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BrowserFlowTests(unittest.TestCase):
    def setUp(self):
        self.realm = json.loads((ROOT/'config/realm/baobab-realm.json').read_text())

    def flow(self, alias):
        return next(f for f in self.realm['authenticationFlows'] if f['alias'] == alias)

    def test_imported_graph_preserves_primary_and_assurance(self):
        module.validate(self.realm)

    def test_old_mixed_root_is_rejected_even_if_conditions_might_be_false(self):
        root = self.flow('Baobab browser')
        root['authenticationExecutions'] = self.flow('Baobab - Primary Authentication')['authenticationExecutions'] + root['authenticationExecutions'][1:]
        with self.assertRaisesRegex(ValueError, 'mixed'):
            module.validate(self.realm)

    def test_disabling_privileged_mfa_is_not_a_login_fix(self):
        self.flow('Baobab forms')['authenticationExecutions'][1]['requirement'] = 'DISABLED'
        with self.assertRaisesRegex(ValueError, 'privileged MFA'):
            module.validate(self.realm)

    def test_assurance_cannot_precede_identity_or_weaken_passkey_order(self):
        self.flow('Baobab browser')['authenticationExecutions'][0]['priority'] = 50
        with self.assertRaisesRegex(ValueError, 'before'):
            module.validate(self.realm)

    def test_missing_child_is_not_silently_accepted(self):
        self.realm['authenticationFlows'] = [f for f in self.realm['authenticationFlows'] if f['alias'] != 'Baobab forms']
        with self.assertRaisesRegex(ValueError, 'missing child'):
            module.validate(self.realm)


if __name__ == '__main__':
    unittest.main()
