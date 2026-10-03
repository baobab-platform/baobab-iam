import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('workload_profiles', ROOT / 'scripts/build_workload_token_profiles.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WorkloadProjectionTests(unittest.TestCase):
    def setUp(self):
        self.registry = {'workloads': {
            'cp': {'credential_type': 'federated_workload_token', 'status': 'PROVISIONED',
                   'allowed_scopes': ['billing:read'], 'allowed_audiences': ['baobab-subscriptions']},
            'trade': {'credential_type': 'client_credentials', 'status': 'ACTIVE',
                      'allowed_scopes': ['context:resolve'], 'allowed_audiences': ['baobab-control-plane']}}}
        self.binding = {'cp': {'issuer': 'https://projected.invalid', 'subject': 'service-account-cp'}}

    def test_shared_authority_preserved(self):
        config = module.build('a' * 40, self.registry, ['cp'], self.binding)
        self.assertEqual(config['workloads']['cp'], self.registry['workloads']['cp'])
        self.assertEqual(config['workloads']['cp']['status'], 'PROVISIONED')
        self.assertEqual(config['bindings'], self.binding)

    def test_runtime_input_cannot_override_shared_scopes(self):
        self.binding['cp']['allowed_scopes'] = ['payment:execute']
        with self.assertRaises(ValueError):
            module.build('a' * 40, self.registry, ['cp'], self.binding)

    def test_missing_and_unrelated_bindings_denied(self):
        for selected, bindings in ((['cp'], {}), (['trade'], self.binding), (['cp', 'cp'], self.binding)):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                module.build('a' * 40, self.registry, selected, bindings)

    def test_wildcard_and_noncanonical_issuer_denied(self):
        for issuer in ('http://projected.invalid', 'https://*.invalid', 'https://user:pass@projected.invalid',
                       'https://projected.invalid?issuer=another', ' https://projected.invalid'):
            with self.subTest(issuer=issuer), self.assertRaises(ValueError):
                module.build('a' * 40, self.registry, ['cp'], {'cp': {'issuer': issuer, 'subject': 'service-account-cp'}})


if __name__ == '__main__':
    unittest.main()
