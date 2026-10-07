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
            'cp': {'environment': 'production', 'credential_type': 'federated_workload_token', 'status': 'PROVISIONED',
                   'allowed_scopes': ['billing:read'], 'allowed_audiences': ['baobab-subscriptions']},
            'trade': {'environment': 'production', 'credential_type': 'client_credentials', 'status': 'ACTIVE',
                      'allowed_scopes': ['context:resolve'], 'allowed_audiences': ['baobab-control-plane']}}}
        self.binding = {'cp': {'issuer': 'https://projected.invalid', 'subject': 'service-account-cp'}}

    def test_shared_authority_preserved(self):
        config = module.build('a' * 40, self.registry, ['cp'], self.binding, 'production')
        self.assertEqual(config['workloads']['cp'], self.registry['workloads']['cp'])
        self.assertEqual(config['workloads']['cp']['status'], 'PROVISIONED')
        self.assertEqual(config['bindings'], self.binding)

    def test_runtime_input_cannot_override_shared_scopes(self):
        self.binding['cp']['allowed_scopes'] = ['payment:execute']
        with self.assertRaises(ValueError):
            module.build('a' * 40, self.registry, ['cp'], self.binding, 'production')

    def test_missing_and_unrelated_bindings_denied(self):
        for selected, bindings in ((['cp'], {}), (['trade'], self.binding), (['cp', 'cp'], self.binding)):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                module.build('a' * 40, self.registry, selected, bindings, 'production')

    def test_distinct_workloads_cannot_share_projected_identity(self):
        self.registry['workloads']['other'] = dict(self.registry['workloads']['cp'])
        bindings = {'cp': self.binding['cp'], 'other': dict(self.binding['cp'])}
        with self.assertRaises(ValueError):
            module.build('a' * 40, self.registry, ['cp', 'other'], bindings, 'production')

    def test_wildcard_and_noncanonical_issuer_denied(self):
        for issuer in ('http://projected.invalid', 'https://*.invalid', 'https://user:pass@projected.invalid',
                       'https://projected.invalid?issuer=another', ' https://projected.invalid'):
            with self.subTest(issuer=issuer), self.assertRaises(ValueError):
                module.build('a' * 40, self.registry, ['cp'], {'cp': {'issuer': issuer, 'subject': 'service-account-cp'}}, 'production')

    def test_environment_is_enforced_and_recorded(self):
        config = module.build('a' * 40, self.registry, ['cp'], self.binding, 'production')
        self.assertEqual((config['environment'], config['workloads']['cp']['environment']), ('production', 'production'))
        for wrong in ('staging', 'development'):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, 'belongs to environment production'):
                module.build('a' * 40, self.registry, ['cp'], self.binding, wrong)
        for invalid in ('', 'evidence', 'Staging', None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                module.build('a' * 40, self.registry, ['cp'], self.binding, invalid)

    def test_staging_evidence_provisioner_is_projected_for_staging_only(self):
        self.registry['workloads']['evidence'] = {
            'environment': 'staging', 'credential_type': 'federated_workload_token', 'status': 'ACTIVE',
            'allowed_scopes': ['erp:provision'], 'allowed_audiences': ['baobab-erp']}
        bindings = {'evidence': {'issuer': 'https://issuer.staging.invalid', 'subject': 'provisioner-evidence'}}
        config = module.build('a' * 40, self.registry, ['evidence'], bindings, 'staging')
        self.assertEqual(config['workloads']['evidence']['allowed_scopes'], ['erp:provision'])
        with self.assertRaises(ValueError):
            module.build('a' * 40, self.registry, ['evidence'], bindings, 'production')
        # A production projection cannot be assembled around it either.
        with self.assertRaises(ValueError):
            module.build('a' * 40, self.registry, ['cp', 'evidence'], {**self.binding, **bindings}, 'production')


if __name__ == '__main__':
    unittest.main()
