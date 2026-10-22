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


    def test_cipc_source_capture_profile_is_staging_scoped_and_non_authorising(self):
        name = 'baobab-cipc-verifier-staging'
        self.registry['workloads'][name] = {
            'environment': 'staging',
            'credential_type': 'federated_workload_token',
            'status': 'PROVISIONED',
            'allowed_scopes': ['verification:source-capture'],
            'allowed_audiences': ['baobab-control-plane'],
        }
        binding = {name: {
            'issuer': 'https://staging-verifier.example.invalid',
            'subject': 'system:serviceaccount:verification:cipc-verifier',
        }}
        projected = module.build('e' * 40, self.registry, [name], binding, 'staging')
        self.assertEqual(projected['workloads'][name]['allowed_scopes'], ['verification:source-capture'])
        self.assertEqual(projected['workloads'][name]['status'], 'PROVISIONED')
        self.assertNotIn('verification:decide', projected['workloads'][name]['allowed_scopes'])
        self.assertNotIn('tenant:bootstrap', projected['workloads'][name]['allowed_scopes'])
        for wrong in ('production', 'development'):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                module.build('e' * 40, self.registry, [name], binding, wrong)
        forged = dict(binding[name], allowed_scopes=['verification:decide'])
        with self.assertRaises(ValueError):
            module.build('e' * 40, self.registry, [name], {name: forged}, 'staging')


    def test_document_extractor_cannot_use_cipc_source_or_production_scopes(self):
        name = 'baobab-document-extractor-staging'
        self.registry['workloads'][name] = {
            'environment': 'staging', 'credential_type': 'federated_workload_token',
            'status': 'PROVISIONED', 'allowed_scopes': ['verification:document-extract'],
            'allowed_audiences': ['baobab-control-plane'],
        }
        binding = {name: {
            'issuer': 'https://document-extractor.staging.example.invalid',
            'subject': 'system:serviceaccount:verification:document-extractor',
        }}
        projected = module.build('8' * 40, self.registry, [name], binding, 'staging')
        profile = projected['workloads'][name]
        self.assertEqual(profile['allowed_scopes'], ['verification:document-extract'])
        self.assertEqual(profile['status'], 'PROVISIONED')
        for forbidden in ('verification:source-capture', 'verification:decide', 'tenant:bootstrap'):
            self.assertNotIn(forbidden, profile['allowed_scopes'])
        with self.assertRaises(ValueError):
            module.build('8' * 40, self.registry, [name], binding, 'production')
        forged = dict(binding[name], allowed_scopes=['verification:source-capture'])
        with self.assertRaises(ValueError):
            module.build('8' * 40, self.registry, [name], {name: forged}, 'staging')


    def test_independent_scan_attestor_has_no_ocr_cipc_or_tenant_authority(self):
        name = 'baobab-independent-scanner-staging'
        self.registry['workloads'][name] = {
            'environment': 'staging', 'credential_type': 'federated_workload_token',
            'status': 'PROVISIONED',
            'allowed_scopes': ['verification:scan-attest'],
            'allowed_audiences': ['baobab-control-plane'],
        }
        binding = {name: {
            'issuer': 'https://scanner.staging.example.invalid',
            'subject': 'system:serviceaccount:verification:independent-scanner',
        }}
        profile = module.build('a' * 40, self.registry, [name], binding, 'staging')['workloads'][name]
        self.assertEqual(profile['status'], 'PROVISIONED')
        self.assertEqual(profile['allowed_scopes'], ['verification:scan-attest'])
        self.assertEqual(profile['allowed_audiences'], ['baobab-control-plane'])
        for forbidden in ('verification:document-extract', 'verification:source-capture',
                          'verification:decide', 'legal-actor:assess', 'tenant:bootstrap'):
            self.assertNotIn(forbidden, profile['allowed_scopes'])
            forged = dict(binding[name], allowed_scopes=[forbidden])
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                module.build('a' * 40, self.registry, [name], {name: forged}, 'staging')
        with self.assertRaises(ValueError):
            module.build('a' * 40, self.registry, [name], binding, 'production')

    def test_estate_bff_human_token_profile_is_copied_exactly(self):
        profile = {'purpose': 'ESTATE_BFF_BUYER', 'audiences': ['baobab-trade'], 'scopes': ['trade:buy']}
        self.registry['workloads']['bff'] = {'environment': 'production', 'credential_type': 'client_credentials',
                                             'status': 'PROVISIONED', 'allowed_scopes': ['trade:buyer-handoff'],
                                             'allowed_audiences': ['baobab-trade'], 'human_token_profile': profile}
        config = module.build('a' * 40, self.registry, ['bff'], {}, 'production')
        self.assertEqual(config['workloads']['bff']['human_token_profile'], profile)
        self.assertNotIn('human_token_profile', module.build('a' * 40, self.registry, ['trade'], {}, 'production')['workloads']['trade'])
        self.registry['workloads']['cp']['human_token_profile'] = profile
        with self.assertRaisesRegex(ValueError, 'client-credentials estate BFF'):
            module.build('a' * 40, self.registry, ['cp'], self.binding, 'production')


if __name__ == '__main__':
    unittest.main()
