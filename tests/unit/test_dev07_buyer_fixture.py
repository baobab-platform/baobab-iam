"""Source-only registration/claim boundaries; not real Hydra evidence."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / 'scripts/dev07_buyer_fixture.py'
spec = importlib.util.spec_from_file_location('dev07_buyer_fixture', path)
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)

class BuyerFixtureTests(unittest.TestCase):
    def registry(self):
        return {'workloads': {
            f.VALIDATOR: {'environment': 'development', 'status': 'ACTIVE', 'allowed_audiences': ['baobab-control-plane'],
                'allowed_scopes': f.VALIDATOR_SCOPES[:], 'subject_principal_audiences': ['baobab-trade'], 'credential_type': 'client_credentials'},
            f.BFF: {'environment': 'development', 'status': 'ACTIVE', 'allowed_audiences': ['baobab-trade'],
                'allowed_scopes': ['trade:buyer-handoff'], 'human_token_profile': {'purpose': 'ESTATE_BFF_BUYER', 'audiences': ['baobab-trade'], 'scopes': ['trade:buy']}, 'credential_type': 'client_credentials'}}}
    def test_dual_grants_never_confuse_the_human_and_workload(self):
        self.assertEqual(f.normalised_claims(f.BFF, ['authorization_code'], 'native-human', {'native-human'}, 'aal1')['actor_type'], 'human')
        own = f.normalised_claims(f.BFF, ['client_credentials'], f.BFF, {'native-human'})
        self.assertEqual(own['actor_type'], 'workload')
        self.assertEqual(set(own), {'actor_type', 'azp', 'client_id'})
        for grant, subject in [(['password'], 'native-human'), (['client_credentials'], 'native-human'), (['authorization_code'], 'unknown')]:
            with self.assertRaises(ValueError): f.normalised_claims(f.BFF, grant, subject, {'native-human'})
    def test_registry_and_lease_are_not_inferred(self):
        now = datetime.now(timezone.utc); secrets = {f.BFF: 'a'*32, f.VALIDATOR: 'b'*32}
        clients = f.build_clients(self.registry(), 'a'*32, now+timedelta(minutes=10), secrets, now)
        self.assertEqual(clients[f.BFF]['audience'], ['baobab-trade'])
        self.assertEqual(set(clients[f.BFF]['scope'].split()), {'openid', 'trade:buy', 'trade:buyer-handoff'})
        self.assertNotIn('refresh_token', clients[f.BFF]['grant_types'])
        self.assertNotIn('identity:principal:register-buyer', clients[f.VALIDATOR]['scope'])
        for name in (f.BFF, f.VALIDATOR):
            registry = self.registry(); registry['workloads'][name]['environment'] = 'production'
            with self.assertRaises(ValueError): f.build_clients(registry, 'a'*32, now+timedelta(minutes=10), secrets, now)
        with self.assertRaises(ValueError): f.build_clients(self.registry(), 'a'*32, now+timedelta(hours=2), secrets, now)
