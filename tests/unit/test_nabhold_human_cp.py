"""G04B-04 negative profile/admission tests. They never mint real identities."""
import importlib.util
import json
from pathlib import Path
import unittest
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("g04b04", ROOT / "scripts/verify_nabhold_human_cp.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

class NabholdHumanProfile(unittest.TestCase):
    def setUp(self):
        self.template = json.loads((ROOT / "config/clients/nabhold-executive.json").read_text())

    def test_source_is_dormant_confidential_and_cp_only(self):
        self.assertTrue(mod.check_template(self.template))
        scope = json.loads((ROOT / "config/scopes/authority-self.json").read_text())
        self.assertEqual(scope["name"], "authority:self")
        self.assertEqual(scope["protocolMappers"][0]["config"]["included.custom.audience"], "baobab-control-plane")
        self.assertEqual(scope["protocolMappers"][0]["config"]["id.token.claim"], "false")
        self.assertEqual(scope["protocolMappers"][0]["config"]["access.token.claim"], "true")

    def test_source_cannot_be_activated_by_accidental_edit(self):
        for key, value in (("enabled", True), ("publicClient", True),
                           ("directAccessGrantsEnabled", True), ("serviceAccountsEnabled", True),
                           ("redirectUris", ["https://example.test/*"]),
                           ("webOrigins", ["*"]), ("defaultClientScopes", ["openid"])):
            d = {**self.template, key: value}
            with self.subTest(key=key), self.assertRaises(mod.Denied):
                mod.check_template(d)

    def test_reviewed_client_requires_exact_https_callback_and_no_extra_permissions(self):
        callback = "https://estate.example.test/api/auth/callback"
        approved = {**self.template, "enabled": True, "redirectUris": [callback]}
        self.assertTrue(mod.check_reviewed_client(approved, callback))
        for key, value in (("redirectUris", ["https://estate.example.test/*"]),
                           ("webOrigins", ["https://estate.example.test"]),
                           ("optionalClientScopes", ["administrator:write"]),
                           ("defaultClientScopes", ["openid", "authority:self"]),
                           ("serviceAccountsEnabled", True), ("publicClient", True),
                           ("authorizationServicesEnabled", True),
                           ("protocolMappers", [{"name": "rogue"}]),
                           ("attributes", {**approved["attributes"], "oauth2.device.authorization.grant.enabled": "true"})):
            with self.subTest(key=key), self.assertRaises(mod.Denied):
                mod.check_reviewed_client({**approved, key: value}, callback)

    def test_introspection_requires_exact_human_cp_profile(self):
        import time
        record = {"active": True, "iss": "https://iam.example.test/realms/baobab",
                  "sub": "kratos-external-subject", "client_id": "nabhold-executive",
                  "aud": ["baobab-control-plane"], "scope": "openid authority:self",
                  "exp": int(time.time()) + 120}
        self.assertTrue(mod.check_positive_claims(record, record["iss"], record["sub"]))
        cases = [{"aud": "baobab-cms"}, {"scope": "authority:selfish"}, {"active": False},
                 {"iss": "https://untrusted.test"}, {"client_id": "other-client"},
                 {"exp": 1}, {"sub": "other-human"}]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(mod.Denied):
                mod.check_positive_claims({**record, **change}, record["iss"], record["sub"])

    def test_wrong_audience_probe_isolates_only_audience(self):
        import time
        positive = {"active": True, "iss": "https://iam.example.test/realms/baobab",
                    "sub": "same-human", "client_id": "nabhold-executive",
                    "aud": ["baobab-control-plane"], "scope": "openid authority:self",
                    "exp": int(time.time()) + 120}
        wrong = {**positive, "aud": ["baobab-cms"], "exp": positive["exp"] + 2}
        self.assertTrue(mod.check_wrong_audience_claims(wrong, positive,
                        positive["iss"], positive["sub"]))
        for changes in ({"scope": "openid"}, {"sub": "different"},
                        {"client_id": "other-client"}, {"iss": "https://other.test"},
                        {"active": False}, {"exp": 1},
                        {"aud": ["baobab-control-plane", "baobab-cms"]}):
            with self.subTest(changes=changes), self.assertRaises(mod.Denied):
                mod.check_wrong_audience_claims({**wrong, **changes}, positive,
                                                positive["iss"], positive["sub"])

    def test_self_response_requires_current_canonical_principal(self):
        value = {"principal_id": "cba4dcea-40d1-4587-81f7-a79b3908a203",
                 "grants": [], "evaluated_at": datetime.now(timezone.utc).isoformat()}
        self.assertTrue(mod.check_cp_response(value, value["principal_id"]))
        for change in ({"principal_id": "provider-sub"}, {"evaluated_at": "2020-01-01T00:00:00Z"},
                       {"grants": "admin"}, {"evaluated_at": "not-a-date"}):
            with self.subTest(change=change), self.assertRaises((mod.Denied, ValueError)):
                mod.check_cp_response({**value, **change}, value["principal_id"])

    def test_empty_environment_cannot_claim_protected_acceptance(self):
        with self.assertRaises((mod.Denied, KeyError)):
            mod.run_protected({})
if __name__ == "__main__":
    unittest.main()
