import copy
import unittest
from scripts.operations.check_jwks_rotation import verify


def fixture():
    old = {"kty": "RSA", "kid": "old", "alg": "RS256", "n": "abc", "e": "AQAB"}
    new = {"kty": "RSA", "kid": "new", "alg": "RS256", "n": "eHl6", "e": "AQAB"}
    plan = {"mode": "routine", "old_kid": "old", "new_kid": "new",
            "verification_distributed": True, "max_token_lifetime_seconds": 600,
            "jwks_cache_seconds": 60, "clock_skew_seconds": 30,
            "overlap_seconds": 690}
    return {"keys": [old]}, {"keys": [old, new]}, plan


class JWKSRotationTests(unittest.TestCase):
    def test_routine_overlap(self):
        self.assertTrue(verify(*fixture()))

    def test_overlap_short(self):
        a, b, p = fixture()
        p["overlap_seconds"] = 689
        with self.assertRaises(ValueError):
            verify(a, b, p)

    def test_old_key_removed_early(self):
        a, b, p = fixture()
        b["keys"] = b["keys"][1:]
        with self.assertRaises(ValueError):
            verify(a, b, p)

    def test_undistributed_new_key(self):
        a, b, p = fixture()
        p["verification_distributed"] = False
        with self.assertRaises(ValueError):
            verify(a, b, p)

    def test_duplicate_and_private_keys(self):
        for key, value in (("d", "secret"), ("k", "secret")):
            a, b, p = fixture()
            b["keys"][1][key] = value
            with self.assertRaises(ValueError):
                verify(a, b, p)
        a, b, p = fixture()
        b["keys"][1]["kid"] = "old"
        with self.assertRaises(ValueError):
            verify(a, b, p)

    def test_unsupported_algorithm(self):
        a, b, p = fixture()
        b["keys"][1]["alg"] = "HS256"
        with self.assertRaises(ValueError):
            verify(a, b, p)

    def test_replacement_must_use_distinct_public_material(self):
        a, b, p = fixture()
        b["keys"][1]["n"] = a["keys"][0]["n"]
        with self.assertRaisesRegex(ValueError, "reuses"):
            verify(a, b, p)

    def test_compromise_rejects_old_key_under_an_alias(self):
        a, b, p = fixture()
        p.update(mode="compromise", incident_approved=True)
        b["keys"][0] = {**b["keys"][0], "kid": "renamed-old"}
        with self.assertRaisesRegex(ValueError, "remains trusted"):
            verify(a, b, p)

    def test_compromise_requires_incident_and_removal(self):
        a, b, p = fixture()
        p["mode"] = "compromise"
        with self.assertRaises(ValueError):
            verify(a, b, p)
        p["incident_approved"] = True
        with self.assertRaises(ValueError):
            verify(a, b, p)
        b["keys"] = b["keys"][1:]
        self.assertTrue(verify(a, b, p))


if __name__ == "__main__":
    unittest.main()
