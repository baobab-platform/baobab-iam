"""IAM-N07 negative-first source tests. These never stand in for a live consumer."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "n07_connected_consumers", HERE / "scripts" / "n07_connected_consumers.py")
n07 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = n07
spec.loader.exec_module(n07)

SHA = "a" * 40
RUN = "b" * 32


def unit_jwt(label="one", *, expires_in=300):
    # Syntactically shaped UNIT DATA, not a signed token or live acceptance.
    now = int(time.time())
    payload = {"iat": now - 5, "exp": now + expires_in, "unit": label}
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True).encode()).rstrip(b"=").decode("ascii")
    return "eyJhbGciOiJub25lIn0." + encoded + ".fixture"


def example():
    names = ["nabhold", "zuribeans", "thamani", "baobab-pulse", "baobab-payments"]
    result = {
        "schema": n07.SCHEMA, "environment": "development", "run_id": RUN,
        "source_pins": {name: SHA for name in ["baobab-iam", "baobab-cp", "shared", *names]},
        "consumers": [],
    }
    for name in names:
        entry = {"name": name, "origin": "https://internal.example.test"}
        if name in n07.ESTATES:
            entry |= {"kind": "estate", "anonymous_path": n07.ESTATES[name]}
        else:
            entry |= {"kind": "engine", "resource_path": "/v1/owner/read"}
            entry.update({f"{c}_token_file": f"/private/{name}-{c}"
                          for c in n07.CASES[1:]})
        result["consumers"].append(entry)
    return result


class N07SourceTests(unittest.TestCase):
    def test_all_core_real_consumers_are_mandatory(self):
        self.assertEqual(set(n07.ESTATES) | n07.REQUIRED_ENGINES,
                         {c["name"] for c in n07.validate_profile(example())["consumers"]})
        p = example()
        p["consumers"].pop()
        with self.assertRaises(n07.Blocked):
            n07.validate_profile(p)

    def test_source_pins_and_run_nonce_are_strict(self):
        for bad in ("latest", "f" * 39, "", None):
            p = example()
            p["source_pins"]["baobab-cp"] = bad
            with self.assertRaises(n07.Blocked):
                n07.validate_profile(p)
        p = example()
        p["run_id"] = "not-the-private-run"
        with self.assertRaises(n07.Blocked):
            n07.validate_profile(p)

    def test_duplicate_and_undeclared_consumers_refused(self):
        p = example()
        p["consumers"][0]["name"] = "zuribeans"
        with self.assertRaises(n07.Blocked):
            n07.validate_profile(p)
        p = example()
        p["consumers"].append({"name": "unknown-service", "origin": "https://x.test"})
        with self.assertRaises(n07.Blocked):
            n07.validate_profile(p)

    def test_thamani_cannot_be_silently_called_zuribeans(self):
        p = example()
        p["consumers"][2]["anonymous_path"] = "/api/health"
        with self.assertRaises(n07.Blocked):
            n07.validate_profile(p)
        p = example()
        p["consumers"][2]["anonymous_path"] = "/api/iam/session"
        with self.assertRaises(n07.Blocked):
            n07.validate_profile(p)

    def test_no_browser_cookie_or_bearer_custody_in_profile(self):
        for key in ("session_token_file", "browser_token_file"):
            p = example()
            p["consumers"][0][key] = "/private/browser-token"
            with self.assertRaises(n07.Blocked):
                n07.validate_profile(p)

    def test_no_ssrf_or_ambiguous_path(self):
        for bad in ("http://public.example", "https://u:p@x.test",
                    "https://x.test/path", "https://x.test/?token=a",
                    "https://x.test/#frag", "file:///tmp/test",
                    "http://localhost:8080"):
            with self.subTest(bad=bad), self.assertRaises(n07.Blocked):
                n07.trusted_origin(bad)
        self.assertEqual(n07.trusted_origin("http://127.0.0.1:8080"),
                         "http://127.0.0.1:8080")
        for bad in ("//external.invalid", "/v1/../admin", "/v1//read",
                    "/read?token=a", "/read#x", "https://evil.test",
                    "/new\r\nAuthorization:bearer secret"):
            with self.subTest(bad=bad), self.assertRaises(n07.Blocked):
                n07.resource_path(bad)

    def test_malformed_identity_and_control_characters_fail_closed(self):
        for invalid in (None, 15, [], {}):
            candidate = example()
            candidate["run_id"] = invalid
            with self.assertRaises(n07.Blocked):
                n07.validate_profile(candidate)
            candidate = example()
            candidate["consumers"][0]["name"] = invalid
            with self.assertRaises(n07.Blocked):
                n07.validate_profile(candidate)
        for bad in ("/v1/hello world", "/v1/read\\tAuthorization:x", "/v1/é"):
            with self.assertRaises(n07.Blocked):
                n07.resource_path(bad)

    def test_only_json_no_store_200_is_native_readback_candidate(self):
        class Response:
            def __init__(self, content_type, cache_control):
                self.status = 200
                self.headers = {"Content-Type": content_type, "Cache-Control": cache_control}
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        class Opener:
            def __init__(self, reply):
                self.reply = reply
            def open(self, *args, **kwargs):
                return self.reply
        for mime, cache, expected in (
            ("text/html", "no-store", False),
            ("application/json", "public", False),
            ("application/json; charset=utf-8", "private, no-store", True),
        ):
            with patch.object(n07, "build_opener", return_value=Opener(Response(mime, cache))):
                status, protected_json = n07.http_probe("https://internal.example.test", "/v1/owner/read", None)
                self.assertEqual(status, 200)
                self.assertEqual(protected_json, expected)

    def test_private_file_rejects_world_readable_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "secret"
            source.write_text("secret")
            source.chmod(0o644)
            with self.assertRaises(n07.Blocked):
                n07.private_read(str(source))
            source.chmod(0o600)
            self.assertEqual(n07.private_read(str(source)), b"secret")
            link = Path(d) / "link"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                n07.private_read(str(link))

    def test_duplicate_json_property_rejected(self):
        with self.assertRaises(n07.Blocked):
            n07.pairs_unique([("schema", "one"), ("schema", "two")])

    def test_missing_thamani_real_session_is_blocked_not_passed(self):
        def fake(origin, path, bearer):
            if path == "/api/auth/session" and bearer is None:
                return 404, False
            return (401, True) if bearer is None else (403, True)
        with patch.object(n07, "token", side_effect=lambda path: path):
            result = n07.observe(example(), "before", fake)
        self.assertEqual(result["cases"]["N07_THAMANI_ANONYMOUS"], "BLOCKED")
        self.assertEqual(result["cases"]["N07_NABHOLD_BROWSER_AND_CP"], "BLOCKED")
        self.assertFalse(result["fully_qualified"])
        self.assertFalse(result["cp_authority_certified"])

    def test_status_404_or_503_is_not_a_denial_witness(self):
        def fake(_origin, _path, bearer):
            return (404, True) if bearer is None else (503, False)
        with patch.object(n07, "token", side_effect=lambda p: p):
            result = n07.observe(example(), "before", fake)
        self.assertTrue(all(x == "BLOCKED" for x in result["cases"].values()))

    def test_real_response_status_and_no_store_required_for_positive(self):
        def fake(_origin, _path, bearer):
            return (200, False) if bearer is not None else (401, False)
        with patch.object(n07, "token", side_effect=lambda p: p):
            result = n07.observe(example(), "before", fake)
        self.assertEqual(result["cases"]["N07_BAOBAB_PULSE_ALLOWED"], "BLOCKED")
        self.assertEqual(result["cases"]["N07_BAOBAB_PULSE_ANONYMOUS"], "OBSERVED")
        self.assertEqual(result["cases"]["N07_BAOBAB_PULSE_MISSING_GRANT"], "BLOCKED")

    def test_wrong_negative_token_cannot_be_the_good_token(self):
        def fake(_origin, _path, bearer):
            return (401, True) if bearer is None else (200, True)
        with patch.object(n07, "token", return_value=unit_jwt()):
            result = n07.observe(example(), "before", fake)
        self.assertEqual(result["cases"]["N07_BAOBAB_PAYMENTS_ALLOWED"], "OBSERVED")
        self.assertEqual(result["cases"]["N07_BAOBAB_PAYMENTS_WRONG_AUDIENCE"], "BLOCKED")

    def test_expired_negative_token_cannot_masquerade_as_native_policy_denial(self):
        # The fake HTTP resource rejects an expired bearer with 403. That
        # observation must NOT qualify a wrong-audience or policy-boundary case.
        def token_for(path):
            return unit_jwt(path, expires_in=-30 if "wrong_audience" in path else 300)

        def resource_response(_origin, _path, bearer):
            if bearer is None:
                return 401, True
            payload = bearer.split(".")[1]
            original = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            return (200, True) if original["unit"].endswith("-allowed") else (403, True)

        with patch.object(n07, "token", side_effect=token_for):
            result = n07.observe(example(), "before", resource_response)

        self.assertEqual(result["cases"]["N07_BAOBAB_PULSE_ALLOWED"], "OBSERVED")
        self.assertEqual(result["cases"]["N07_BAOBAB_PULSE_WRONG_AUDIENCE"], "BLOCKED")
        self.assertEqual(result["cases"]["N07_BAOBAB_PAYMENTS_WRONG_AUDIENCE"], "BLOCKED")
        self.assertFalse(result["fully_qualified"])

    def test_expired_or_oversized_jwt_fails_without_proving_signature(self):
        for value in (unit_jwt(expires_in=-10), unit_jwt(expires_in=10),
                      "not.a.valid.token", unit_jwt(expires_in=3600)):
            with self.subTest(value=value[:20]), self.assertRaises(n07.Blocked):
                n07.unexpired_jwt(value)

    def test_after_rejects_missing_or_tampered_pre_original(self):
        with tempfile.TemporaryDirectory() as d:
            n07.original_write(d, "before", n07.observe(
                example(), "before", lambda *_: (401, True)))
            with self.assertRaises(n07.Blocked):
                n07.require_before(example(), d)
            with (Path(d) / "before.sha256").open("w") as stream:
                stream.write("0" * 64 + "\n")
            with self.assertRaises(n07.Blocked):
                n07.require_before(example(), d)

    def test_after_requires_exact_same_original_token(self):
        with patch.object(n07, "token", side_effect=lambda path: path), \
                patch.object(n07, "http_probe", return_value=(401, True)):
            # Explicit probe injected: no network and no provider acceptance.
            result = n07.observe(example(), "after",
                lambda _origin, _path, _bearer: (401, True))
        self.assertEqual(result["cases"]["N07_BAOBAB_PULSE_REVOKED_UNEXPIRED"], "BLOCKED")

    def test_post_revocation_observation_always_unattested(self):
        p = example()
        original = unit_jwt()
        before = {"fingerprints": {name: n07.fingerprint(RUN, original)
                                   for name in n07.REQUIRED_ENGINES}}
        with patch.object(n07, "token", return_value=original):
            result = n07.observe(p, "after",
                lambda _origin, _path, _bearer: (403, True), before=before)
        self.assertEqual(result["cases"]["N07_BAOBAB_PAYMENTS_REVOKED_UNEXPIRED"], "OBSERVED")
        self.assertFalse(result["fully_qualified"])
        self.assertFalse(result["issuer_qualified"])

    def test_originals_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "private"
            receipt = {"accepted": False, "cases": {"example": "BLOCKED"}}
            n07.original_write(str(root), "before", receipt)
            self.assertEqual((root / "before.json").stat().st_mode & 0o077, 0)
            self.assertEqual((root / "before.sha256").stat().st_mode & 0o077, 0)
            with self.assertRaises(n07.Blocked):
                n07.original_write(str(root), "before", receipt)


if __name__ == "__main__":
    unittest.main()
