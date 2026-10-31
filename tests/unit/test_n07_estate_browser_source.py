"""N07 real-browser structural negatives; no playwright launch in CI."""
import importlib.util
import json
from pathlib import Path
import sys
import time
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "n07_estates_live", ROOT / "tests" / "browser" / "n07_estates_live.py")
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)

SHA = "a" * 40
RUN = "b" * 32


def profile():
    p = {
        "schema": mod.SCHEMA, "environment": "development", "run_id": RUN,
        "source_pins": {name: SHA for name in
                        ["baobab-iam", "baobab-cp", "shared", *mod.ESTATES]},
        "estates": {},
    }
    for name, (route, context) in mod.ESTATES.items():
        entry = {
            "origin": "https://internal.example.test",
            "entry_path": "/sign-in",
            "session_path": route,
            "identifier_selector": "#user",
            "password_selector": "#pass",
            "submit_selector": "button[type=submit]",
            "login_button_selector": "#start",
            "logout_button_selector": "#logout",
            "identifier_file": "/run/private/uid",
            "password_file": "/run/private/pass",
        }
        if context:
            entry["context_path"] = context
            entry["executive_navigation" if name == "nabhold" else "logistics_navigation"] = {
                "tenant_id": "tn_abcde", "market": "ZA",
            }
        p["estates"][name] = entry
    return p


class Response:
    def __init__(self, payload, status=200, headers=None):
        self.status = status
        self.headers = headers if headers is not None else {
            "cache-control": "private, no-store",
            "content-type": "application/json",
        }
        self.payload = payload

    def body(self):
        return self.payload


class N07BrowserSource(unittest.TestCase):
    def test_three_real_estates_required(self):
        mod.validate_browser_profile(profile())
        p = profile()
        del p["estates"]["thamani"]
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)

    def test_no_health_or_cross_owner_session_alias(self):
        p = profile()
        p["estates"]["thamani"]["session_path"] = "/api/health"
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)
        p = profile()
        p["estates"]["zuribeans"]["session_path"] = "/api/auth/session"
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)

    def test_nabhold_requires_cp_navigation_expectations(self):
        p = profile()
        p["estates"]["nabhold"].pop("executive_navigation")
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)
        p = profile()
        p["estates"]["nabhold"]["executive_navigation"]["tenant_id"] = "foreign"
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)

    def test_thamani_cp_navigation_required(self):
        p = profile()
        p["estates"]["thamani"].pop("context_path")
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)
        p = profile()
        p["estates"]["thamani"].pop("logistics_navigation")
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)

    def test_malformed_source_or_secret_file_blocks(self):
        p = profile()
        p["source_pins"]["nabhold"] = "main"
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)
        p = profile()
        p["estates"]["thamani"]["password_file"] = "../../bad"
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)
        p = profile()
        p["estates"]["thamani"]["login_button_selector"] = ""
        with self.assertRaises(mod.n07.Blocked):
            mod.validate_browser_profile(p)

    def test_current_bff_response_must_be_private_json(self):
        for response in (
            Response(b"{}", 200, {"cache-control": "public", "content-type": "application/json"}),
            Response(b"{}", 302),
            Response(b"{}", 200, {"cache-control": "no-store", "content-type": "text/html"}),
            Response(b'{"authenticated":true,"authenticated":false}'),
            Response(b"[" + b"0," * 5000 + b"0]"),
        ):
            with self.assertRaises(mod.n07.Blocked):
                mod.cookie_free_json(response)
        self.assertEqual(mod.cookie_free_json(Response(b'{"authenticated":true}')),
                         {"authenticated": True})

    def test_zuribeans_current_issuer_session(self):
        now = time.time() * 1000
        for name in ("zuribeans",):
            with self.assertRaises(mod.n07.Blocked):
                mod.current_session(name, {"authenticated": False, "expiresAt": now + 60000})
            with self.assertRaises(mod.n07.Blocked):
                mod.current_session(name, {"authenticated": True, "expiresAt": now - 1})
            mod.current_session(name, {"authenticated": True, "expiresAt": now + 60000})

    def test_cp_principal_uuids_for_nabhold_and_thamani(self):
        now = time.time() * 1000
        for name in ("nabhold", "thamani"):
            for subject in ("identity@email.test", "not-a-uuid", ""):
                with self.assertRaises(mod.n07.Blocked):
                    mod.current_session(name, {"principalId": subject, "expiresAt": now + 60000})
            mod.current_session(name, {"principalId": str(uuid4()), "expiresAt": now + 60000})

    def test_cp_navigation_is_only_read_model_never_execution_permit(self):
        now = time.time() * 1000
        expect = {"tenant_id": "tn_abcde", "market": "ZA"}
        ok = {
            "kind": "EXECUTIVE_NAVIGATION",
            "tenantId": "tn_abcde",
            "market": {"countryCode": "ZA"},
            "executionAuthority": False,
            "expiresAt": now + 60000,
        }
        mod.current_executive_context(ok, expect)
        mod.current_executive_context(dict(ok, kind="LOGISTICS_NAVIGATION"), expect, "LOGISTICS_NAVIGATION")
        for bad in (
            dict(ok, executionAuthority=True),
            dict(ok, tenantId="tn_other"),
            dict(ok, expiresAt=now - 100),
            dict(ok, kind="EXECUTIVE_OPERATION"),
        ):
            with self.assertRaises(mod.n07.Blocked):
                mod.current_executive_context(bad, expect)


if __name__ == "__main__":
    unittest.main()
