"""N02 real-provider client manager: source-only negative tests, NO issuer acceptance."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "scripts/n02_development_clients.py"
spec = importlib.util.spec_from_file_location("iam_n02_client_registry", SOURCE)
assert spec and spec.loader
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class NativeClientSourceTests(unittest.TestCase):
    def setUp(self):
        self.run = "a" * 32
        self.lease = {
            "schema": "baobab.iam.n02.disposable-clients.v1",
            "environment": "development",
            "protected_acceptance": False,
            "run_id": self.run,
            "iam_source_sha": "b" * 40,
            "shared_source_sha": "c" * 40,
            "cp_source_sha": "d" * 40,
            "zuribeans_source_sha": "e" * 40,
            "infrastructure_harness_sha": "f" * 40,
            "estate_origin": "https://n02.example.test",
            "hydra_admin_origin": "http://127.0.0.1:4445",
            "expires_at_unix": int(time.time()) + 500,
            "browser_secret_file": "/private/browser",
            "cp_reader_secret_file": "/private/reader",
        }

    def profile(self, *, revision="b" * 40, dirt=""):
        def read(file, limit=32768):
            if file == "/private/profile":
                return json.dumps(self.lease).encode()
            if file in ("/private/browser", "/private/reader"):
                return b"x" * 64
            raise AssertionError("unknown credential file")
        with (
            patch.dict(os.environ, {"BAOBAB_ENVIRONMENT": "development"}),
            patch.object(manager, "private_bytes", side_effect=read),
            patch.object(manager.subprocess, "run", side_effect=[
                SimpleNamespace(stdout=revision + "\n"),
                SimpleNamespace(stdout=dirt),
            ]),
        ):
            return manager.current_profile("/private/profile")

    def test_disposable_registration_is_exact_and_separate(self):
        doc = self.profile()
        with patch.object(manager, "private_bytes", return_value=b"x" * 64):
            registry = manager.Registry(doc)
            browser = registry.expected(manager.ROLES[0])
            cp = registry.expected(manager.ROLES[1])
        self.assertEqual(browser["client_id"], "baobab-dev-zuribeans-native-browser-bff")
        self.assertEqual(browser["grant_types"], ["authorization_code"])
        self.assertEqual(browser["response_types"], ["code"])
        self.assertEqual(browser["scope"], "openid trade:buy")
        self.assertEqual(browser["redirect_uris"], ["https://n02.example.test/auth/callback"])
        self.assertEqual(cp["client_id"], "baobab-dev-zuribeans-cp-principal-validator")
        self.assertEqual(cp["grant_types"], ["client_credentials"])
        self.assertEqual(cp["response_types"], [])
        self.assertEqual(cp["scope"], "identity:principal:resolve")
        self.assertEqual(cp["audience"], ["baobab-control-plane"])
        self.assertNotIn("redirect_uris", cp)
        self.assertNotEqual(cp["client_id"], browser["client_id"])
        self.assertTrue(all(p["metadata"]["development_run_id"] == self.run for p in (browser, cp)))

    def test_profile_does_not_accept_protected_or_unknown_source(self):
        self.assertEqual(self.profile()["run_id"], self.run)
        for key, value in (
            ("environment", "production"),
            ("protected_acceptance", True),
            ("run_id", "notrun"),
            ("iam_source_sha", "main"),
            ("estate_origin", "https://attacker@n02.example.test"),
            ("hydra_admin_origin", "https://hydra.example.test"),
            ("expires_at_unix", int(time.time()) + 7000),
        ):
            with self.subTest(key=key):
                original = self.lease[key]
                self.lease[key] = value
                try:
                    with self.assertRaises((manager.Refused, ValueError)):
                        self.profile()
                finally:
                    self.lease[key] = original
        with self.assertRaises(manager.Refused):
            self.profile(revision="f" * 40)
        with self.assertRaises(manager.Refused):
            self.profile(dirt="?? malicious_override.py\n")

    def test_existing_client_rejected_without_adoption(self):
        with patch.object(manager, "private_bytes", return_value=b"x" * 64):
            registry = manager.Registry(self.lease)
            with patch.object(registry, "request", return_value=(200, {"client_id": "foreign"})) as send:
                with self.assertRaisesRegex(manager.Refused, "N02_CLIENT_ID_ALREADY_USED"):
                    registry.register()
                self.assertEqual(send.call_count, 1)

    def test_partial_recovery_only_deletes_owned_readback(self):
        registry = manager.Registry(self.lease)
        called = []
        removed = False
        def send(method, path, payload=None):
            nonlocal removed
            called.append((method, path))
            if method == "GET" and path.endswith(manager.CP_READER):
                return 404, None
            if method == "GET" and path.endswith(manager.BROWSER):
                return (404, None) if removed else (200, {"client_id": manager.BROWSER})
            if method == "DELETE" and path.endswith(manager.BROWSER):
                removed = True
                return 204, None
            raise AssertionError("unexpected path")
        with (
            patch.object(registry, "request", side_effect=send),
            patch.object(registry, "readback") as readback,
        ):
            registry.recover()
            readback.assert_called_once_with(manager.ROLES[0])
        self.assertEqual([c[0] for c in called], ["GET", "GET", "DELETE", "GET"])

    def test_immutable_originals_are_private_and_cannot_be_rewritten(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            root.chmod(0o700)
            manager.original(d, self.lease, "REGISTER")
            out = root / "n02-clients-register.json"
            digest = root / "n02-clients-register.sha256"
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(hashlib.sha256(out.read_bytes()).hexdigest(),
                             digest.read_text().strip())
            self.assertFalse(json.loads(out.read_text())["cp_principal_resolved"])
            with self.assertRaises(FileExistsError):
                manager.original(d, self.lease, "REGISTER")


if __name__ == "__main__":
    unittest.main()
