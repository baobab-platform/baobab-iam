"""Source-only N02 browser admission/custody regression tests.

These tests mock the browser producer and MUST NEVER count as Playwright,
Kratos, Hydra, Control Plane or DEV-04 runtime acceptance.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[2] / "tests/browser/n02_live.py"
spec = importlib.util.spec_from_file_location("iam_n02_browser", MODULE)
browser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser)


class BrowserSourceAndCustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.folder.chmod(0o700)
        self.sha = "a" * 40
        self.profile = {
            "schema": "baobab.iam.n02.browser-qualification.v1",
            "environment": "development",
            "run_id": "b" * 32,
            "iam_source_sha": self.sha,
            "shared_source_sha": "c" * 40,
            "cp_source_sha": "d" * 40,
            "infrastructure_harness_sha": "e" * 40,
            "bff_origin": "https://bff.example.invalid",
            "kratos_origin": "https://kratos.example.invalid",
            "hydra_origin": "https://hydra.example.invalid",
            "require_aal2": True,
            "post_recovery_password_file": "/dev/null",
            "synthetic_identifier": "synthetic@example.invalid",
            "selectors": {name: "#fixture" for name in (
                "identifier", "password", "submit", "recovery_identifier",
                "recovery_submit", "recovery_code", "recovery_complete",
            )},
        }

    def load(self):
        with (patch.dict(os.environ, {
                "BAOBAB_ENVIRONMENT": "development",
                "BAOBAB_N02_PRIVATE_PROFILE": "/private/fixture.json",
              }),
              patch.object(browser, "private_file",
                           return_value=json.dumps(self.profile).encode()),
              patch.object(browser.subprocess, "run", side_effect=[
                  SimpleNamespace(stdout=self.sha + "\n"),
                  SimpleNamespace(returncode=0),
              ])):
            return browser.load_profile()

    def test_only_exact_clean_source_and_aal2_profile_admitted(self):
        self.assertEqual(self.load()["iam_source_sha"], self.sha)
        for key, value in (
            ("require_aal2", False),
            ("cp_source_sha", "not-a-sha"),
            ("post_recovery_password_file", None),
        ):
            with self.subTest(key=key):
                original = self.profile[key]
                self.profile[key] = value
                try:
                    with self.assertRaises(browser.Denied):
                        self.load()
                finally:
                    self.profile[key] = original

    def test_claimed_source_does_not_bypass_real_git_revision(self):
        with (patch.dict(os.environ, {
                "BAOBAB_ENVIRONMENT": "development",
                "BAOBAB_N02_PRIVATE_PROFILE": "/private/fixture.json",
              }),
              patch.object(browser, "private_file",
                           return_value=json.dumps(self.profile).encode()),
              patch.object(browser.subprocess, "run", side_effect=[
                  SimpleNamespace(stdout="f" * 40 + "\n"),
                  SimpleNamespace(returncode=0),
              ])):
            with self.assertRaises(browser.Denied):
                browser.load_profile()

    def test_original_receipt_and_sidecar_are_owner_private(self):
        # Deliberately mock all cases: only filesystem integrity is tested.
        with (patch.dict(os.environ, {"BAOBAB_N02_EVIDENCE_DIR": str(self.folder)}),
              patch.object(browser, "load_profile", return_value=self.profile),
              patch.object(browser, "run_browser",
                           return_value={name: "OBSERVED" for name in browser.CASES})):
            self.assertEqual(browser.main(), 0)
        receipt = self.folder / "browser-observation.json"
        sidecar = self.folder / "browser-observation.sha256"
        for path in (receipt, sidecar):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(sidecar.read_text().strip(),
                         hashlib.sha256(receipt.read_bytes()).hexdigest())
        actual = json.loads(receipt.read_text())
        self.assertEqual(actual["cp_source_sha"], self.profile["cp_source_sha"])
        self.assertEqual(actual["shared_source_sha"], self.profile["shared_source_sha"])
        self.assertFalse(actual["provider_and_cp_independently_attested"])
        self.assertFalse(actual["protected_accepted"])


if __name__ == "__main__":
    unittest.main()
