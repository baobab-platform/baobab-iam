"""N08 source-only safety regressions. NOT a real provider restore receipt."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("n08_ory_restore", ROOT / "tests/operations/n08_ory_restore_state.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class N08RealProviderRestoreSafety(unittest.TestCase):
    def test_no_remote_provider_urls_or_browser_selected_redirects(self):
        for value in ("https://production.invalid/oauth2/token",
                      "http://host.docker.internal:4434/admin/identities",
                      "http://127.0.0.1:8080/realms/master",
                      "http://127.0.0.1:4445.evil.invalid/admin/keys"):
            with self.subTest(value=value), self.assertRaises(mod.Refused):
                mod.request("GET", value)

    def test_private_oneuse_fixture_custody(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            directory.chmod(0o700)
            target = directory / "state.json"
            original = {"identity_id": "synthetic", "session": "disposable",
                        "client_id": "synthetic", "client_secret": "disposable"}
            mod.save(target, original)
            self.assertEqual(mod.load(target), original)
            with self.assertRaises(mod.Refused):
                mod.save(target, original)
            target.chmod(0o644)
            with self.assertRaises(mod.Refused):
                mod.load(target)
            target.chmod(0o600)
            link = directory / "symlink.json"
            link.symlink_to(target)
            with self.assertRaises(mod.Refused):
                mod.load(link)

    def test_destructive_restore_must_be_ci_disposable(self):
        script = ROOT / "tests/operations/n08_ory_live_restore.sh"
        source = script.read_text()
        self.assertIn('test "${GITHUB_ACTIONS:-}" = true', source)
        self.assertIn('test "${ORY_FOUNDATION:-}" = 1', source)
        self.assertIn("com.docker.compose.project", source)
        self.assertIn('docker exec "$kratos_db" pg_dump', source)
        self.assertIn('docker exec "$hydra_db" pg_dump', source)
        self.assertIn("pg_restore --exit-on-error", source)
        self.assertIn("n08_ory_restore_state.py verify", source)
        self.assertIn("rm -rf --", source)
        result = subprocess.run(["bash", "-n", str(script)],
                                capture_output=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, "N08 shell syntax invalid")
        # No real provider or CI label in this offline environment; MUST
        # refuse without touching any Compose databases.
        env = dict(os.environ, GITHUB_ACTIONS="false", ORY_FOUNDATION="1")
        result = subprocess.run(["bash", str(script)], capture_output=True,
                                env=env, check=False, timeout=10)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
