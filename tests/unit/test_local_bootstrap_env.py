"""Exercise secret lifecycle and failure paths; no live IAM account is created."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("local_bootstrap_env", ROOT / "scripts/local_bootstrap_env.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def entries(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if line and not line.startswith("#"))


class LocalBootstrapEnvTests(unittest.TestCase):
    def test_private_unique_local_credentials_without_workload_seed_or_authority(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            first, second = directory / ".env", directory / ".env.local"
            previous = os.umask(0)
            try:
                module.create_local_env(first, "local-bootstrap", "local")
                module.create_local_env(second, "ci-bootstrap", "ci")
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)
            values = [entries(first), entries(second)]
            secrets = [value[key] for value in values for key in ("KEYCLOAK_ADMIN_PASSWORD", "POSTGRES_PASSWORD")]
            self.assertEqual(len(set(secrets)), 4)
            for secret in secrets:
                self.assertRegex(secret, r"^[A-Za-z0-9_-]{43}$")
            self.assertNotIn("BOOTSTRAP_WORKLOAD_CLIENT_SECRET", values[0])
            self.assertNotIn("SUPER_ADMIN", first.read_text())
            self.assertEqual(list(directory.glob(".bootstrap-env-*")), [])

    def test_existing_secret_or_symlink_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            output = directory / ".env"
            output.write_text("existing configuration")
            with self.assertRaises(FileExistsError):
                module.create_local_env(output, "bootstrap-admin", "local")
            self.assertEqual(output.read_text(), "existing configuration")
            output.unlink()
            target = directory / "operator-file"
            target.write_text("untouched")
            output.symlink_to(target)
            with self.assertRaises(FileExistsError):
                module.create_local_env(output, "bootstrap-admin", "local")
            self.assertTrue(output.is_symlink())
            self.assertEqual(target.read_text(), "untouched")
            self.assertEqual(list(directory.glob(".bootstrap-env-*")), [])

    def test_unsafe_parent_and_symlink_parent_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            unsafe = directory / "unsafe"
            unsafe.mkdir(mode=0o700)
            unsafe.chmod(0o777)
            with self.assertRaises(ValueError):
                module.create_local_env(unsafe / ".env", "bootstrap-admin", "local")
            self.assertEqual(list(unsafe.iterdir()), [])
            unsafe.chmod(0o700)
            alias = directory / "alias"
            alias.symlink_to(unsafe, target_is_directory=True)
            with self.assertRaises(OSError):
                module.create_local_env(alias / ".env", "bootstrap-admin", "local")

    def test_production_and_shell_injection_input_cannot_create_files(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / ".env"
            for username, environment in [("admin", "production"), ("x\nROLE=SUPER_ADMIN", "local"), ("$(command)", "ci")]:
                with self.assertRaises(ValueError):
                    module.create_local_env(output, username, environment)
                self.assertFalse(output.exists())
            with self.assertRaises(ValueError):
                module.create_local_env(output.with_name("credentials.json"), "admin", "local")

    def test_cli_does_not_emit_secret_values_and_bad_args_are_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / ".env"
            result = subprocess.run([sys.executable, str(ROOT / "scripts/local_bootstrap_env.py"), "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            for key in ("KEYCLOAK_ADMIN_PASSWORD", "POSTGRES_PASSWORD"):
                self.assertNotIn(entries(output)[key], result.stdout + result.stderr)
            rejected = subprocess.run([sys.executable, str(ROOT / "scripts/local_bootstrap_env.py"), "--token", "do-not-echo-this"], capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertNotIn("do-not-echo-this", rejected.stdout + rejected.stderr)

    def test_bootstrap_refuses_missing_admin_credentials_or_nonlocal_seed_before_login(self):
        # These paths exit before any Keycloak binary/network call. An absent
        # kcadm executable must not be mistaken for the tested refusal reason.
        for values, expected in [
            ({}, "KEYCLOAK_ADMIN"),
            ({"KEYCLOAK_ADMIN": "fixture-admin"}, "KEYCLOAK_ADMIN_PASSWORD"),
            ({"KEYCLOAK_ADMIN": "fixture-admin", "KEYCLOAK_ADMIN_PASSWORD": "synthetic-test-password", "BOOTSTRAP_WORKLOAD_CLIENT_SECRET": "synthetic-test-seed", "BAOBAB_ENVIRONMENT": "production"}, "restricted"),
        ]:
            environment = {key: value for key, value in os.environ.items() if key not in {"KEYCLOAK_ADMIN", "KEYCLOAK_ADMIN_PASSWORD", "BOOTSTRAP_WORKLOAD_CLIENT_SECRET", "BAOBAB_ENVIRONMENT"}}
            environment.update(values)
            result = subprocess.run(["bash", str(ROOT / "scripts/bootstrap.sh")], env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertNotIn("synthetic-test-password", result.stdout + result.stderr)
            self.assertNotIn("kcadm.sh", result.stderr)

    def test_secret_dotenv_names_are_excluded_from_git_and_build_context(self):
        for filename in (".gitignore", ".dockerignore"):
            lines = (ROOT / filename).read_text().splitlines()
            self.assertIn(".env", lines)
            self.assertIn(".env.*", lines)
            self.assertIn(".bootstrap-env-*", lines)
            self.assertIn("!.env.example", lines)


if __name__ == "__main__":
    unittest.main()
