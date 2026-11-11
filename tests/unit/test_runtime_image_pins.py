import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.check_runtime_image_pins import verify


ROOT = Path(__file__).resolve().parents[2]
FILES = (
    "provider.lock.yaml",
    "upstream.lock.yaml",
    "docker-compose.yml",
    "docker-compose.ory.yml",
    "Dockerfile",
    ".github/workflows/ci.yml",
)


class RuntimeImagePinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in FILES:
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, dest)

    def mutate(self, path, before, after):
        target = self.root / path
        text = target.read_text(encoding="utf-8")
        self.assertIn(before, text)
        target.write_text(text.replace(before, after, 1), encoding="utf-8")

    def test_repository_image_locks_match(self):
        verify(self.root)

    def test_floating_postgres_image_denied(self):
        self.mutate("docker-compose.yml", "postgres@sha256:", "postgres:17-alpine#sha256:")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_runtime_kratos_pin_substitution_denied(self):
        self.mutate("docker-compose.ory.yml", "oryd/kratos:v26.2.0@sha256:", "oryd/kratos:v26.2.0@sha256:000")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_disposable_pg_pin_drift_denied(self):
        self.mutate(".github/workflows/ci.yml", "image: postgres@sha256:", "image: postgres:17-alpine@sha256:")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_keycloak_dockerfile_pin_drift_denied(self):
        self.mutate("Dockerfile", "quay.io/keycloak/keycloak:26.7.5@sha256:", "quay.io/keycloak/keycloak:26.7.5@sha256:000")
        with self.assertRaises(ValueError):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
