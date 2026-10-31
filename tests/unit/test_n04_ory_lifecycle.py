"""Guard the live foundation test producer against malformed N02 injection.

Source layout checks are never substituted for a successful Ory live run.
"""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / "tests/ory-foundation/run.sh"
PROFILE = ROOT / "tests/ory-foundation/token_profile.sh"


class N04FoundationRunner(unittest.TestCase):
    def test_exact_real_client_test_and_original_provider_suite(self):
        content = RUN.read_text(encoding="utf-8")
        self.assertEqual(
            content.count("go test -json ./internal/nativebff -run '^TestLiveDevelopmentHydraEstateClientRegistration$'"),
            1,
        )
        self.assertEqual(
            content.count("go test -json ./internal/provider/ory -run"),
            1,
        )
        self.assertEqual(content.count("tee ory-foundation-evidence/tests.jsonl"), 1)
        self.assertEqual(content.count("tee ory-foundation-evidence/native-bff-client.jsonl"), 1)
        self.assertIn("missing live PASS evidence", content)
        self.assertIn("N02 actual Hydra client test skipped", content)
        for line in content.splitlines():
            self.assertFalse(line.strip().startswith("-count="),
                             "dangling go test arguments became a shell command")
        self.assertLess(content.index("native-bff-client.jsonl"),
                        content.index("go test -json ./internal/provider/ory -run"))

    def test_both_live_scripts_parse(self):
        for path in (RUN, PROFILE):
            result = subprocess.run(["bash", "-n", str(path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    check=False, timeout=10)
            self.assertEqual(result.returncode, 0, path.name)


if __name__ == "__main__":
    unittest.main()
