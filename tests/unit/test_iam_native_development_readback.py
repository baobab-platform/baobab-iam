"""IAM-native source-only fixtures. They NEVER qualify a running provider."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import iam_native_development_readback as gate

PKG = "github.com/baobab-platform/baobab-iam/internal/provider/ory"


def records(suite):
    return [{"Action": "pass", "Package": PKG, "Test": name}
            for name in sorted(gate.SUITES[suite])]


class TestNativeDeveloperCaseReader(unittest.TestCase):
    def test_all_native_families_and_synthetic_proofs_refuse_promotion(self):
        self.assertEqual(set(gate.SUITES),
                         {"kratos", "hydra", "keycloak", "security", "recovery"})
        for suite in gate.SUITES:
            gate.check_cases(suite, records(suite))
            for name in gate.SUITES[suite]:
                missing = [r for r in records(suite) if r["Test"] != name]
                with self.assertRaises(gate.Held):
                    gate.check_cases(suite, missing)
            for action in ("skip", "fail"):
                changed = records(suite)
                changed.append({"Action": action, "Package": PKG,
                                "Test": "TestLiveExtra"})
                with self.assertRaises(gate.Held):
                    gate.check_cases(suite, changed)

    def test_wrong_go_package_or_duplicate_properties_denied(self):
        for bad in ("example.com/untrusted", "github.com/baobab-platform/baobab-iam"):
            changed = records("kratos")
            changed[0]["Package"] = bad
            with self.assertRaises(gate.Held):
                gate.check_cases("kratos", changed)
        with self.assertRaises(gate.Held):
            gate.unique([("Action", "pass"), ("Action", "fail")])

    def test_original_digest_custody_and_complete_non_authorising_readback(self):
        with tempfile.TemporaryDirectory() as root:
            args = ["--iam-source-sha", "a" * 40]
            for suite in gate.SUITES:
                p = Path(root) / (suite + ".jsonl")
                d = Path(root) / (suite + ".sha256")
                raw = "".join(json.dumps(x) + "\n" for x in records(suite)).encode()
                p.write_bytes(raw)
                d.write_text(hashlib.sha256(raw).hexdigest() + "\n")
                p.chmod(0o600)
                d.chmod(0o600)
                args += ["--" + suite + "-log", str(p),
                         "--" + suite + "-digest", str(d)]
            self.assertEqual(gate.readback(args),
                             "IAM_NATIVE_REQUIRED_CASES_RECONCILED_UNATTESTED")
            mutated = list(args)
            mutated[1] = "main"
            with self.assertRaises(gate.Held):
                gate.readback(mutated)
            bad = Path(root) / "hydra.sha256"
            bad.write_text("f" * 64)
            with self.assertRaises(gate.Held):
                gate.readback(args)
            bad.chmod(0o644)
            with self.assertRaises(gate.Held):
                gate.readback(args)


if __name__ == "__main__":
    unittest.main()
