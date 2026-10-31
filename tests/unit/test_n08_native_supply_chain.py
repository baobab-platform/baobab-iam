"""IAM-N08 source gate negatives. No runtime or provider acceptance."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("n08", ROOT / "scripts/n08_verify_supply_chain.py")
n08 = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = n08
spec.loader.exec_module(n08)


class N08SourcePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = [
            (ROOT / "Dockerfile.native-browser-bff").read_text(),
            (ROOT / "Dockerfile.federation-authority").read_text(),
            (ROOT / "go.mod").read_text(),
            (ROOT / "go.sum").read_text(),
            (ROOT / ".dockerignore").read_text(),
        ]

    def test_current_source_is_bound_but_not_live_proof(self):
        self.assertIsNone(n08.check(*self.args))

    def test_mutable_toolchain_and_digest_drift_denied(self):
        for replacement in ("golang:1.27.3-alpine", "golang:latest",
                            "golang:1.27.3-alpine@sha256:" + "0" * 64):
            args = self.args.copy()
            args[0] = args[0].replace(
                "golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd",
                replacement)
            with self.subTest(replacement=replacement), self.assertRaises(n08.PolicyError):
                n08.check(*args)

    def test_runtime_must_be_rootless_without_wide_copy(self):
        for before, after in (
            ("FROM scratch", "FROM alpine:latest"),
            ("USER 65532:65532", "USER 0:0"),
            ("COPY internal/ ./internal/", "COPY . ./"),
            ("GOTOOLCHAIN=local", "GOTOOLCHAIN=auto"),
            ("-trimpath -buildvcs=false", "-buildvcs=true"),
            ("go mod verify", "go mod download"),
        ):
            args = self.args.copy()
            args[0] = args[0].replace(before, after)
            with self.subTest(change=before), self.assertRaises(n08.PolicyError):
                n08.check(*args)

    def test_replaced_or_unlocked_dependencies_denied(self):
        args = self.args.copy()
        args[2] += "\nreplace github.com/go-jose/go-jose/v4 => ../local\n"
        with self.assertRaises(n08.PolicyError):
            n08.check(*args)
        args = self.args.copy()
        args[3] = ""
        with self.assertRaises(n08.PolicyError):
            n08.check(*args)

    def test_discarding_source_exclusions_denied(self):
        args = self.args.copy()
        args[4] = args[4].replace(".env.*", "# .env.*")
        with self.assertRaises(n08.PolicyError):
            n08.check(*args)


if __name__ == "__main__":
    unittest.main()
