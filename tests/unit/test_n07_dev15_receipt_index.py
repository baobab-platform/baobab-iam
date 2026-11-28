"""Source regressions for custody. The fixtures are neither owner nor runtime evidence."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from n07_dev15_receipt_index import Blocked, PAYMENTS_BLOCKERS, receipt_index


class ReceiptIndexTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        pins = dict(zip(
            ("infrastructure", "shared", "baobab-iam", "baobab-cp", "baobab-payments"),
            (c * 40 for c in "abcde"), strict=True,
        ))
        self.lifecycle = {
            "schema": "infrastructure.dev01.lifecycle.observed.v1",
            "run_id": "b" * 32, "harness_sha": pins["infrastructure"],
            "source_pins": {k: v for k, v in pins.items() if k != "infrastructure"},
            "teardown_verified": True, "protected_acceptance": False, "production_authorized": False,
        }
        self.manifest = {
            "schema": "baobab.iam.dev15.private-index-input.v1", "adopter": "baobab-payments",
            "run_id": self.lifecycle["run_id"], "source_pins": pins,
            "lifecycle": self.write("lifecycle", self.lifecycle),
            "originals": {"issuer": self.write("issuer", {"fixture": True}), "cp": None, "engine": None},
        }

    def write(self, name, value):
        path = self.root / name
        raw = json.dumps(value).encode()
        path.write_bytes(raw)
        path.chmod(0o600)
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}

    def test_redacted_index_preserves_all_payments_blockers(self):
        result = receipt_index(self.manifest)
        self.assertEqual(result["acceptance"], "BLOCKED")
        self.assertEqual(set(result["blocked_cases"]), set(PAYMENTS_BLOCKERS))
        self.assertEqual(result["originals"]["issuer"]["status"], "HASH_VERIFIED_UNATTESTED")
        self.assertEqual(result["originals"]["cp"]["status"], "BLOCKED")
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_rejects_wrong_run_pin_and_missing_teardown(self):
        for changes in ({"run_id": "e"*32}, {"harness_sha": "f"*40}, {"source_pins": {}},
                        {"teardown_verified": False}, {"protected_acceptance": True}):
            with self.subTest(changes=changes), self.assertRaises(Blocked):
                self.manifest["lifecycle"] = self.write("lifecycle", self.lifecycle | changes)
                receipt_index(self.manifest)

    def test_rejects_modified_original(self):
        (self.root / "issuer").write_text("{}")
        with self.assertRaisesRegex(Blocked, "ORIGINAL_DIGEST_MISMATCH"):
            receipt_index(self.manifest)


if __name__ == "__main__":
    unittest.main()
