"""Validate historical/current separation and the pinned Shared case vocabulary."""
from datetime import date
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import iam_cts_evidence_register as register


class EvidenceRegisterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = register.canonical_cases(Path(os.environ["SHARED_REPO_DIR"]))

    def setUp(self):
        self.data = json.loads(register.REGISTER.read_text(encoding="utf-8"))
        self.records = {r["id"]: r for r in self.data["requirements"]}

    def test_current_register_and_shared_case_inventory(self):
        register.validate(self.data, self.cases)
        self.assertIn("payments-sandbox:PAYMENTS-EVENT-REPLAY", self.cases["DEV-15"])
        self.assertIn("INT-03C", self.cases["DEV-04"])

    def test_rejects_registered_case_from_unrelated_package(self):
        record = self.records["CTS2-015"]
        record["required_cases"] = ["NAB-03"]
        record["case_outcomes"] = {"NAB-03": "NOT_OBSERVED"}
        with self.assertRaisesRegex(ValueError, "case mapping"):
            register.validate(self.data, self.cases)

    def test_rejects_stale_workflow_marked_current(self):
        record = self.records["CTS2-032"]
        old = next(o for o in record["observations"] if o["standing"] == "HISTORICAL")
        old["standing"] = "CURRENT_CANDIDATE"
        with self.assertRaisesRegex(ValueError, "candidate head"):
            register.validate(self.data, self.cases)

    def test_review_can_advance_for_exact_head_and_does_not_carry_forward(self):
        record = self.records["CTS2-032"]
        old = next(o for o in record["observations"] if o["standing"] == "HISTORICAL")
        candidate = record["candidate"]
        ref = candidate["reference"]
        history = [
            {"decision": "CHANGES_REQUESTED", "head_sha": old["source_sha"],
             "observed_at": "2026-11-28T00:00:00Z", "reference": ref + "#pullrequestreview-1"},
            {"decision": "APPROVED", "head_sha": candidate["head_sha"],
             "observed_at": "2026-11-28T01:00:00Z", "reference": ref + "#pullrequestreview-2"},
        ]
        record["review"] = [
            {"reviewer": "fixture-reviewer", "scope": "SOURCE_RECORD", **entry} for entry in history
        ]
        recorded = date.fromisoformat(self.data["observed_on"])
        register.validate(self.data, self.cases)
        self.assertEqual(register.check_review(record["review"], candidate, recorded), "APPROVED")
        self.assertEqual(register.check_review(record["review"], candidate | {"head_sha": "0" * 40},
                                               recorded), "PENDING")
        record["review"].reverse()
        with self.assertRaisesRegex(ValueError, "chronological"):
            register.validate(self.data, self.cases)

    def test_rejects_foreign_pr_review_even_with_matching_head(self):
        record = self.records["CTS2-032"]
        record["review"] = [{"decision": "APPROVED", "head_sha": record["candidate"]["head_sha"],
                             "observed_at": "2026-11-28T01:00:00Z",
                             "reference": register.REPO + "pull/1#pullrequestreview-1",
                             "reviewer": "fixture-reviewer", "scope": "SOURCE_RECORD"}]
        with self.assertRaisesRegex(ValueError, "candidate PR"):
            register.validate(self.data, self.cases)


if __name__ == "__main__":
    unittest.main()
