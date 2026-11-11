"""Regression tests for IAM CTS v2 historic-coverage and authority invariants."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/check_iam_cts_v2.py"
SPEC = importlib.util.spec_from_file_location("iam_cts_v2_validator", MODULE)
validator = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(validator)


class CTSCrosswalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy = validator.LEGACY.read_text(encoding="utf-8")
        cls.target = validator.TARGET.read_text(encoding="utf-8")
        cls.crosswalk = json.loads(validator.CROSSWALK.read_text(encoding="utf-8"))

    def test_all_227_sections_17_gates_and_44_requirements(self):
        validator.validate(self.legacy, self.target, self.crosswalk)

    def test_gap_or_duplicate_original_section_is_denied(self):
        data = copy.deepcopy(self.crosswalk)
        data["sections"][4]["from"] += 1
        with self.assertRaisesRegex(ValueError, "gap, overlap"):
            validator.validate(self.legacy, self.target, data)

    def test_renamed_original_heading_is_denied(self):
        data = copy.deepcopy(self.crosswalk)
        data["sections"][0]["first_heading"] = "Rewritten past"
        with self.assertRaisesRegex(ValueError, "title drift"):
            validator.validate(self.legacy, self.target, data)

    def test_undocumented_legacy_gate_is_denied(self):
        data = copy.deepcopy(self.crosswalk)
        data["gates"].pop()
        with self.assertRaisesRegex(ValueError, "17 original"):
            validator.validate(self.legacy, self.target, data)

    def test_undocumented_v2_normative_requirement_is_denied(self):
        target = self.target.replace("**CTS2-024.", "**CTS2-900.")
        with self.assertRaisesRegex(ValueError, "normative requirements"):
            validator.validate(self.legacy, target, self.crosswalk)

    def test_scope_or_provider_activation_is_denied(self):
        for name, value in (
            ("native_commitment_adr_status", "ACCEPTED"),
            ("native_commitment_scope_allocation", "ACTIVE"),
            ("provider_support", "ACTIVE"),
            ("protected_release", "GRANTED"),
        ):
            with self.subTest(name=name):
                data = copy.deepcopy(self.crosswalk)
                data["guardrails"][name] = value
                with self.assertRaisesRegex(ValueError, "authority promotion"):
                    validator.validate(self.legacy, self.target, data)

    def test_thamani_b2c_resurrection_is_denied(self):
        data = copy.deepcopy(self.crosswalk)
        data["gates"][7]["disposition"] = "REPLACED_SEQUENCE"
        with self.assertRaisesRegex(ValueError, "Thamani B2C"):
            validator.validate(self.legacy, self.target, data)


if __name__ == "__main__":
    unittest.main()
