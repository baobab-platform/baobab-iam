"""IAM-N01 negative source governance drift checks."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("iam_n01", ROOT / "scripts/check_iam_n01.py")
n01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n01)


class IAMN01Tests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / n01.RECORD_PATH).read_text())
        self.lock = yaml.safe_load((ROOT / "contracts.lock.yaml").read_text())
        self.declaration = yaml.safe_load((ROOT / ".baobab/capability-provider.yaml").read_text())

    def deny(self, message):
        with self.assertRaisesRegex(ValueError, message):
            n01.check(record=self.record, lock=self.lock, declaration=self.declaration)

    def test_baseline(self):
        self.assertTrue(n01.check(record=self.record, lock=self.lock, declaration=self.declaration))

    def test_new_shared_pin_without_qualification_denied(self):
        self.lock["source"]["commit"] = self.record["shared"]["reviewed_head"]
        self.deny("Shared lock differs")

    def test_manifest_cannot_pretend_repin_is_approved(self):
        self.record["shared"]["decision"] = "ACTIVE"
        self.deny("re-pin was not independently reviewed")

    def test_manifest_cannot_move_to_new_shared_head(self):
        self.record["shared"]["pin"] = self.record["shared"]["reviewed_head"]
        self.deny("re-pin was not independently reviewed")

    def test_no_staging_bootstrap(self):
        self.record["development"]["environment"] = "staging"
        self.deny("development/protected boundary")

    def test_no_production_bootstrap(self):
        self.record["development"]["no_protected_bootstrap"] = False
        self.deny("development/protected boundary")

    def test_staging_requires_independent_acceptance(self):
        self.record["development"]["no_protected_acceptance_from_development"] = False
        self.deny("development/protected boundary")

    def test_no_self_approval(self):
        self.record["development"]["distinct_maker_checker_principals"] = False
        self.deny("development/protected boundary")

    def test_synthetic_development_no_run_by_run_human_gate(self):
        self.record["development"]["independent_human_approval_per_run"] = True
        self.deny("development/protected boundary")

    def test_real_signed_provider_tokens_are_required(self):
        self.record["development"]["real_provider_tokens_required"] = False
        self.deny("development/protected boundary")

    def test_development_lease_maximum_is_24_hours(self):
        self.record["development"]["max_lease_seconds"] = 86401
        self.deny("development/protected boundary")

    def test_development_does_not_grant_authority(self):
        self.record["development"]["no_authority_from_scope_or_provider_health"] = False
        self.deny("development/protected boundary")

    def test_no_unreviewed_fourth_provider(self):
        extra = copy.deepcopy(self.declaration["providers"][0])
        extra["provider_key"] = "baobab-iam.shadow"
        self.declaration["providers"].append(extra)
        self.deny("provider declaration mismatch")

    def test_no_premature_canonical_support_promotion(self):
        self.declaration["providers"][0]["support"][0]["implementation_status"] = "IMPLEMENTED"
        self.deny("cannot promote support")

    def test_no_fallback_from_hydra_to_keycloak(self):
        self.declaration["providers"][1]["implementation_key"] = "keycloak"
        self.deny("provider allocation drift")

    def test_unknown_canonical_capability_is_denied(self):
        self.declaration["providers"][0]["support"][0]["capability_key"] = "identity.human.provision"
        self.deny("canonical capability/major")

    def test_planned_key_not_implicitly_approved(self):
        self.declaration["planned_capabilities"][0]["proposal_status"] = "IMPLEMENTED"
        self.deny("improperly promoted")

    def test_required_shared_contracts_cannot_disappear(self):
        self.lock["contracts"].remove("contracts/identity/v1/workload-registry.yaml")
        self.deny("required Shared contract missing")

    def test_accepted_adr_precedence_not_demoted(self):
        self.record["governing"]["native_status"] = "Proposed"
        self.deny("ADR precedence mismatch")


if __name__ == "__main__":
    unittest.main()
