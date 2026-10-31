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


    def test_duplicate_json_governance_keys_are_denied(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            n01.load_unique_json('{"development": {"environment":"development"}, "development": {}}')

    def test_duplicate_yaml_governance_keys_are_denied(self):
        with self.assertRaisesRegex(ValueError, "duplicate YAML key"):
            n01.load_unique_yaml("source:\\n  commit: first\\nsource:\\n  commit: second\\n".replace("\\n", "\n"))

    def test_duplicate_nested_yaml_provider_keys_are_denied(self):
        with self.assertRaisesRegex(ValueError, "duplicate YAML key"):
            n01.load_unique_yaml("providers:\\n  - provider_key: baobab-iam.hydra\\n    provider_key: baobab-iam.shadow\\n".replace("\\n", "\n"))

    def test_shared_pin_is_real_go_declaration_not_comment(self):
        comment = '// const SharedCommit = "' + n01.PIN + '"'
        with self.assertRaisesRegex(ValueError, "Go Shared pin declaration"):
            n01.actual_shared_commit(comment)
        with self.assertRaisesRegex(ValueError, "Go Shared pin declaration"):
            n01.actual_shared_commit('const SharedCommit = "' + n01.PIN + '"\n' +
                                     'const SharedCommit = "' + n01.PIN + '"')
        self.assertEqual(n01.actual_shared_commit('const SharedCommit = "' + n01.PIN + '"'),
                         n01.PIN)

    def test_contract_lock_policy_cannot_be_downgraded(self):
        self.lock["policy"]["updates"] = "automatic"
        self.deny("Shared contract review policy relaxed")

    def test_duplicate_contract_entry_denied(self):
        self.lock["contracts"].append(self.lock["contracts"][0])
        self.deny("duplicate or invalid Shared contracts")

    def test_simulated_provider_is_not_accepted(self):
        self.declaration["providers"][0]["simulated"] = True
        self.deny("simulated or non-adapter")

    def test_provider_must_remain_reviewed_adapter(self):
        self.declaration["providers"][0]["provider_type"] = "ENGINE"
        self.deny("simulated or non-adapter")

    def test_provider_provenance_repository_is_pinned(self):
        self.declaration["providers"][1]["provenance"]["authority"]["repository"] = "external/other"
        self.deny("provider provenance drift")

    def test_provider_eligibility_type_cannot_be_string(self):
        self.declaration["providers"][0]["production_permitted"] = "true"
        self.deny("provider eligibility")

    def test_provider_support_must_retain_real_source_evidence(self):
        self.declaration["providers"][0]["support"][0]["implementation_evidence"] = []
        self.deny("provider support evidence")

    def test_provider_evidence_path_must_exist(self):
        self.declaration["providers"][1]["support"][0]["implementation_evidence"][0]["path"] = (
            "internal/provider/ory/nonexistent.go")
        self.deny("provider support evidence")

    def test_provider_evidence_must_include_integration_test(self):
        support = self.declaration["providers"][2]["support"][0]
        support["implementation_evidence"] = support["implementation_evidence"][:1]
        self.deny("provider support evidence")

    def test_duplicate_planned_capability_cannot_be_hidden(self):
        self.declaration["planned_capabilities"].append(
            copy.deepcopy(self.declaration["planned_capabilities"][0]))
        self.deny("duplicated or invalid planned capability")

    def test_planned_capability_cannot_target_unreviewed_provider(self):
        self.declaration["planned_capabilities"][0]["target_provider_key"] = "baobab-iam.shadow"
        self.deny("planned capability targets unreviewed provider")

    def test_invalid_governance_root_is_denied(self):
        with self.assertRaisesRegex(ValueError, "invalid governance document structure"):
            n01.check(record=[], lock=self.lock, declaration=self.declaration)


if __name__ == "__main__":
    unittest.main()
