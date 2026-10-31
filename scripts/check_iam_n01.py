#!/usr/bin/env python3
"""IAM-N01 source-only governance drift check; never activates a provider."""
import json
from pathlib import Path
import re
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
RECORD_PATH = "docs/governance/iam-n01-convergence.json"
PIN = "1517429bcae601a1b0288ca0279e524ce48a3d77"
OWNERS = {
    "baobab-iam.kratos": ("kratos", "identity.authentication.perform"),
    "baobab-iam.hydra": ("hydra", "identity.workload-token.issue"),
    "baobab-iam.keycloak": ("keycloak", "identity.authentication.perform"),
}
DEVELOPMENT = {
    "environment": "development",
    "allowed_execution": ["local-development", "disposable-ci", "isolated-shared-development"],
    "profiles": ["nabhold", "zuribeans", "thamani", "equator-estate", "external-client"],
    "synthetic_only": True,
    "independent_human_approval_per_run": False,
    "distinct_maker_checker_principals": True,
    "real_provider_tokens_required": True,
    "max_lease_seconds": 86400,
    "no_protected_bootstrap": True,
    "no_protected_acceptance_from_development": True,
    "revocation_and_teardown_required": True,
    "no_authority_from_scope_or_provider_health": True,
}
GOVERNING = {
    "native": "ADR-IAM-0033",
    "native_status": "Accepted",
    "original": "ADR-0001..ADR-0018 Proposed (preserved where applicable)",
    "successors": "ADR-IAM-0019..ADR-IAM-0033 Accepted (amended by 0033)",
    "native_commitment": "ADR-IAM-0034 Proposed",
    "development": "ADR-SHARED-043 Accepted",
}
CONTRACTS = {
    "contracts/identity/v1/workload-registry.yaml",
    "contracts/identity/v1/capabilities.yaml",
    "contracts/authorization/v1/scope-registry.yaml",
    "contracts/control-plane/v1/estate-resource-assignment.schema.json",
}


# A release-boundary guard must reject ambiguous input before checking values.
# PyYAML safe_load and json.loads accept duplicate keys last-writer-wins.
class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ValueError("non-string YAML key in governance document")
            if key in result:
                raise ValueError("duplicate YAML key: " + key)
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_unique_yaml(content):
    return yaml.load(content, Loader=UniqueKeyLoader)


def unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load_unique_json(content):
    return json.loads(content, object_pairs_hook=unique_json_pairs)


def actual_shared_commit(content):
    # Compare the actual Go declaration, not a comment containing the pin.
    found = re.findall(
        r'(?m)^const[ \t]+SharedCommit[ \t]*=[ \t]*"([0-9a-f]{40})"[ \t]*$',
        content,
    )
    require(len(found) == 1, "Go Shared pin declaration missing or ambiguous")
    return found[0]


def evidence_paths_valid(root, items):
    if not isinstance(items, list) or not items:
        return False
    seen = set()
    types = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"type", "path"}:
            return False
        kind, path = item["type"], item["path"]
        if kind not in ("source", "integration-test") or not isinstance(path, str):
            return False
        if path in seen or not path.startswith("internal/provider/") or not path.endswith(".go"):
            return False
        seen.add(path)
        types.add(kind)
        if not (root / path).is_file():
            return False
    return types == {"source", "integration-test"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def adr(root, number, prefix):
    matches = list((root / "docs/adr").glob(f"{prefix}{number:04d} *.md"))
    require(len(matches) == 1, "ADR source missing or ambiguous")
    return matches[0].read_text()


def check(root=ROOT, record=None, lock=None, declaration=None):
    if record is None:
        record = load_unique_json((root / RECORD_PATH).read_text())
    if lock is None:
        lock = load_unique_yaml((root / "contracts.lock.yaml").read_text())
    if declaration is None:
        declaration = load_unique_yaml((root / ".baobab/capability-provider.yaml").read_text())

    require(all(isinstance(item, dict) for item in (record, lock, declaration)),
            "invalid governance document structure")
    require(record.get("schema") == "baobab.iam.n01.convergence.v1", "N01 schema mismatch")
    require(record.get("governing") == GOVERNING, "ADR precedence mismatch")
    require(record.get("development") == DEVELOPMENT, "development/protected boundary mismatch")

    for n in range(1, 19):
        require(re.search(r"\*\*Status:\*\*\s*Proposed\b", "\n".join(adr(root, n, "ADR-").splitlines()[:12])),
                "original ADR status was silently promoted")
    for n in range(19, 34):
        require(re.search(r"\*\*Status:\*\*\s*Accepted\b", "\n".join(adr(root, n, "ADR-IAM-").splitlines()[:12])),
                "accepted successor ADR status drift")
    proposed = adr(root, 34, "ADR-IAM-")
    require(re.search(r"\*\*Status:\*\*\s*Proposed\b", "\n".join(proposed.splitlines()[:12])),
            "ADR-IAM-0034 cannot be silently accepted")
    index = (root / "docs/adr/README.md").read_text()
    for identifier in ("ADR-IAM-0033:", "ADR-IAM-0034:", "ADR-SHARED-043"):
        require(identifier in index, "ADR index omission: " + identifier)
    for document in ("docs/operations/c4-03-live-qualification.md",
                     "docs/operations/c4-04-governed-runtime-readiness.md"):
        require("ADR-SHARED-043" in (root / document).read_text(),
                "development approval boundary not reconciled in " + document)

    shared = record.get("shared", {})
    require(shared == {
        "repository": "baobab-platform/shared",
        "pin": PIN,
        "reviewed_head": "c97387ed8e27eeffb0c0382e043db98cb450b900",
        "decision": "HOLD_REPIN_PENDING_CONSUMER_QUALIFICATION",
    }, "Shared re-pin was not independently reviewed")
    require(lock.get("source") == {"repository": "baobab-platform/shared", "commit": PIN},
            "Shared lock differs from reviewed pin")
    entries = lock.get("contracts")
    require(isinstance(entries, list) and all(isinstance(x, str) for x in entries)
            and len(entries) == len(set(entries)), "duplicate or invalid Shared contracts")
    require(CONTRACTS.issubset(set(entries)), "required Shared contract missing")
    require(lock.get("policy") == {"updates": "explicit_pull_request",
                                   "compatibility": "validate_before_merge"},
            "Shared contract review policy relaxed")
    require(actual_shared_commit((root / "internal/federation/consume.go").read_text()) == PIN,
            "Go Shared pin changed")
    require(PIN in proposed, "proposed native commitment Shared reference changed")

    expected = record.get("providers", {})
    require(isinstance(expected, dict) and set(expected) == set(OWNERS),
            "unreviewed provider identity")
    providers = declaration.get("providers", [])
    require(declaration.get("engine", {}).get("engine_id") == "baobab-iam"
            and isinstance(providers, list) and len(providers) == 3, "provider declaration mismatch")
    seen = set()
    for row in providers:
        key = row.get("provider_key")
        require(key in OWNERS and key not in seen, "unknown or repeated provider")
        seen.add(key)
        impl, capability = OWNERS[key]
        require(row.get("implementation_key") == impl, "provider allocation drift")
        require(row.get("provider_type") == "ADAPTER" and row.get("simulated") is False,
                "provider changed to simulated or non-adapter support")
        require(type(row.get("production_permitted")) is bool,
                "provider eligibility is not a boolean")
        authority = row.get("provenance", {}).get("authority", {})
        require(authority == {"repository": "baobab-platform/baobab-iam",
                              "decision": "ADR-IAM-0033"},
                "provider provenance drift")
        supports = row.get("support", [])
        require(isinstance(supports, list) and len(supports) == 1, "provider support census drift")
        support = supports[0]
        require(support.get("capability_key") == capability and support.get("contract_versions") == [1],
                "canonical capability/major mismatch")
        require(support.get("implementation_status") == "PARTIAL",
                "N01 cannot promote support without N02/N03/N04 qualification")
        require(evidence_paths_valid(root, support.get("implementation_evidence")),
                "provider support evidence is missing or invalid")
        require(expected[key] == {"key": impl, "capability": capability, "status": "PARTIAL"},
                "manifest support drift")
    planned = declaration.get("planned_capabilities", [])
    require(isinstance(planned, list), "planned capability census invalid")
    planned_keys = set()
    for row in planned:
        require(isinstance(row, dict), "planned capability census invalid")
        require(row.get("proposal_status") in ("PROPOSED", "CANDIDATE"),
                "planned capability improperly promoted")
        key = row.get("proposed_key")
        target = row.get("target_provider_key")
        require(isinstance(key, str) and key.startswith("identity.")
                and key not in planned_keys, "duplicated or invalid planned capability")
        planned_keys.add(key)
        require(target in OWNERS or (key == "identity.migration.map"
                                    and target == "baobab-iam.ory"),
                "planned capability targets unreviewed provider")
    return True


def main():
    try:
        check()
    except (ValueError, KeyError, TypeError, OSError, yaml.YAMLError, json.JSONDecodeError) as exc:
        print("IAM-N01 denied: " + str(exc), file=sys.stderr)
        return 1
    print("IAM-N01 source convergence valid; Shared re-pin and provider activation held")
    return 0


if __name__ == "__main__":
    sys.exit(main())
