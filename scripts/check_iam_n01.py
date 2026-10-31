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


def require(condition, message):
    if not condition:
        raise ValueError(message)


def adr(root, number, prefix):
    matches = list((root / "docs/adr").glob(f"{prefix}{number:04d} *.md"))
    require(len(matches) == 1, "ADR source missing or ambiguous")
    return matches[0].read_text()


def check(root=ROOT, record=None, lock=None, declaration=None):
    if record is None:
        record = json.loads((root / RECORD_PATH).read_text())
    if lock is None:
        lock = yaml.safe_load((root / "contracts.lock.yaml").read_text())
    if declaration is None:
        declaration = yaml.safe_load((root / ".baobab/capability-provider.yaml").read_text())

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
    require(CONTRACTS.issubset(set(lock.get("contracts", []))), "required Shared contract missing")
    require(('const SharedCommit = "' + PIN + '"') in
            (root / "internal/federation/consume.go").read_text(), "Go Shared pin changed")
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
        require(row.get("provenance", {}).get("authority", {}).get("decision") == "ADR-IAM-0033",
                "provider has wrong governing ADR")
        supports = row.get("support", [])
        require(isinstance(supports, list) and len(supports) == 1, "provider support census drift")
        support = supports[0]
        require(support.get("capability_key") == capability and support.get("contract_versions") == [1],
                "canonical capability/major mismatch")
        require(support.get("implementation_status") == "PARTIAL",
                "N01 cannot promote support without N02/N03/N04 qualification")
        require(expected[key] == {"key": impl, "capability": capability, "status": "PARTIAL"},
                "manifest support drift")
    for row in declaration.get("planned_capabilities", []):
        require(row.get("proposal_status") in ("PROPOSED", "CANDIDATE"),
                "planned capability improperly promoted")
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
