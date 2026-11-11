#!/usr/bin/env python3
"""Fail CI when the offline Hydra planning ceiling drifts from approved Shared.

The Go binary embeds a deliberately small, reviewable snapshot instead of
trusting operator-provided scope/audience strings. This check ties that snapshot
to the exact Shared checkout pinned in contracts.lock.yaml.
"""
import argparse
import json
import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "cmd/provision-workload/approved_profiles.json"
LOCK = ROOT / "contracts.lock.yaml"


def check(shared_checkout: pathlib.Path) -> None:
    lock = yaml.safe_load(LOCK.read_text(encoding="utf-8"))
    pinned = lock["source"]["commit"]
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if data["source_commit"] != pinned:
        raise ValueError("provisioning snapshot is not for the locked Shared commit")
    resolved = subprocess.run(
        ["git", "-C", str(shared_checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if resolved != pinned:
        raise ValueError("Shared checkout does not match the locked commit")
    shared_root = shared_checkout / "contracts"
    registry = yaml.safe_load(
        (shared_root / "identity/v1/workload-registry.yaml").read_text(encoding="utf-8")
    )["workloads"]
    scopes = yaml.safe_load(
        (shared_root / "authorization/v1/scope-registry.yaml").read_text(encoding="utf-8")
    )["scopes"]
    audience_by_scope = {s["name"]: s.get("audience", []) for s in scopes}
    if not data["workloads"]:
        raise ValueError("no reviewed workloads in planning snapshot")
    referenced_scopes = set()
    for client_id, pinned_profile in data["workloads"].items():
        current = registry.get(client_id)
        if current is None:
            raise ValueError(f"missing Shared workload: {client_id}")
        for field in ("environment", "status", "credential_type", "allowed_scopes", "allowed_audiences"):
            if pinned_profile[field] != current[field]:
                raise ValueError(f"Shared workload {client_id} changed {field}; review the provisioning gate")
        if (pinned_profile["credential_type"] != "client_credentials"
                or pinned_profile["status"] != "ACTIVE"
                or pinned_profile["environment"] != "production"):
            raise ValueError(f"unqualified client-credentials workload: {client_id}")
        referenced_scopes.update(pinned_profile["allowed_scopes"])
    if set(data["scope_audiences"]) != referenced_scopes:
        raise ValueError("scope audience mapping does not exactly cover selected Shared scopes")
    for scope, audience in data["scope_audiences"].items():
        if audience != audience_by_scope.get(scope) or len(audience) != 1:
            raise ValueError(f"scope audience mapping drift or ambiguous scope: {scope}")
    if "trade:native-commitment:submit" in referenced_scopes:
        raise ValueError("ADR-IAM-0034 unallocated commitment scope must not appear in a plan")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared-checkout", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        check(args.shared_checkout.resolve())
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, yaml.YAMLError) as err:
        print(f"workload provisioning ceiling refused: {err}", file=sys.stderr)
        return 1
    print("Hydra planning ceiling exactly matches locked Shared workload and scope registries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
