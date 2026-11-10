#!/usr/bin/env python3
"""ADR-IAM-0027: fail-closed, offline DR promotion evidence preflight.

This is a necessary evidence gate, NOT a fencing actuator or authorization to promote.
Infrastructure and Security must independently verify every attestation.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = (
    "incident_declared",
    "old_writer_fenced",
    "writer_lease_invalidated",
    "replication_position_verified",
    "security_journal_replayed",
    "provider_revocations_reconciled",
    "cp_revocations_reconciled",
    "issuer_and_keys_verified",
    "security_smoke_denials_verified",
)
ROLES = {"incident_declared": "security", "old_writer_fenced": "infrastructure",
         "writer_lease_invalidated": "infrastructure",
         "replication_position_verified": "database",
         "security_journal_replayed": "security",
         "provider_revocations_reconciled": "security",
         "cp_revocations_reconciled": "control-plane",
         "issuer_and_keys_verified": "security",
         "security_smoke_denials_verified": "security"}


def verify(record):
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    for name in ("domain_id", "old_region", "candidate_region", "issuer",
                 "backup_checkpoint", "recovery_checkpoint"):
        if not isinstance(record.get(name), str) or not record[name].strip():
            raise ValueError(f"missing {name}")
    if record["old_region"] == record["candidate_region"]:
        raise ValueError("candidate must be a different region")
    if not record["issuer"].startswith("https://"):
        raise ValueError("issuer must use https")
    if record["backup_checkpoint"] == record["recovery_checkpoint"]:
        raise ValueError("recovery checkpoint must differ from backup checkpoint")
    if record.get("old_writer_reachable") is not False:
        raise ValueError("old writer must be independently fenced and unreachable")
    if record.get("candidate_writer_enabled") is not False:
        raise ValueError("candidate must remain read-only during preflight")
    attestations = record.get("attestations")
    if not isinstance(attestations, dict) or set(attestations) != set(REQUIRED):
        raise ValueError("missing or unexpected promotion attestations")
    actors = {}
    for name in REQUIRED:
        att = attestations[name]
        if not isinstance(att, dict) or att.get("verified") is not True:
            raise ValueError(f"{name} not verified")
        if att.get("role") != ROLES[name]:
            raise ValueError(f"{name} has wrong witness role")
        actor = att.get("actor")
        receipt = att.get("evidence_ref")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError(f"{name} missing witness")
        if not isinstance(receipt, str) or not receipt.strip():
            raise ValueError(f"{name} missing independent evidence reference")
        actors[name] = actor
    if actors["old_writer_fenced"] == actors["security_journal_replayed"]:
        raise ValueError("fencing and journal replay require independent witnesses")
    if actors["old_writer_fenced"] == actors["incident_declared"]:
        raise ValueError("fencing and incident declaration require independent witnesses")
    if record.get("unresolved_revocations") != 0:
        raise ValueError("unresolved revocations: deny promotion")
    if record.get("unresolved_replication_gap") is not False:
        raise ValueError("replication gap not reconciled")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    args = parser.parse_args()
    try:
        verify(json.loads(args.record.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"DR PREFLIGHT HELD: {exc}", file=sys.stderr)
        return 1
    print("DR PREFLIGHT EVIDENCE COMPLETE (NOT PROMOTION AUTHORIZATION)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
