#!/usr/bin/env python3
"""ADR-IAM-0027: fail-closed, offline DR promotion evidence preflight.

This is a necessary evidence gate, NOT a fencing actuator or authorization to promote.
Infrastructure and Security must independently verify every attestation.
"""
import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

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


def exact_text(value):
    return isinstance(value, str) and bool(value) and value.strip() == value and value.isprintable()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate evidence member")
        result[key] = value
    return result


def verify(record):
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    for name in ("domain_id", "old_region", "candidate_region", "issuer",
                 "backup_checkpoint", "recovery_checkpoint"):
        if not exact_text(record.get(name)):
            raise ValueError(f"missing {name}")
    if record["old_region"] == record["candidate_region"]:
        raise ValueError("candidate must be a different region")
    raw_issuer = record["issuer"]
    issuer = urlsplit(raw_issuer)
    if (issuer.scheme != "https" or not issuer.hostname or issuer.username is not None
            or issuer.password is not None or issuer.netloc.endswith(":")
            or any(c in raw_issuer for c in "?#\\")
            or any(c.isspace() for c in raw_issuer)):
        raise ValueError("issuer must be an exact HTTPS issuer identifier")
    _ = issuer.port  # Invalid or out-of-range ports raise ValueError.
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
        if not exact_text(actor):
            raise ValueError(f"{name} missing witness")
        if not exact_text(receipt):
            raise ValueError(f"{name} missing independent evidence reference")
        actors[name] = actor
    if actors["old_writer_fenced"] == actors["security_journal_replayed"]:
        raise ValueError("fencing and journal replay require independent witnesses")
    if actors["old_writer_fenced"] == actors["incident_declared"]:
        raise ValueError("fencing and incident declaration require independent witnesses")
    if type(record.get("unresolved_revocations")) is not int or record["unresolved_revocations"] != 0:
        raise ValueError("unresolved revocations: deny promotion")
    if record.get("unresolved_replication_gap") is not False:
        raise ValueError("replication gap not reconciled")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    args = parser.parse_args()
    try:
        verify(json.loads(args.record.read_text(encoding="utf-8"), object_pairs_hook=unique_object))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"DR PREFLIGHT HELD: {exc}", file=sys.stderr)
        return 1
    print("DR PREFLIGHT EVIDENCE COMPLETE (NOT PROMOTION AUTHORIZATION)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
