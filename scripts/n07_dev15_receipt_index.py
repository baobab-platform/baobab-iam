#!/usr/bin/env python3
"""Index private DEV-15 originals against one Infrastructure lifecycle receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from n07_connected_consumers import (
    Blocked, DIGEST, REQUIRED_ENGINES, RUN, SHA, original_write, pairs_unique,
    private_json, private_read,
)

PAYMENTS_BLOCKERS = {
    "ENG-ONB-03": ("baobab-cp / baobab-payments", "Verify actual legal actor and mandate."),
    "ENG-ONB-06": ("baobab-payments / infrastructure", "Execute native replay refusal in the owner lifecycle."),
    "PAYMENTS-ACTOR-MARKET-CURRENCY": ("baobab-cp / baobab-payments", "Verify the current actor, Market and currency binding."),
    "PAYMENTS-MISSING-MANDATE": ("baobab-cp / baobab-payments", "Observe missing-mandate denial at the native resource."),
    "PAYMENTS-EVENT-REPLAY": ("baobab-payments", "Exercise durable replay protection on the native event path."),
}
ROLES = {"issuer", "cp", "engine"}
SCOPE = "ORIGINAL_CUSTODY_ONLY_UNATTESTED"


def checked_original(ref):
    if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
            or not isinstance(ref["sha256"], str) or not DIGEST.fullmatch(ref["sha256"])):
        raise Blocked("ORIGINAL_REFERENCE_INVALID")
    raw = private_read(ref["path"], 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        raise Blocked("ORIGINAL_DIGEST_MISMATCH")
    return raw


def receipt_index(manifest):
    if (set(manifest) != {"schema", "adopter", "run_id", "source_pins", "lifecycle", "originals"}
            or manifest["schema"] != "baobab.iam.dev15.private-index-input.v1"
            or manifest["adopter"] not in REQUIRED_ENGINES
            or not isinstance(manifest["run_id"], str) or not RUN.fullmatch(manifest["run_id"])):
        raise Blocked("DEV15_INDEX_INPUT_INVALID")
    adopter, run_id, pins = (manifest[k] for k in ("adopter", "run_id", "source_pins"))
    if (not isinstance(pins, dict)
            or set(pins) != {"infrastructure", "shared", "baobab-iam", "baobab-cp", adopter}
            or any(not isinstance(sha, str) or not SHA.fullmatch(sha) for sha in pins.values())):
        raise Blocked("DEV15_EXACT_SOURCE_PINS_REQUIRED")
    lifecycle = json.loads(checked_original(manifest["lifecycle"]), object_pairs_hook=pairs_unique)
    if (not isinstance(lifecycle, dict)
            or lifecycle.get("schema") != "infrastructure.dev01.lifecycle.observed.v1"
            or lifecycle.get("run_id") != run_id
            or lifecycle.get("harness_sha") != pins["infrastructure"]
            or lifecycle.get("teardown_verified") is not True
            or lifecycle.get("protected_acceptance") is not False
            or lifecycle.get("production_authorized") is not False
            or not isinstance(lifecycle.get("source_pins"), dict)
            or any(lifecycle["source_pins"].get(repo) != sha for repo, sha in pins.items()
                   if repo != "infrastructure")):
        raise Blocked("DEV15_LIFECYCLE_SOURCE_OR_TEARDOWN_MISMATCH")
    originals = manifest["originals"]
    if not isinstance(originals, dict) or set(originals) != ROLES:
        raise Blocked("DEV15_OWNER_ORIGINAL_ROLES_REQUIRED")
    indexed = {}
    for role, ref in sorted(originals.items()):
        if ref is None:
            indexed[role] = {"status": "BLOCKED", "sha256": None}
            continue
        checked_original(ref)
        # Hash verification cannot attest signature, authority or effect semantics.
        indexed[role] = {"status": "HASH_VERIFIED_UNATTESTED", "sha256": ref["sha256"]}
    return {
        "schema": "baobab.iam.dev15.receipt-index.v1",
        "classification": SCOPE,
        "adopter": adopter, "run_id": run_id, "source_pins": pins,
        "lifecycle_receipt_sha256": manifest["lifecycle"]["sha256"],
        "teardown_recorded_in_owner_receipt": True,
        "originals": indexed,
        "blocked_cases": {case: {"status": "BLOCKED", "owner": owner, "next_action": action}
                          for case, (owner, action) in PAYMENTS_BLOCKERS.items()}
                         if adopter == "baobab-payments" else {},
        "acceptance": "BLOCKED", "protected_accepted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if os.environ.get("BAOBAB_ENVIRONMENT") != "development":
            raise Blocked("DEV15_DEVELOPMENT_REQUIRED")
        result = receipt_index(private_json(args.manifest))
        original_write(str(args.output_dir), "index", result)
        print("DEV15_RECEIPT_INDEX_WRITTEN_UNATTESTED")
    except (Blocked, OSError, ValueError, TypeError, KeyError):
        print("DEV15_RECEIPT_INDEX_BLOCKED", file=sys.stderr)
        return 2
    return 3


if __name__ == "__main__":
    sys.exit(main())
