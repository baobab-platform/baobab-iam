#!/usr/bin/env python3
"""Refuse incomplete CTS v1 -> v2 coverage or inadvertent IAM authority promotion.

Documentation consistency ONLY. This validator never checks real issuer,
provider, tenant or engine qualification and cannot upgrade EA-DEV status.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY = ROOT / "docs/adr/Consolidated-Technical-Specification.md"
TARGET = ROOT / "docs/adr/Consolidated-Technical-Specification-v2.0.md"
CROSSWALK = ROOT / "docs/governance/iam-cts-v2-reconciliation.json"

DISPOSITIONS = {
    "PRESERVED", "AMENDED", "SUPERSEDED", "ILLUSTRATIVE_ONLY",
    "REPLACED_SEQUENCE",
}
OWNERS = {
    "baobab-iam", "baobab-cp", "shared", "baobab-trade",
    "baobab-erp", "baobab-dev", "infrastructure", "digital-estates",
    "thamani", "zuribeans",
}
DEV_IDS = {f"DEV-{i:02d}" for i in range(16)}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate(legacy: str, target: str, data: dict) -> None:
    original = [
        (int(number), heading.strip())
        for number, heading in re.findall(r"^# (\d+)\. (.+)$", legacy, re.M)
    ]
    require(len(original) == 227 and
            [number for number, _ in original] == list(range(1, 228)),
            "original v1 numbered sections must remain exactly 1..227")

    headings = re.findall(r"^## (S\d{2}) — (.+)$", target, re.M)
    identifiers = [identifier for identifier, _ in headings]
    require(len(headings) == 21 and
            identifiers == [f"S{i:02d}" for i in range(1, 22)],
            "v2 must have the complete ordered S01..S21 normative sections")

    requirements = [int(n) for n in re.findall(r"\*\*CTS2-(\d{3})\.", target)]
    require(requirements == list(range(1, 45)),
            "v2 normative requirements must remain exactly CTS2-001..044")

    require(data.get("schema") == "baobab.iam.cts-v2-reconciliation" and
            data.get("document_version") == "2.0" and
            data.get("status") == "DRAFT_RECONCILIATION_NO_AUTHORITY_PROMOTION",
            "v2 crosswalk is not a standalone decision or accepted runtime result")
    require(data.get("source", {}).get("numbered_sections") == 227 and
            data.get("source", {}).get("original_gates") == 17,
            "do not rewrite the original numbered sections or gate count")
    require(data.get("target_document") == "docs/adr/Consolidated-Technical-Specification-v2.0.md",
            "invalid v2 target path")

    guards = data.get("guardrails", {})
    require(guards.get("native_commitment_adr_status") == "PROPOSED" and
            guards.get("native_commitment_scope_allocation") == "NONE" and
            guards.get("provider_support") == "PARTIAL_NOT_PROMOTED" and
            guards.get("protected_release") == "NOT_GRANTED",
            "unapproved scope, provider or protected-environment authority promotion")
    require("ADR-IAM-0034 remains Proposed" in target and
            "scope is **allocated to no workload**" in target and
            "Kratos" in target and "Hydra" in target and "Keycloak" in target,
            "v2 is missing explicit multi-provider and unallocated-scope holds")

    spans = data.get("sections")
    require(isinstance(spans, list) and spans,
            "v1 section crosswalk must not be empty")
    expected = 1
    for index, item in enumerate(spans):
        start, end = item.get("from"), item.get("to")
        require(isinstance(start, int) and isinstance(end, int) and
                start == expected and start <= end <= 227,
                f"legacy section gap, overlap or reordering at span {index}")
        expected = end + 1
        require(item.get("first_heading") == original[start - 1][1] and
                item.get("last_heading") == original[end - 1][1],
                f"legacy title drift at sections {start}..{end}")
        require(item.get("disposition") in DISPOSITIONS,
                f"unknown disposition at sections {start}..{end}")
        require(item.get("target") in identifiers,
                f"unresolved v2 target at sections {start}..{end}")
        require(isinstance(item.get("interpretation"), str) and
                len(item["interpretation"].strip()) >= 30,
                f"empty architectural explanation at sections {start}..{end}")
        require(bool(item.get("authority")) and
                all(isinstance(x, str) and x.strip() for x in item["authority"]),
                f"missing governing decision at sections {start}..{end}")
        require(bool(item.get("owners")) and
                set(item["owners"]).issubset(OWNERS),
                f"unrecognised owning repository/boundary at sections {start}..{end}")
        require(bool(item.get("ea_dev")) and
                set(item["ea_dev"]).issubset(DEV_IDS),
                f"invalid EA-DEV work package at sections {start}..{end}")
    require(expected == 228, "not all 227 original sections are reconciled")

    gates = data.get("gates")
    require(isinstance(gates, list) and len(gates) == 17,
            "exactly 17 original IAM-0..16 gates are required")
    for i, gate in enumerate(gates):
        number = i + 203
        require(gate.get("gate") == f"IAM-{i}" and
                gate.get("legacy_section") == number and
                gate.get("legacy_heading") == original[number - 1][1],
                f"IAM-{i} changed original gate meaning/reference")
        require(gate.get("target") in identifiers and
                gate.get("disposition") in {"REPLACED_SEQUENCE", "SUPERSEDED"},
                f"IAM-{i} must map to current v2 interpretation without claiming completion")
        require(bool(gate.get("ea_dev")) and set(gate["ea_dev"]).issubset(DEV_IDS),
                f"IAM-{i} lacks governed delivery mapping")
        require(bool(gate.get("owners")) and set(gate["owners"]).issubset(OWNERS),
                f"IAM-{i} lacks owner")
        require(isinstance(gate.get("acceptance"), str) and len(gate["acceptance"]) >= 30,
                f"IAM-{i} lacks qualification obligation")
    require(gates[7]["disposition"] == "SUPERSEDED" and
            spans[13]["from"] == 65 and spans[13]["to"] == 68 and
            spans[13]["disposition"] == "SUPERSEDED",
            "legacy Thamani B2C gate and sections must remain superseded")


def main() -> int:
    try:
        validate(
            LEGACY.read_text(encoding="utf-8"),
            TARGET.read_text(encoding="utf-8"),
            json.loads(CROSSWALK.read_text(encoding="utf-8")),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"IAM CTS v2 crosswalk FAILED: {error}", file=sys.stderr)
        return 1
    print("IAM CTS v2 crosswalk PASS: 227 legacy sections, 17 IAM gates, "
          "21 new chapters and 44 normative requirement IDs; "
          "no scope/provider/protected activation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
