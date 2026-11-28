#!/usr/bin/env python3
"""Validate and render the CTS v2 implementation evidence register."""
import argparse
from datetime import date
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SPEC = "docs/adr/Consolidated-Technical-Specification-v2.0.md"
REGISTER = ROOT / "docs/governance/iam-cts-v2-implementation-register.json"
VIEW = REGISTER.with_suffix(".md")
FIELDS = {"id", "section", "authorities", "owners", "source_revision", "source_status",
          "evidence_class", "required_cases", "observations", "blocker", "ea_dev",
          "review", "rollback"}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate field: {key}")
        result[key] = value
    return result


def requirements():
    section = None
    result = []
    for line in (ROOT / SPEC).read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^## (S\d{2}) — ", line)
        if heading:
            section = heading[1]
        row = re.match(r"^\*\*(CTS2-\d{3})\.\*\* ", line)
        if row:
            result.append((row[1], section))
    return result


def validate(register):
    if (set(register) != {"schema", "specification", "observed_on", "scope", "requirements"}
            or register["schema"] != "baobab.iam.cts-v2.implementation-evidence.v1"
            or register["specification"] != SPEC
            or register["scope"] != "READ_MODEL_NO_ACCEPTANCE_AUTHORITY"):
        raise ValueError("invalid implementation evidence register header")
    date.fromisoformat(register["observed_on"])
    rows = register["requirements"]
    expected = requirements()
    if [entry[0] for entry in expected] != [f"CTS2-{n:03}" for n in range(1, 45)]:
        raise ValueError("normative source inventory changed")
    if [(r["id"], r["section"]) for r in rows] != expected:
        raise ValueError("register must cover the ordered CTS requirement and section pairs")
    for r in rows:
        if set(r) != FIELDS:
            raise ValueError(f"unexpected record fields for {r['id']}")
        for key in ("id", "section", "blocker", "review", "rollback"):
            value = r[key]
            if not isinstance(value, str) or not value.strip() or "|" in value or "\n" in value:
                raise ValueError(f"invalid {r['id']} {key}")
        for key in ("authorities", "owners", "ea_dev", "required_cases"):
            value = r[key]
            if (not isinstance(value, list) or (key != "required_cases" and not value)
                    or any(not isinstance(item, str) or not re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9.-]*", item) for item in value)
                    or len(value) != len(set(value))):
                raise ValueError(f"invalid {r['id']} {key}")
        if not re.fullmatch(r"[0-9a-f]{40}", r["source_revision"]):
            raise ValueError(f"invalid source revision for {r['id']}")
        if r["source_status"] not in {"REVIEW_PENDING", "SOURCE_REVIEWED", "CANDIDATE_SOURCE_REVIEWED"}:
            raise ValueError(f"invalid source status for {r['id']}")
        if r["evidence_class"] not in {"NOT_ASSESSED", "SOURCE", "SCOPED_DEVELOPMENT_CI"}:
            raise ValueError(f"invalid or promoted evidence for {r['id']}")
        if bool(r["observations"]) != (r["evidence_class"] != "NOT_ASSESSED"):
            raise ValueError(f"missing or inconsistent observations for {r['id']}")
        for o in r["observations"]:
            if (set(o) != {"result", "scope", "reference"}
                    or o["result"] not in {"PASS", "FAIL", "BLOCKED"}
                    or not isinstance(o["scope"], str) or not o["scope"].strip()
                    or "|" in o["scope"] or "\n" in o["scope"]
                    or not re.fullmatch(r"https://github\.com/baobab-platform/[A-Za-z0-9.-]+/(pull|actions/runs)/[0-9]+(?:/job/[0-9]+)?", o["reference"])):
                raise ValueError(f"invalid observation for {r['id']}")


def render(register):
    lines = [
        "# IAM CTS v2 implementation evidence register",
        "",
        f"Observation date **{register['observed_on']}**.",
        "",
        "Each row tracks one normative requirement. The source revision identifies the",
        "review baseline or the named candidate. A scoped PASS applies to the linked",
        "observation. Shared retains programme acceptance and each owner retains the",
        "original evidence. An empty case list means case mapping is still due.",
        "",
        "| Requirement | Accountable owners | Source | Evidence | Open obligation |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in register["requirements"]:
        observations = " · ".join(
            f"[{o['result']}]({o['reference']}) {o['scope']}" for o in r["observations"]
        )
        evidence = r["evidence_class"] + (f" · {observations}" if observations else "")
        lines.append(
            f"| {r['id']} ({r['section']}) | {', '.join(r['owners'])} | "
            f"{r['source_status']} `{r['source_revision'][:12]}` | {evidence} | {r['blocker']} |"
        )
    lines.extend(["", "Authority, case mapping, EA-DEV traceability and rollback are recorded in",
                 "[the canonical JSON](iam-cts-v2-implementation-register.json)."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-view", action="store_true")
    args = parser.parse_args()
    try:
        data = json.loads(REGISTER.read_text(encoding="utf-8"), object_pairs_hook=unique)
        validate(data)
        view = render(data)
        if args.write_view:
            VIEW.write_text(view, encoding="utf-8")
        elif VIEW.read_text(encoding="utf-8") != view:
            raise ValueError("generated Markdown drift; run with --write-view")
    except (ValueError, TypeError, KeyError, OSError) as error:
        raise SystemExit(f"CTS evidence register invalid: {error}") from None
    print("CTS evidence register PASS: 44 requirement records; no acceptance decision")


if __name__ == "__main__":
    main()
