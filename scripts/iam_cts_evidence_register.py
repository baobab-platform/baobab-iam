#!/usr/bin/env python3
"""Validate and render the CTS v2 implementation evidence register."""
import argparse
from datetime import date, datetime
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SPEC = "docs/adr/Consolidated-Technical-Specification-v2.0.md"
REGISTER = ROOT / "docs/governance/iam-cts-v2-implementation-register.json"
VIEW = REGISTER.with_suffix(".md")
FIELDS = {"id", "section", "authorities", "owners", "source_revision", "source_status",
          "evidence_class", "required_cases", "observations", "blocker", "ea_dev",
          "review", "rollback", "case_mapping", "case_outcomes"}
PIN_TYPES = {"consumer_pins": r"[0-9a-f]{40}",
             "contract_pins": r"(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})",
             "image_pins": r"sha256:[0-9a-f]{64}"}
CASE_MAP = {"CTS2-015": {"INT-07"}, "CTS2-017": {"INT-03C"},
            "CTS2-023": {"ENG-ONB-03", "ENG-ONB-06"}, "CTS2-035": {"L4-OPS-01"},
            "CTS2-040": {"INT-03C", "NAB-03"}}
REPO = "https://github.com/baobab-platform/baobab-iam/"


def check_observation(o, record, observed_on):
    wanted = {"result", "scope", "reference", "observed_at", "source_sha", "source_ref",
              "workflow", "owner_original", "teardown_original", *PIN_TYPES}
    if (set(o) != wanted or o["result"] not in {"PASS", "FAIL", "BLOCKED"}
            or not isinstance(o["scope"], str) or not o["scope"].strip()
            or "|" in o["scope"] or "\n" in o["scope"]
            or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", o["observed_at"])
            or datetime.fromisoformat(o["observed_at"]).date() > observed_on
            or o["source_sha"] != record["source_revision"]
            or o["source_ref"] != REPO + "commit/" + o["source_sha"]):
        raise ValueError(f"invalid or mismatched observation for {record['id']}")
    for key, pattern in PIN_TYPES.items():
        pins = o[key]
        if pins is not None and (not isinstance(pins, dict) or not pins or
                any(not name.strip() or not re.fullmatch(pattern, value) for name, value in pins.items())):
            raise ValueError(f"invalid {key} for {record['id']}")
    for key in ("owner_original", "teardown_original"):
        proof = o[key]
        if proof is not None and (
                set(proof) != {"reference", "sha256", "verified_by"}
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", proof["sha256"])
                or not proof["reference"].strip() or not proof["verified_by"].strip()):
            raise ValueError(f"invalid {key} for {record['id']}")
    workflow = o["workflow"]
    if workflow is None:
        if record["evidence_class"] != "SOURCE" or not re.fullmatch(
                re.escape(REPO) + r"pull/[0-9]+", o["reference"]):
            raise ValueError("scoped CI evidence requires exact workflow and check coordinates")
        return
    if (set(workflow) != {"run_id", "job_id", "head_sha", "name", "check", "conclusion"}
            or workflow["head_sha"] != o["source_sha"]
            or any(type(workflow[k]) is not int or workflow[k] <= 0 for k in ("run_id", "job_id"))
            or not workflow["name"].strip() or not workflow["check"].strip()
            or workflow["conclusion"] not in {"success", "failure", "cancelled", "skipped"}
            or (o["result"] == "PASS") != (workflow["conclusion"] == "success")
            or o["reference"] != REPO + f"actions/runs/{workflow['run_id']}/job/{workflow['job_id']}"):
        raise ValueError(f"invalid workflow head, check or URL for {record['id']}")


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
    observed_on = date.fromisoformat(register["observed_on"])
    rows = register["requirements"]
    expected = requirements()
    if [entry[0] for entry in expected] != [f"CTS2-{n:03}" for n in range(1, 45)]:
        raise ValueError("normative source inventory changed")
    if [(r["id"], r["section"]) for r in rows] != expected:
        raise ValueError("register must cover the ordered CTS requirement and section pairs")
    for r in rows:
        if set(r) != FIELDS:
            raise ValueError(f"unexpected record fields for {r['id']}")
        for key in ("id", "section", "blocker", "rollback"):
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
        cases = CASE_MAP.get(r["id"], set())
        if (set(r["required_cases"]) != cases
                or r["case_mapping"] != ("PARTIAL" if cases else "PENDING")
                or set(r["case_outcomes"]) != cases
                or any(v not in {"NOT_OBSERVED", "BLOCKED"} for v in r["case_outcomes"].values())):
            raise ValueError(f"invalid pending case mapping for {r['id']}")
        if r["review"] != {"reviewer": None, "decision": "PENDING", "reference": None}:
            raise ValueError(f"unverified requirement review for {r['id']}")
        if r["source_status"] not in {"REVIEW_PENDING", "SOURCE_REVIEWED", "CANDIDATE_SOURCE_REVIEWED"}:
            raise ValueError(f"invalid source status for {r['id']}")
        if r["evidence_class"] not in {"NOT_ASSESSED", "SOURCE", "SCOPED_DEVELOPMENT_CI"}:
            raise ValueError(f"invalid or promoted evidence for {r['id']}")
        if bool(r["observations"]) != (r["evidence_class"] != "NOT_ASSESSED"):
            raise ValueError(f"missing or inconsistent observations for {r['id']}")
        for o in r["observations"]:
            check_observation(o, r, observed_on)


def render(register):
    lines = [
        "# IAM CTS v2 implementation evidence register",
        "",
        f"Observation date **{register['observed_on']}**.",
        "",
        "This is a summary of the [full evidence records](iam-cts-v2-implementation-register.json).",
        "Each row tracks one normative requirement. The source revision identifies the",
        "review baseline or the named candidate. A scoped PASS applies to the linked",
        "observation. Shared retains programme acceptance and each owner retains the",
        "original evidence. A PENDING case mapping is incomplete. The validator checks",
        "internal consistency. It does not fetch GitHub or verify owner originals.",
        "",
        "| Requirement | Accountable owners | Source | Evidence | Open obligation | Authority, cases and review |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in register["requirements"]:
        observations = " · ".join(
            f"[{o['result']}]({o['reference']}) {o['scope']}" for o in r["observations"]
        )
        evidence = r["evidence_class"] + (f" · {observations}" if observations else "")
        lines.append(
            f"| {r['id']} ({r['section']}) | {', '.join(r['owners'])} | "
            f"{r['source_status']} `{r['source_revision'][:12]}` | {evidence} | {r['blocker']} | "
            f"{', '.join(r['authorities'])} · {', '.join(r['ea_dev'])} · "
            f"{r['case_mapping']} {', '.join(r['required_cases'])} · review {r['review']['decision']} |"
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
