#!/usr/bin/env python3
"""Validate and render the CTS v2 implementation evidence register."""
import argparse
from datetime import date, datetime
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SPEC = "docs/adr/Consolidated-Technical-Specification-v2.0.md"
REGISTER = ROOT / "docs/governance/iam-cts-v2-implementation-register.json"
VIEW = REGISTER.with_suffix(".md")
FIELDS = {"id", "section", "authorities", "owners", "source_revision", "source_status",
          "evidence_class", "required_cases", "observations", "blocker", "ea_dev",
          "review", "rollback", "case_mapping", "case_outcomes", "candidate"}
PIN_TYPES = {"consumer_pins": r"[0-9a-f]{40}",
             "contract_pins": r"(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})",
             "image_pins": r"sha256:[0-9a-f]{64}"}
REPO = "https://github.com/baobab-platform/baobab-iam/"
SHA = r"[0-9a-f]{40}"


def canonical_cases(shared_root):
    lock = (ROOT / "contracts.lock.yaml").read_text(encoding="utf-8")
    pins = re.findall(r"^  commit: (" + SHA + r")$", lock, re.M)
    if len(pins) != 1:
        raise ValueError("exact Shared contract pin required")
    head = subprocess.check_output(
        ["git", "-C", str(shared_root), "rev-parse", "HEAD"], text=True, timeout=10).strip()
    if head != pins[0]:
        raise ValueError("Shared acceptance registry source drift")

    def original(name):
        return subprocess.check_output(
            ["git", "-C", str(shared_root), "show", f"{head}:docs/architecture/{name}"],
            text=True, encoding="utf-8", timeout=10)

    register = json.loads(original("ea-dev-implementation-register.json"), object_pairs_hook=unique)
    cases = {}
    for package in register["packages"]:
        runtime = package["runtime"]
        package_cases = set(runtime["canonical_scenarios"])
        for case in runtime["cases"]:
            name = case["case"]
            package_cases.add(name)
            if ":" in name:
                package_cases.add(name.split(":", 1)[1])
        cases[package["id"]] = package_cases
    dev04 = original("ea-dev-04-seven-case-qualification.md")
    if not re.search(r"^# DEV-04\b", dev04) or "original seven INT-03C cases" not in dev04:
        raise ValueError("INT-03C qualification source unavailable")
    cases["DEV-04"].add("INT-03C")
    return cases


def check_review(review, candidate, observed_on):
    if not isinstance(review, list):
        raise ValueError("review history must be a list")
    prior_date = None
    prior_decision = None
    references = set()
    for entry in review:
        if (set(entry) != {"reviewer", "decision", "reference", "observed_at", "head_sha", "scope"}
                or entry["decision"] not in {"CHANGES_REQUESTED", "APPROVED"}
                or entry["scope"] != "SOURCE_RECORD"
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", entry["reviewer"])
                or not re.fullmatch(SHA, entry["head_sha"])
                or not re.fullmatch(re.escape(REPO) + r"pull/[0-9]+#pullrequestreview-[0-9]+", entry["reference"])
                or entry["reference"] in references):
            raise ValueError("invalid independent source review")
        reviewed_at = datetime.fromisoformat(entry["observed_at"])
        if (not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["observed_at"])
                or reviewed_at.date() > observed_on or (prior_date and reviewed_at <= prior_date)):
            raise ValueError("review history must be chronological and timestamped")
        prior_date = reviewed_at
        prior_decision = entry
        references.add(entry["reference"])
    if prior_decision and candidate and prior_decision["head_sha"] == candidate["head_sha"]:
        if prior_decision["reference"].split("#", 1)[0] != candidate["reference"]:
            raise ValueError("current review must refer to the candidate PR")
        return prior_decision["decision"]
    return "PENDING"


def check_observation(o, record, observed_on):
    wanted = {"result", "scope", "reference", "observed_at", "source_sha", "source_ref",
              "workflow", "owner_original", "teardown_original", "standing", *PIN_TYPES}
    if (set(o) != wanted or o["result"] not in {"PASS", "FAIL", "BLOCKED"}
            or not isinstance(o["scope"], str) or not o["scope"].strip()
            or "|" in o["scope"] or "\n" in o["scope"]
            or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", o["observed_at"])
            or datetime.fromisoformat(o["observed_at"]).date() > observed_on
            or not re.fullmatch(SHA, o["source_sha"])
            or o["source_ref"] != REPO + "commit/" + o["source_sha"]):
        raise ValueError(f"invalid or mismatched observation for {record['id']}")
    candidate = record["candidate"]
    if o["standing"] not in {"HISTORICAL", "CURRENT_CANDIDATE", "SOURCE_BASELINE"}:
        raise ValueError("observation standing required")
    if o["standing"] == "CURRENT_CANDIDATE" and (
            candidate is None or o["source_sha"] != candidate["head_sha"]):
        raise ValueError("current observation must match the candidate head")
    if o["standing"] == "SOURCE_BASELINE" and (
            candidate is not None or o["source_sha"] != record["source_revision"]):
        raise ValueError("baseline observation must match its recorded revision")
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


def validate(register, case_registry):
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
                        r"[A-Za-z0-9][A-Za-z0-9.:-]*", item) for item in value)
                    or len(value) != len(set(value))):
                raise ValueError(f"invalid {r['id']} {key}")
        if not re.fullmatch(r"[0-9a-f]{40}", r["source_revision"]):
            raise ValueError(f"invalid source revision for {r['id']}")
        if any(package not in case_registry for package in r["ea_dev"]):
            raise ValueError(f"unknown EA-DEV package for {r['id']}")
        applicable = set().union(*(case_registry[p] for p in r["ea_dev"]))
        cases = set(r["required_cases"])
        if (not cases.issubset(applicable)
                or r["case_mapping"] != ("PARTIAL" if cases else "PENDING")
                or set(r["case_outcomes"]) != cases
                or any(v not in {"NOT_OBSERVED", "BLOCKED"} for v in r["case_outcomes"].values())):
            raise ValueError(f"invalid pending case mapping for {r['id']}")
        candidate = r["candidate"]
        if candidate is not None and (
                set(candidate) != {"reference", "head_sha"}
                or not re.fullmatch(SHA, candidate["head_sha"])
                or not re.fullmatch(re.escape(REPO) + r"pull/[0-9]+", candidate["reference"])):
            raise ValueError(f"invalid candidate for {r['id']}")
        check_review(r["review"], candidate, observed_on)
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
        "internal consistency against the pinned Shared register. It does not fetch GitHub",
        "or verify owner originals. Review decisions here are source-record dispositions.",
        "",
        "| Requirement | Accountable owners | Source | Evidence | Open obligation | Authority, cases and review |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in register["requirements"]:
        observations = " · ".join(
            f"[{o['result']}]({o['reference']}) {o['standing']} {o['scope']}" for o in r["observations"]
        )
        evidence = r["evidence_class"] + (f" · {observations}" if observations else "")
        candidate = r["candidate"]
        current = f" · [candidate {candidate['head_sha'][:12]}]({candidate['reference']})" if candidate else ""
        review = check_review(r["review"], candidate, date.fromisoformat(register["observed_on"]))
        lines.append(
            f"| {r['id']} ({r['section']}) | {', '.join(r['owners'])} | "
            f"{r['source_status']} `{r['source_revision'][:12]}`{current} | {evidence} | {r['blocker']} | "
            f"{', '.join(r['authorities'])} · {', '.join(r['ea_dev'])} · "
            f"{r['case_mapping']} {', '.join(r['required_cases'])} · review {review} |"
        )
    lines.extend(["", "Authority, case mapping, EA-DEV traceability and rollback are recorded in",
                 "[the canonical JSON](iam-cts-v2-implementation-register.json)."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-view", action="store_true")
    parser.add_argument("--shared-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(REGISTER.read_text(encoding="utf-8"), object_pairs_hook=unique)
        validate(data, canonical_cases(args.shared_root))
        view = render(data)
        if args.write_view:
            VIEW.write_text(view, encoding="utf-8")
        elif VIEW.read_text(encoding="utf-8") != view:
            raise ValueError("generated Markdown drift; run with --write-view")
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"CTS evidence register invalid: {error}") from None
    print("CTS evidence register PASS: 44 requirement records; no acceptance decision")


if __name__ == "__main__":
    main()
