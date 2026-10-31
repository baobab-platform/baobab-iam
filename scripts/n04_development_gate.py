#!/usr/bin/env python3
"""IAM-N04: fail-closed readback of ORIGINAL development qualification receipts.

This is a *candidate-evidence integrity gate*, never a provider registry,
CP activation, witness signature, runtime origin authenticator or approval.
Run genuine owner integration producers separately and keep their original
private bytes. Missing proof is BLOCKED, not a skipped PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

import n02_evidence_gate as n02

SHA = re.compile(r"[a-f0-9]{40}\Z")
RUN = re.compile(r"[a-f0-9]{32}\Z")
C403 = frozenset({
    "real_hydra_workload_issuance", "signed_scoped_audience_token",
    "current_cp_runtime_after_issuance", "kratos_synthetic_session_verified",
    "governed_login_consent", "signed_nonce_bound_oidc", "code_replay_denied",
    "synthetic_session_revoked", "protected_cp_resource_accepted",
    "foreign_owned_context_accepted", "foreign_tenant_context_denied",
    "tampered_subject_token_denied",
    "real_cp_withdrawal_denied_unexpired_token", "evidence_closed",
})
N03_PULSE = frozenset({
    "N03_HYDRA_CURRENT_ISSUER_ISSUANCE",
    "N03_NATIVE_PULSE_OWN_CONTEXT",
    "N03_NATIVE_PULSE_NEIGHBOUR_OWN_CONTEXT",
    "N03_NATIVE_PULSE_CROSS_CONTEXT_DENIAL",
    "N03_NATIVE_PULSE_MISSING_BEARER_DENIAL",
    "N03_HYDRA_REVOCATION_READBACK",
    "N03_NATIVE_PULSE_REVOKED_BEARER_DENIAL",
})
ENG = frozenset(f"ENG-ONB-0{i}" for i in range(1, 10))
PROFILES = {"baobab-pulse": "pulse-intelligence", "baobab-payments": "payments-sandbox"}


class Held(ValueError):
    """Never contain credentials, bearer material or raw original evidence."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Held(reason)


def original(path: str, digest: str, *, c403: bool = False) -> dict:
    """Read exactly once via N02's owner-private, no-follow original file reader."""
    doc, raw = n02.document(path)
    data = n02.secure_read(digest, 512).decode("ascii")
    expected = hashlib.sha256(raw).hexdigest()
    if c403:
        require(data == f"{expected}  receipt.json\n", "C403_DIGEST_MISMATCH")
    else:
        n02.digest_sidecar(raw, digest)
    return doc


def c403_readback(doc: dict, iam_sha: str) -> None:
    """Exact existing C4-03 B-E full receipt vocabulary, not C4-03A alone."""
    require(set(doc) == {
        "schema", "source_commit", "result", "checks",
        "registered_live_services_contacted", "cp_withdrawal_observed",
        "physical_passkey_qualified", "production_ready",
    }, "C403_SHAPE_DRIFT")
    require(
        doc["schema"] == "baobab-c4-03-registered-integration/v1"
        and doc["source_commit"] == iam_sha
        and doc["result"] == "PASS"
        and doc["registered_live_services_contacted"] is True
        and doc["cp_withdrawal_observed"] is True
        and doc["physical_passkey_qualified"] is False
        and doc["production_ready"] is False
        and isinstance(doc["checks"], dict)
        and set(doc["checks"]) == C403
        and all(value is True for value in doc["checks"].values()),
        "C403_ORIGINAL_RUNTIME_CASES_UNQUALIFIED",
    )


def engine_readback(receipt: dict, expected_engine: str,
                    iam_sha: str, shared_sha: str, cp_sha: str, infrastructure_sha: str) -> None:
    """Read the original Infrastructure completed/receipt.json, not a new claim."""
    require(receipt.get("schema") == "infrastructure.dev01.lifecycle.observed.v1"
            and RUN.fullmatch(receipt.get("run_id", "")) is not None
            and receipt.get("evidence_class") == "REAL_COMPONENT_SYNTHETIC_DATA"
            and receipt.get("lifecycle_passed") is True
            and receipt.get("teardown_verified") is True
            and receipt.get("protected_acceptance") is False
            and receipt.get("production_authorized") is False,
            "ENGINE_OWNER_LIFECYCLE_NOT_COMPLETED")
    pins = receipt.get("source_pins")
    require(isinstance(pins, dict)
            and pins.get("baobab-iam") == iam_sha
            and pins.get("shared") == shared_sha
            and pins.get("baobab-cp") == cp_sha
            and receipt.get("harness_sha") == infrastructure_sha,
            "ENGINE_IMMUTABLE_SOURCE_DRIFT")
    report = receipt.get("engine_integration")
    require(isinstance(report, dict)
            and report.get("schema") == "infrastructure.engine-integration.observed.v1"
            and report.get("run_id") == receipt["run_id"]
            and report.get("subject_engine") == expected_engine
            and report.get("profile_key") == PROFILES[expected_engine]
            and report.get("synthetic_only") is True
            and report.get("protected_acceptance") is False
            and report.get("production_authorized") is False,
            "ENGINE_OWNER_PROFILE_MISMATCH")
    cases = report.get("cases")
    require(isinstance(cases, dict) and ENG.issubset(cases)
            and all(isinstance(row, dict) and set(row) == {"result", "reason"}
                    and row["result"] == "PASS" and row["reason"] == "OBSERVED"
                    for row in cases.values()),
            "ENGINE_MANDATORY_CASES_NOT_PASSED")
    observations = report.get("independent_observations")
    require(isinstance(observations, dict)
            and observations.get("issuer_cleanup") is True
            and observations.get("host_cleanup") is True
            and observations.get("principal_denial") is True
            and observations.get("authority_denials") == 4
            and {"cp", "hydra"}.issubset(observations.get("faults_observed", []))
            and type(observations.get("native_audits_joined")) is int
            and observations["native_audits_joined"] > 0,
            "ENGINE_INDEPENDENT_AUTHORITY_OR_TEARDOWN_UNPROVEN")
    capabilities = report.get("capabilities")
    counts = observations.get("native_cp_resolutions")
    require(isinstance(capabilities, dict) and bool(capabilities)
            and isinstance(counts, dict) and set(capabilities) == set(counts)
            and all(isinstance(v, dict) and
                    v.get("source") == "DECLARED_IMPLEMENTED" and
                    v.get("development") == "OBSERVED" and
                    v.get("certification") == "NOT_QUALIFIED" and
                    v.get("protected_authorized") is False and
                    type(counts[k]) is int and counts[k] > 0
                    for k, v in capabilities.items()),
            "ENGINE_NATIVE_CAPABILITY_NOT_OBSERVED")


def n03_pulse_readback(original: dict, *, pulse_sha: str, iam_sha: str,
                       shared_sha: str, cp_sha: str, owner_run_id: str) -> None:
    """Require original native JWT revocation/CP denial observation.

    This only reconciles private bytes. A source-only fixture, same-run ID,
    untrusted self-attestation or engine unit test cannot certify two
    independent CP tenants, live issuer revocation or provider readiness.
    """
    require(set(original) == {
        "schema", "classification", "environment", "run_id",
        "pulse_source_sha", "iam_source_sha", "cp_source_sha",
        "shared_source_sha", "cases", "two_tenants_independently_attested",
        "protected_accepted",
    }, "N03_NATIVE_ORIGINAL_SCHEMA_DRIFT")
    require(
        original["schema"] == "baobab.pulse.n03.native-observation.v1"
        and original["classification"] == "REAL_NATIVE_HYDRA_PULSE_CP_UNATTESTED"
        and original["environment"] == "development"
        and original["protected_accepted"] is False
        and original["two_tenants_independently_attested"] is False
        and original["run_id"] == owner_run_id
        and original["pulse_source_sha"] == pulse_sha
        and original["iam_source_sha"] == iam_sha
        and original["shared_source_sha"] == shared_sha
        and original["cp_source_sha"] == cp_sha
        and isinstance(original["cases"], dict)
        and set(original["cases"]) == N03_PULSE
        and all(value == "OBSERVED" for value in original["cases"].values()),
        "N03_REAL_NATIVE_REVOCATION_AND_CP_DENIAL_NOT_OBSERVED",
    )


def readback(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iam-sha", required=True)
    parser.add_argument("--shared-sha", required=True)
    parser.add_argument("--cp-sha", required=True)
    parser.add_argument("--pulse-source-sha", required=True)
    parser.add_argument("--infrastructure-sha", required=True)
    for kind in ("browser", "int03c", "c403", "pulse", "pulse-native", "payments"):
        parser.add_argument(f"--{kind}", required=True)
        parser.add_argument(f"--{kind}-digest", required=True)
    args = parser.parse_args(argv)
    require(all(SHA.fullmatch(x) for x in
                (args.iam_sha, args.shared_sha, args.cp_sha, args.infrastructure_sha, args.pulse_source_sha)),
            "IMMUTABLE_REVIEWED_SOURCE_PINS_REQUIRED")
    browser = original(args.browser, args.browser_digest)
    int03c = original(args.int03c, args.int03c_digest)
    c403 = original(args.c403, args.c403_digest, c403=True)
    pulse = original(args.pulse, args.pulse_digest)
    pulse_native = original(args.pulse_native, args.pulse_native_digest)
    payments = original(args.payments, args.payments_digest)
    try:
        run_id = n02.browser_readback(browser, args.iam_sha)
        n02.dev04_readback(int03c, args.iam_sha, run_id)
    except (n02.Blocked, ValueError, KeyError, TypeError) as err:
        raise Held("N02_DEV04_CONNECTED_ORIGINAL_EVIDENCE_MISSING") from None
    pins = int03c.get("source_pins", {})
    require(isinstance(pins, dict) and pins.get("shared") == args.shared_sha
            and pins.get("baobab-cp") == args.cp_sha,
            "N02_DEV04_DEPENDENCY_SOURCE_DRIFT")
    require(int03c.get("harness_sha") == args.infrastructure_sha,
            "N02_DEV04_INFRASTRUCTURE_SOURCE_DRIFT")
    c403_readback(c403, args.iam_sha)
    engine_readback(pulse, "baobab-pulse", args.iam_sha, args.shared_sha, args.cp_sha,
                    args.infrastructure_sha)
    engine_readback(payments, "baobab-payments", args.iam_sha, args.shared_sha, args.cp_sha,
                    args.infrastructure_sha)
    n03_pulse_readback(pulse_native,
        pulse_sha=args.pulse_source_sha,
        iam_sha=args.iam_sha, shared_sha=args.shared_sha, cp_sha=args.cp_sha,
        owner_run_id=pulse["run_id"])
    require(len({run_id, pulse["run_id"], payments["run_id"]}) == 3,
            "ENGINE_DISPOSABLE_RUN_COLLISION")
    # C4-04A's existing read-only current CP/health command emits no
    # immutable receipt; N03's current opt-in test only proves a CP/router
    # *fixture*, not a deployed engine. Do not allow an internally consistent
    # packet to bypass the actual remaining owner checks or self-promote.
    return "N04_ORIGINAL_EVIDENCE_RECONCILED_UNATTESTED"


def main() -> int:
    try:
        status = readback()
        print(status)
        print("HELD N04: actual C4-04B/C current CP support, independently "
              "read-back binding, real native runtime consumer and "
              "reviewed developer acceptance remain separate")
        return 3
    except (Held, n02.Blocked, OSError, ValueError, KeyError, TypeError,
            UnicodeDecodeError, json.JSONDecodeError):
        print("HELD N04: original source-pinned development qualification "
              "missing, invalid, or untrusted")
        return 2


if __name__ == "__main__":
    sys.exit(main())
