#!/usr/bin/env python3
"""N02 evidence reconciliation. Never manufactures connected/protected acceptance.

Checks *original* browser/Infrastructure artifacts, source/run binding, cases,
digest sidecars and protected reviewer signature. A valid packet remains
OBSERVED_UNATTESTED until independent provider, legal, custody and staging
review. No passed source test can unlock a protected environment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SHA = re.compile(r"[a-f0-9]{40}\Z")
RUN = re.compile(r"[a-f0-9]{32}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
CASE_IDS = {
    "N02_BROWSER_ORIGIN_CSRF_DENIAL",
    "N02_REAL_KRATOS_HYDRA_LOGIN",
    "N02_PKCE_STATE_CALLBACK_REPLAY_DENIAL",
    "N02_CP_ACTIVE_PRINCIPAL_SESSION",
    "N02_REAL_AAL2_STEP_UP",
    "N02_REAL_RECOVERY_NO_AUTO_GRANT",
    "N02_ALL_NATIVE_SESSIONS_LOGOUT",
}
DEV04_CASES = {
    "issuer-issuance-and-readback",
    "current-cp-principal-and-link",
    "wrong-audience-denial",
    "wrong-tenant-denial",
    "issuer-revocation-before-expiry",
    "cp-principal-deactivation",
    "complete-teardown",
}
PROTECTED_CHECKS = {
    "approved_runtime_source_and_image_digest",
    "separate_cp_maker_checker_approval",
    "real_kratos_session_and_aal2",
    "real_hydra_registered_client_and_audience",
    "real_cp_active_principal_and_external_link",
    "real_browser_consent_pkce_recovery",
    "cross_tenant_and_wrong_audience_denied",
    "unexpired_token_revocation_denied",
    "global_kratos_logout_and_refresh_revocation",
    "protected_backup_restore_observed",
    "independent_teardown_witnessed",
    "external_custody_readback_verified",
}


class Blocked(Exception):
    pass


def secure_read(path: str, limit: int = 1_048_576) -> bytes:
    file = Path(path)
    if not file.is_absolute():
        raise Blocked("PRIVATE_PATH_REQUIRED")
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > limit):
            raise Blocked("ORIGINAL_PRIVATE_FILE_REQUIRED")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise Blocked("EVIDENCE_SIZE_LIMIT")
        return data


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    target = {}
    for name, value in pairs:
        if name in target:
            raise Blocked("DUPLICATE_EVIDENCE_FIELD")
        target[name] = value
    return target


def document(path: str) -> tuple[dict, bytes]:
    raw = secure_read(path)
    try:
        decoded = json.loads(raw, object_pairs_hook=unique_pairs)
    except (ValueError, TypeError, UnicodeDecodeError) as error:
        raise Blocked("MALFORMED_EVIDENCE") from None
    if not isinstance(decoded, dict):
        raise Blocked("INVALID_EVIDENCE")
    return decoded, raw


def digest_sidecar(data: bytes, sidecar: str) -> None:
    raw = secure_read(sidecar, 1024).decode("ascii").strip()
    # Native BFF emits raw 64 hex; Infrastructure emits {"sha256":hex}.
    try:
        expected = json.loads(raw)["sha256"] if raw.startswith("{") else raw
    except (ValueError, KeyError, TypeError):
        raise Blocked("EVIDENCE_DIGEST_INVALID") from None
    if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
        raise Blocked("EVIDENCE_DIGEST_INVALID")
    if hashlib.sha256(data).hexdigest() != expected:
        raise Blocked("ORIGINAL_EVIDENCE_DIGEST_MISMATCH")


def browser_readback(browser: dict, iam_sha: str) -> str:
    if (browser.get("schema") != "baobab.iam.n02.browser-observation.v1"
            or browser.get("classification") != "REAL_BROWSER_SYNTHETIC_DATA"
            or browser.get("source_sha") != iam_sha
            or browser.get("protected_accepted") is not False
            or browser.get("provider_and_cp_independently_attested") is not False
            or not RUN.fullmatch(browser.get("run_id", ""))):
        raise Blocked("BROWSER_PROVENANCE_INVALID")
    cases = browser.get("cases")
    if not isinstance(cases, dict) or set(cases) != CASE_IDS or any(v != "OBSERVED" for v in cases.values()):
        raise Blocked("MANDATORY_BROWSER_CASE_MISSING")
    for name in ("shared_source_sha", "cp_source_sha", "infrastructure_harness_sha"):
        if not isinstance(browser.get(name), str) or not SHA.fullmatch(browser[name]):
            raise Blocked("BROWSER_PEER_SOURCE_UNPINNED")
    return browser["run_id"]


def joined_source_readback(browser: dict, dev04: dict) -> None:
    """Cross-check original producer source pins without editing either source."""
    pins = dev04.get("source_pins")
    if (not isinstance(pins, dict) or
            browser.get("shared_source_sha") != pins.get("shared") or
            browser.get("cp_source_sha") != pins.get("baobab-cp") or
            browser.get("infrastructure_harness_sha") != dev04.get("harness_sha")):
        raise Blocked("CONNECTED_SOURCE_PROVENANCE_MISMATCH")


def dev04_readback(dev04: dict, iam_sha: str, run_id: str) -> None:
    if (dev04.get("schema") != "infrastructure.dev01.lifecycle.observed.v1"
            or dev04.get("run_id") != run_id
            or dev04.get("source_pins", {}).get("baobab-iam") != iam_sha
            or not SHA.fullmatch(dev04.get("harness_sha", ""))
            or dev04.get("evidence_class") != "REAL_COMPONENT_SYNTHETIC_DATA"
            or dev04.get("lifecycle_passed") is not True
            or dev04.get("teardown_verified") is not True
            or dev04.get("int03c_qualified") is not True
            or dev04.get("protected_acceptance") is not False
            or dev04.get("production_authorized") is not False):
        raise Blocked("REAL_IAM_CP_RUN_NOT_BOUND")
    report = dev04.get("int03c")
    if (not isinstance(report, dict)
            or report.get("schema") != "infrastructure.dev04.int03c-observed.v1"
            or report.get("run_id") != run_id
            or report.get("scope") != "DEV04_INT03C_DEVELOPMENT_ONLY"
            or report.get("protected_acceptance") is not False
            or report.get("canonical_provider_qualified") is not False):
        raise Blocked("REAL_IAM_CP_CASES_NOT_BOUND")
    cases = report.get("cases")
    if not isinstance(cases, dict) or set(cases) != DEV04_CASES:
        raise Blocked("SEVEN_ORIGINAL_CASES_MISSING")
    for case in cases.values():
        if not isinstance(case, dict):
            raise Blocked("INT03C_OBSERVATION_INCOMPLETE")
        evidence = case.get("assertions")
        if (case.get("result") != "PASS" or case.get("reason") != "OBSERVED"
                or not isinstance(evidence, dict) or not evidence
                or any(value is not True for value in evidence.values())):
            raise Blocked("INT03C_OBSERVATION_INCOMPLETE")


def protected_packet(packet: dict, browser_raw: bytes, dev04_raw: bytes,
                     iam_sha: str, run_id: str, packet_path: str,
                     public_key_path: str, signature_path: str) -> None:
    if (packet.get("schema") != "baobab.iam.n02.protected-review-packet.v1"
            or packet.get("environment") != "protected-staging"
            or packet.get("run_id") != run_id
            or packet.get("source_sha") != iam_sha
            or packet.get("browser_sha256") != hashlib.sha256(browser_raw).hexdigest()
            or packet.get("int03c_sha256") != hashlib.sha256(dev04_raw).hexdigest()):
        raise Blocked("PROTECTED_EVIDENCE_PROVENANCE_UNBOUND")
    checks = packet.get("observed_evidence_digests")
    if (not isinstance(checks, dict) or set(checks) != PROTECTED_CHECKS
            or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in checks.values())):
        raise Blocked("PROTECTED_EVIDENCE_INCOMPLETE")
    if (not isinstance(packet.get("maker_id"), str)
            or not isinstance(packet.get("checker_id"), str)
            or not isinstance(packet.get("witness_id"), str)
            or len({packet["maker_id"], packet["checker_id"], packet["witness_id"]}) != 3):
        raise Blocked("INDEPENDENT_REVIEW_ROLES_NOT_DISTINCT")
    # Verification uses an externally trust-anchored reviewer public key.
    # A public key supplied *by the report itself* would prove nothing.
    secure_read(public_key_path, 4096)
    secure_read(signature_path, 2048)
    result = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public_key_path,
         "-sigfile", signature_path, "-in", packet_path],
        capture_output=True, text=False, timeout=15, check=False,
    )
    if result.returncode != 0:
        raise Blocked("INDEPENDENT_REVIEWER_SIGNATURE_NOT_VERIFIED")
    # Signature + digest ensure custody of the packet, not that the protected
    # runtime met laws, approved access or production go-live conditions.


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", required=True)
    parser.add_argument("--browser-digest", required=True)
    parser.add_argument("--int03c", required=True)
    parser.add_argument("--int03c-digest", required=True)
    parser.add_argument("--iam-sha", required=True)
    parser.add_argument("--protected-packet")
    parser.add_argument("--independent-review-key")
    parser.add_argument("--independent-review-signature")
    args = parser.parse_args()
    try:
        if not SHA.fullmatch(args.iam_sha):
            raise Blocked("IMMUTABLE_IAM_SOURCE_REQUIRED")
        browser, raw_browser = document(args.browser)
        dev04, raw_dev04 = document(args.int03c)
        digest_sidecar(raw_browser, args.browser_digest)
        digest_sidecar(raw_dev04, args.int03c_digest)
        run_id = browser_readback(browser, args.iam_sha)
        dev04_readback(dev04, args.iam_sha, run_id)
        joined_source_readback(browser, dev04)
        if any((args.protected_packet, args.independent_review_key, args.independent_review_signature)):
            if not all((args.protected_packet, args.independent_review_key, args.independent_review_signature)):
                raise Blocked("INDEPENDENT_REVIEW_MISSING")
            packet, raw = document(args.protected_packet)
            protected_packet(packet, raw_browser, raw_dev04, args.iam_sha,
                run_id, args.protected_packet,
                args.independent_review_key, args.independent_review_signature)
            print("N02_PROTECTED_PACKET_SIGNATURE_OBSERVED_REVIEW_PENDING")
        else:
            print("N02_DEVELOPMENT_BROWSER_AND_CP_OBSERVED_UNATTESTED")
        return 0
    except (Blocked, OSError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, Blocked) else "EVIDENCE_UNAVAILABLE"
        if not re.fullmatch(r"[A-Z_]+", code):
            code = "EVIDENCE_UNAVAILABLE"
        print("N02_EVIDENCE_BLOCKED " + code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
