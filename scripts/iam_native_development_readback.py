#!/usr/bin/env python3
"""Independent IAM-native *development* case reader, before CP consumer enablement.

The original IAM N04 connected gate remains separate, not weakened. This reader
qualifies whether required provider-owned *cases* are present in original private
go test -json logs, without requiring CP ACTIVE support, estates or protected
deployment. Original hash consistency is not independent producer provenance;
never promote an unattested report to development QUALIFIED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

HEX = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
SUITES = {
    "kratos": frozenset({
        "TestLiveFoundation/real-session-revocation",
        "TestLiveNativeHumanCanonicalHandoff",
        "TestLiveN06KratosCurrentSessionAndRevocation",
        "TestLiveKratosPasskeyRegistrationAndA3StepUp",
        "TestLiveKratosRecoveryRebindAndDisable",
    }),
    "hydra": frozenset({
        "TestLiveWorkloadFederated",
        "TestLiveTokenProfileFederatedAudienceBoundary",
        "TestLiveHydraSigningJWKSOverlapAndRetirement",
        "TestLiveHydraIssuerRevocationAndAudienceDenials",
    }),
    "keycloak": frozenset({
        "TestLiveKeycloakEnterpriseBroker",
        "TestLiveKeycloakFederationLogoutAndCompromiseContainment",
    }),
    "security": frozenset({
        "TestLivePrivilegedA4HardwareIndependentWitness",
        "TestLiveCrossProviderIdentityRevocation",
    }),
    "recovery": frozenset({
        "TestLiveIAMWholeRuntimeRestoreRevokedRemainsDenied",
        "TestLiveIAMRecoveryHoldCannotBeReplayedOrDowngraded",
    }),
}


class Held(ValueError):
    """No source credentials or original evidence in public exception text."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise Held(code)


def private_bytes(value: str, limit: int) -> bytes:
    require(isinstance(value, str) and os.path.isabs(value),
            "ABSOLUTE_PRIVATE_ORIGINAL_REQUIRED")
    fd = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and info.st_mode & 0o077 == 0
                and 0 < info.st_size <= limit, "ORIGINAL_OWNER_CUSTODY_INVALID")
        with os.fdopen(fd, "rb", closefd=False) as reader:
            data = reader.read(limit + 1)
        require(len(data) <= limit, "ORIGINAL_TOO_LARGE")
        return data
    finally:
        os.close(fd)


def original_log(path: str, sidecar: str) -> list[dict]:
    raw = private_bytes(path, 8 * 1024 * 1024)
    digest = private_bytes(sidecar, 512).decode("ascii").strip()
    require(SHA256.fullmatch(digest) is not None
            and digest == hashlib.sha256(raw).hexdigest(), "ORIGINAL_DIGEST_DRIFT")
    try:
        records = [json.loads(line, object_pairs_hook=unique)
                   for line in raw.decode("utf-8").splitlines() if line]
    except (UnicodeDecodeError, ValueError, TypeError):
        raise Held("GO_JSONL_PARSE_FAILED") from None
    require(bool(records) and all(isinstance(x, dict) for x in records),
            "GO_JSONL_EVENTS_REQUIRED")
    return records


def unique(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for k, value in pairs:
        require(k not in obj, "DUPLICATE_GO_EVENT_PROPERTY")
        obj[k] = value
    return obj


def check_cases(suite: str, records: list[dict]) -> None:
    require(suite in SUITES and bool(records), "UNKNOWN_OR_EMPTY_PROVIDER_SUITE")
    observed = set()
    for record in records:
        action = record.get("Action")
        test = record.get("Test")
        pkg = record.get("Package")
        require(action in {"start", "run", "pass", "fail", "skip", "output", "pause", "cont"}
                and isinstance(pkg, str)
                and pkg.startswith("github.com/baobab-platform/baobab-iam/"),
                "FOREIGN_OR_UNRECOGNISED_GO_TEST_EVENT")
        if test is not None:
            require(isinstance(test, str) and test.startswith("Test"),
                    "NON_TEST_EVENT_SUBSTITUTION")
        if action in {"fail", "skip"}:
            raise Held("GO_LIVE_TEST_NOT_PASSED")
        if action == "pass" and test is not None:
            observed.add(test)
    require(SUITES[suite] <= observed, "MANDATORY_NATIVE_PROVIDER_CASES_MISSING")


def readback(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iam-source-sha", required=True)
    for suite in SUITES:
        parser.add_argument("--" + suite + "-log", required=True)
        parser.add_argument("--" + suite + "-digest", required=True)
    args = parser.parse_args(argv)
    require(HEX.fullmatch(args.iam_source_sha) is not None,
            "IMMUTABLE_NATIVE_SOURCE_SHA_REQUIRED")
    paths = []
    for suite in SUITES:
        p = getattr(args, suite + "_log")
        digest = getattr(args, suite + "_digest")
        paths.extend([p, digest])
        check_cases(suite, original_log(p, digest))
    require(len(set(paths)) == len(paths), "ORIGINAL_SUITE_CUSTODY_COLLISION")
    # A successful parse never independently authenticates the runtime
    # producer or proves concrete provider semantics. The archive must be
    # checked separately with n04_github_archive_readback and owner witnesses.
    return "IAM_NATIVE_REQUIRED_CASES_RECONCILED_UNATTESTED"


def main() -> int:
    try:
        status = readback()
        print(status)
        print("HELD: immutable GitHub original producer/real-runtime independent "
              "witness and teardown required for development qualification")
        return 3
    except (Held, OSError, ValueError, UnicodeError):
        print("HELD: required authentic native provider original cases missing or invalid")
        return 2


if __name__ == "__main__":
    sys.exit(main())
