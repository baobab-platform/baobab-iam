#!/usr/bin/env python3
"""IAM-N07 real-service development HTTP probes.

These are *consumer* transport observations, not authentication certification,
N02 browser acceptance, N03 issuer/CP/native acceptance, or CP approval.
Unexecuted/missing/uncertain probes are BLOCKED. Never use these observations
to activate provider support, grant a Principal, or certify an engine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPHandler, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener,
)

SCHEMA = "baobab.iam.n07.consumer-http.v1"
ESTATES = {"nabhold": "/api/auth/session",
           "zuribeans": "/api/iam/session",
           "thamani": "/api/auth/session"}
REQUIRED_ENGINES = {"baobab-pulse", "baobab-payments"}
OPTIONAL_ENGINES = {"baobab-trade", "baobab-erp", "baobab-cms"}
CASES = ("anonymous", "allowed", "wrong_audience", "foreign_tenant",
         "missing_grant", "revoked_unexpired")
SHA = re.compile(r"[0-9a-f]{40}\Z")
RUN = re.compile(r"[0-9a-f]{32}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class Blocked(Exception):
    """Only stable, low-cardinality error codes leave this runner."""


def pairs_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise Blocked("DUPLICATE_PROFILE_FIELD")
        obj[k] = v
    return obj


def private_read(path: str, limit: int = 65536) -> bytes:
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise Blocked("PRIVATE_ABSOLUTE_PATH_REQUIRED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or
                st.st_nlink != 1 or st.st_mode & 0o077 or st.st_size > limit):
            raise Blocked("OWNER_ONLY_ORIGINAL_REQUIRED")
        b = f.read(limit + 1)
    if len(b) > limit:
        raise Blocked("FILE_TOO_LARGE")
    return b


def private_json(path: str) -> dict[str, Any]:
    try:
        doc = json.loads(private_read(path), object_pairs_hook=pairs_unique)
    except (ValueError, UnicodeError):
        raise Blocked("INVALID_PRIVATE_JSON") from None
    if not isinstance(doc, dict):
        raise Blocked("INVALID_PRIVATE_OBJECT")
    return doc


def trusted_origin(value: str) -> str:
    if not isinstance(value, str):
        raise Blocked("ORIGIN_REQUIRED")
    try:
        u = urlsplit(value)
        host = u.hostname
        port = u.port
    except ValueError:
        raise Blocked("ORIGIN_INVALID") from None
    if (not host or u.username or u.password or u.query or u.fragment or
            u.path not in ("", "/") or (port is not None and port < 1)):
        raise Blocked("ORIGIN_INVALID")
    if u.scheme != "https" and not (u.scheme == "http" and host == "127.0.0.1"):
        raise Blocked("TLS_REQUIRED")
    if any(c.isspace() for c in value):
        raise Blocked("ORIGIN_INVALID")
    return value.rstrip("/")


def resource_path(value: str) -> str:
    if (not isinstance(value, str) or not value.startswith("/") or
            value.startswith("//") or "//" in value or ".." in value or
            any(c in value for c in ("?", "#", "\\", "\r", "\n")) or
            len(value) > 180):
        raise Blocked("READ_ONLY_RESOURCE_PATH_INVALID")
    return value


def validate_profile(p: dict[str, Any]) -> dict[str, Any]:
    if p.get("schema") != SCHEMA or p.get("environment") != "development":
        raise Blocked("N07_DEVELOPMENT_PROFILE_REQUIRED")
    if not RUN.fullmatch(p.get("run_id", "")):
        raise Blocked("ORIGINAL_RUN_ID_REQUIRED")
    pins = p.get("source_pins")
    required_pins = {"baobab-iam", "baobab-cp", "shared", *ESTATES, *REQUIRED_ENGINES}
    if not isinstance(pins, dict) or not required_pins.issubset(pins) or any(
            not isinstance(x, str) or not SHA.fullmatch(x) for x in pins.values()):
        raise Blocked("EXACT_IMMUTABLE_PEER_PINS_REQUIRED")
    targets = p.get("consumers")
    if not isinstance(targets, list) or len(targets) < 5:
        raise Blocked("ALL_CORE_CONSUMERS_REQUIRED")
    names = set()
    for c in targets:
        if not isinstance(c, dict) or c.get("name") in names:
            raise Blocked("DUPLICATE_OR_INVALID_CONSUMER")
        name = c.get("name")
        if name not in ESTATES and name not in REQUIRED_ENGINES | OPTIONAL_ENGINES:
            raise Blocked("UNREGISTERED_CONSUMER")
        names.add(name)
        if name not in pins:
            raise Blocked("CONSUMER_SOURCE_UNPINNED")
        trusted_origin(c.get("origin"))
        if name in ESTATES:
            if c.get("kind") != "estate" or c.get("anonymous_path") != ESTATES[name]:
                raise Blocked("ESTATE_SESSION_ROUTE_NOT_OWNED")
            if any(key.endswith("_token_file") for key in c):
                raise Blocked("ESTATE_BROWSER_CREDENTIAL_NOT_TRANSFERABLE")
        else:
            if c.get("kind") != "engine":
                raise Blocked("ENGINE_TYPE_REQUIRED")
            resource_path(c.get("resource_path"))
            paths = [c.get(f"{case}_token_file") for case in CASES[1:]]
            if any(not isinstance(x, str) or not Path(x).is_absolute() for x in paths):
                raise Blocked("ORIGINAL_PROVIDER_TOKEN_FILES_REQUIRED")
    if not (set(ESTATES) | REQUIRED_ENGINES).issubset(names):
        raise Blocked("REQUIRED_CONSUMER_MISSING")
    return p


def exact_source(p: dict[str, Any]) -> None:
    """The checked-out executable, not a user-provided SHA, is authoritative."""
    root = Path(__file__).resolve().parents[1]
    try:
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True, timeout=8)
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                               capture_output=True, text=True, check=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        raise Blocked("SOURCE_READBACK_UNAVAILABLE") from None
    if head.stdout.strip() != p["source_pins"]["baobab-iam"] or dirty.stdout.strip():
        raise Blocked("EXECUTABLE_SOURCE_DRIFT")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_probe(origin: str, path: str, bearer: str | None) -> tuple[int, bool]:
    """Return only status and no-store; do not store response body or headers."""
    request = Request(trusted_origin(origin) + resource_path(path),
                      headers={"Accept": "application/json",
                               "Cache-Control": "no-store",
                               "User-Agent": "baobab-n07-dev-qualification/1"})
    if bearer is not None:
        request.add_header("Authorization", "Bearer " + bearer)
    transport = build_opener(ProxyHandler({}), HTTPHandler(),
                             HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    try:
        response = transport.open(request, timeout=5)
    except HTTPError as error:
        response = error
    except (URLError, TimeoutError, OSError, ValueError):
        raise Blocked("REAL_CONSUMER_UNAVAILABLE") from None
    with response:
        return response.status, "no-store" in response.headers.get("Cache-Control", "").lower()


def token(path: str) -> str:
    try:
        value = private_read(path, 16384).decode("ascii").strip()
    except (UnicodeError, OSError):
        raise Blocked("PRIVATE_PROVIDER_TOKEN_UNAVAILABLE") from None
    if not (32 <= len(value) <= 16384) or any(ch.isspace() for ch in value):
        raise Blocked("INVALID_ORIGINAL_PROVIDER_TOKEN")
    return value


def case_id(name: str, case: str) -> str:
    return "N07_" + name.upper().replace("-", "_") + "_" + case.upper()


def observe(p: dict[str, Any], phase: str,
            probe=http_probe) -> dict[str, Any]:
    """HTTP observations only. External N02/N03/CP owner evidence is mandatory."""
    results: dict[str, str] = {}
    for c in p["consumers"]:
        name, base = c["name"], c["origin"]
        if phase == "before":
            path = c.get("anonymous_path") if name in ESTATES else c["resource_path"]
            try:
                status, _ = probe(base, path, None)
                results[case_id(name, "anonymous")] = (
                    "OBSERVED" if status in (401, 403) else "BLOCKED")
            except Blocked:
                results[case_id(name, "anonymous")] = "BLOCKED"
            if name in ESTATES:
                # A real first-party Playwright user journey, not a cookie or
                # bearer passed into this CLI, must qualify each estate.
                results[case_id(name, "browser_and_cp")] = "BLOCKED"
                continue
            observed_tokens = set()
            for case in ("allowed", "wrong_audience", "foreign_tenant", "missing_grant"):
                try:
                    original = token(c[f"{case}_token_file"])
                    digest = hashlib.sha256(original.encode("ascii")).digest()
                    if digest in observed_tokens:
                        raise Blocked("REUSED_INDEPENDENT_NEGATIVE_TOKEN")
                    observed_tokens.add(digest)
                    status, no_store = probe(base, c["resource_path"], original)
                    good = status == 200 and no_store if case == "allowed" else status in (401, 403)
                    results[case_id(name, case)] = "OBSERVED" if good else "BLOCKED"
                except (Blocked, OSError):
                    results[case_id(name, case)] = "BLOCKED"
        else:
            if name in ESTATES:
                # No assertion of SLO/revocation from an unauthenticated page.
                continue
            # The owner revokes the *same still-unexpired original token*
            # separately; independent Hydra and CP readbacks are not replaced.
            try:
                earlier = token(c["allowed_token_file"])
                revoked = token(c["revoked_unexpired_token_file"])
                if earlier != revoked:
                    raise Blocked("REVOKED_TOKEN_MUST_MATCH_PREVIOUS")
                status, _ = probe(base, c["resource_path"], revoked)
                results[case_id(name, "revoked_unexpired")] = (
                    "OBSERVED" if status in (401, 403) else "BLOCKED")
            except (Blocked, OSError):
                results[case_id(name, "revoked_unexpired")] = "BLOCKED"
    return {"schema": "baobab.iam.n07.http-observation.v1",
            "evidence_class": "REAL_HTTP_READBACK_UNATTESTED",
            "environment": "development", "phase": phase,
            "run_id": p["run_id"], "source_pins": p["source_pins"],
            "cases": results, "protected_accepted": False,
            "cp_authority_certified": False, "issuer_qualified": False,
            "consumer_native_consequence_qualified": False,
            "fully_qualified": False}


def original_write(directory: str, phase: str, receipt: dict[str, Any]) -> None:
    """Exclusive, private, checksum-bound originals; never rewrite history."""
    root = Path(directory)
    if not root.is_absolute() or root.is_symlink():
        raise Blocked("PRIVATE_OUTPUT_REQUIRED")
    root.mkdir(mode=0o700, exist_ok=True)
    st = root.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Blocked("PRIVATE_OUTPUT_PERMISSIONS_REQUIRED")
    payload = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    for suffix, data in ((".json", payload),
                         (".sha256", (hashlib.sha256(payload).hexdigest() + "\n").encode("ascii"))):
        target = root / (phase + suffix)
        if target.exists() or target.is_symlink():
            raise Blocked("ORIGINAL_EVIDENCE_ALREADY_EXISTS")
        tmp = root / (phase + suffix + ".part")
        if tmp.exists() or tmp.is_symlink():
            raise Blocked("TEMPORARY_EVIDENCE_ALREADY_EXISTS")
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(tmp, target, follow_symlinks=False)
        finally:
            tmp.unlink(missing_ok=True)
    dir_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="IAM-N07 real-service readback (not acceptance)")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--phase", required=True, choices=("before", "after"))
    args = parser.parse_args()
    try:
        if os.environ.get("BAOBAB_ENVIRONMENT") != "development":
            raise Blocked("PROTECTED_EXECUTION_NOT_AUTHORIZED")
        profile = validate_profile(private_json(args.profile))
        exact_source(profile)
        result = observe(profile, args.phase)
        original_write(args.output_dir, args.phase, result)
        print(json.dumps({"classification": "N07_SOURCE_AND_HTTP_OBSERVED_UNATTESTED"
                          if all(v == "OBSERVED" for v in result["cases"].values())
                          else "N07_CONSUMER_BLOCKED",
                          "phase": args.phase,
                          "observed": sum(v == "OBSERVED" for v in result["cases"].values()),
                          "required": len(result["cases"]),
                          "accepted": False}, sort_keys=True))
        # Even a complete readback is not independent N02/N03/CP/provider
        # qualification; never return zero as if acceptance were passed.
        return 3 if all(v == "OBSERVED" for v in result["cases"].values()) else 2
    except (Blocked, OSError, KeyError, TypeError):
        print('{"classification":"N07_CONSUMER_BLOCKED","accepted":false}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
