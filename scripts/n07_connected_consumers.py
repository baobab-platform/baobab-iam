#!/usr/bin/env python3
"""IAM-N07 real-service development HTTP probes.

These are *consumer* transport observations, not authentication certification,
N02 browser acceptance, N03 issuer/CP/native acceptance, or CP approval.
Unexecuted/missing/uncertain probes are BLOCKED. Never use these observations
to activate provider support, grant a Principal, or certify an engine.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import time
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
            any(c in value for c in ("?", "#", "%", "\\", "\r", "\n")) or
            any(ord(c) < 0x21 or ord(c) > 0x7e for c in value) or
            len(value) > 180):
        raise Blocked("READ_ONLY_RESOURCE_PATH_INVALID")
    return value


def validate_profile(p: dict[str, Any], *, dev15_adopter: str | None = None) -> dict[str, Any]:
    # The original no-secret profile is a closed owner contract. Unknown
    # keys may not smuggle browser credentials, switch run policy or assert
    # support/acceptance outside the independently governed owners.
    if not isinstance(p, dict) or set(p) != {
            "schema", "environment", "run_id", "source_pins", "consumers"}:
        raise Blocked("UNREVIEWED_PROFILE_FIELDS")
    if p.get("schema") != SCHEMA or p.get("environment") != "development":
        raise Blocked("N07_DEVELOPMENT_PROFILE_REQUIRED")
    if not isinstance(p.get("run_id"), str) or not RUN.fullmatch(p["run_id"]):
        raise Blocked("ORIGINAL_RUN_ID_REQUIRED")
    pins = p.get("source_pins")
    required = set(ESTATES) | REQUIRED_ENGINES
    required_pins = {"baobab-iam", "baobab-cp", "shared"}
    if dev15_adopter is not None:
        if dev15_adopter not in REQUIRED_ENGINES:
            raise Blocked("DEV15_ADOPTER_NOT_REGISTERED")
        required = {dev15_adopter}
        required_pins.add("infrastructure")
    required_pins.update(required)
    if not isinstance(pins, dict) or not required_pins.issubset(pins) or any(
            not isinstance(x, str) or not SHA.fullmatch(x) for x in pins.values()):
        raise Blocked("EXACT_IMMUTABLE_PEER_PINS_REQUIRED")
    targets = p.get("consumers")
    if not isinstance(targets, list) or len(targets) < len(required):
        raise Blocked("ALL_CORE_CONSUMERS_REQUIRED")
    names = set()
    for c in targets:
        if (not isinstance(c, dict) or not isinstance(c.get("name"), str) or
                c["name"] in names):
            raise Blocked("DUPLICATE_OR_INVALID_CONSUMER")
        name = c.get("name")
        if name not in ESTATES and name not in REQUIRED_ENGINES | OPTIONAL_ENGINES:
            raise Blocked("UNREGISTERED_CONSUMER")
        if dev15_adopter is not None and name != dev15_adopter:
            raise Blocked("DEV15_SINGLE_ADOPTER_REQUIRED")
        names.add(name)
        if name not in pins:
            raise Blocked("CONSUMER_SOURCE_UNPINNED")
        trusted_origin(c.get("origin"))
        if name in ESTATES:
            if set(c) != {"name", "origin", "kind", "anonymous_path"}:
                raise Blocked("ESTATE_BROWSER_CREDENTIAL_NOT_TRANSFERABLE")
            if c.get("kind") != "estate" or c.get("anonymous_path") != ESTATES[name]:
                raise Blocked("ESTATE_SESSION_ROUTE_NOT_OWNED")
            if any(key.endswith("_token_file") for key in c):
                raise Blocked("ESTATE_BROWSER_CREDENTIAL_NOT_TRANSFERABLE")
        else:
            expected = {"name", "origin", "kind", "resource_path", "response_contract"} | {
                f"{case}_token_file" for case in CASES[1:]}
            if set(c) != expected:
                raise Blocked("UNREVIEWED_ENGINE_PROBE_FIELDS")
            if c.get("kind") != "engine":
                raise Blocked("ENGINE_TYPE_REQUIRED")
            resource_path(c.get("resource_path"))
            contract = c.get("response_contract")
            if (not isinstance(contract, dict) or set(contract) != {"operation", "classification"}
                    or any(not isinstance(contract.get(k), str) or not contract[k]
                           or len(contract[k]) > 120 or "<" in contract[k] or ">" in contract[k]
                           for k in ("operation", "classification"))
                    or contract["classification"] != "READ_ONLY_RESOURCE"):
                raise Blocked("OWNER_OPERATION_RESPONSE_CONTRACT_REQUIRED")
            paths = [c.get(f"{case}_token_file") for case in CASES[1:]]
            if any(not isinstance(x, str) or not Path(x).is_absolute() for x in paths):
                raise Blocked("ORIGINAL_PROVIDER_TOKEN_FILES_REQUIRED")
    if not required.issubset(names):
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


def is_json_content_type(value: str) -> bool:
    """Accept JSON with no parameters or an explicit UTF-8 charset."""
    return re.fullmatch(
        r'application/json(?:[ \t]*;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8"))?',
        value.strip(), re.ASCII | re.IGNORECASE,
    ) is not None


def http_probe(origin: str, path: str, bearer: str | None,
               response_contract: dict[str, str] | None = None) -> tuple[int, bool, bool]:
    """Return status and low-cardinality contract booleans; never retain a response body."""
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
        headers = response.headers
        no_store = "no-store" in {
            directive.strip().lower()
            for directive in headers.get("Cache-Control", "").split(",")
        }
        safe_resource = no_store and is_json_content_type(headers.get("Content-Type", ""))
        contract_match = False
        if response.status == 200 and bearer is not None and response_contract is not None:
            if not safe_resource:
                return response.status, False, False
            length = headers.get("Content-Length")
            if length is None or not length.isascii() or not length.isdigit() or int(length) > 8192:
                raise Blocked("RESOURCE_RESPONSE_SIZE_UNBOUNDED")
            raw = response.read(8193)
            if len(raw) > 8192 or len(raw) != int(length):
                raise Blocked("RESOURCE_RESPONSE_SIZE_INVALID")
            try:
                payload = json.loads(raw, object_pairs_hook=pairs_unique)
            except (ValueError, UnicodeError, TypeError):
                raise Blocked("RESOURCE_RESPONSE_INVALID") from None
            if (not isinstance(payload, dict) or
                    set(payload) != {"operation", "classification"} or
                    payload.get("operation") != response_contract["operation"] or
                    payload.get("classification") != response_contract["classification"]):
                raise Blocked("RESOURCE_RESPONSE_CONTRACT_MISMATCH")
            contract_match = True
        return response.status, safe_resource, contract_match


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


def correlation_key(path: str, output_dir: str, phase: str) -> bytes:
    """Create once before the first phase; require the same owner-only key afterwards."""
    key_path = Path(path)
    root = Path(output_dir).resolve()
    if not key_path.is_absolute() or key_path.resolve().is_relative_to(root):
        raise Blocked("CORRELATION_KEY_MUST_BE_OUTSIDE_RECEIPT_DIRECTORY")
    if phase == "before" and not key_path.exists():
        key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            key = secrets.token_bytes(32)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(key)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                key_path.unlink(missing_ok=True)
                raise
    key = private_read(str(key_path), 32)
    if len(key) != 32:
        raise Blocked("CORRELATION_KEY_INVALID")
    return key


def fingerprint(key: bytes, run_id: str, source_pins: dict[str, str], value: str) -> str:
    """Secret-keyed token correlation bound to this run and immutable peer pins."""
    context = json.dumps({"run_id": run_id, "source_pins": source_pins},
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    message = b"baobab-iam-n07-revocation-v1\x00" + context + b"\x00" + value.encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def unexpired_jwt(value: str) -> None:
    """Untrusted expiry sanity only; real issuer/JWKS/RFC7662 evidence is N03."""
    chunks = value.split(".")
    if len(chunks) != 3:
        raise Blocked("SIGNED_JWT_REQUIRED")
    try:
        claims = json.loads(base64.urlsafe_b64decode(
            chunks[1] + "=" * (-len(chunks[1]) % 4)),
            object_pairs_hook=pairs_unique)
    except (ValueError, UnicodeError, TypeError):
        raise Blocked("SIGNED_JWT_CLAIMS_UNAVAILABLE") from None
    if not isinstance(claims, dict):
        raise Blocked("SIGNED_JWT_CLAIMS_UNAVAILABLE")
    now = time.time()
    exp, iat = claims.get("exp"), claims.get("iat")
    if (isinstance(exp, bool) or isinstance(iat, bool) or
            not isinstance(exp, int) or not isinstance(iat, int) or
            iat > now or exp <= now + 15 or exp - iat > 15 * 60):
        raise Blocked("ORIGINAL_UNEXPIRED_SHORT_LIVED_TOKEN_REQUIRED")


def require_before(profile: dict[str, Any], directory: str, key: bytes, *,
                   dev15_adopter: str | None = None) -> dict[str, Any]:
    root = Path(directory)
    if not (root / "before").is_dir() and (
            (root / "before.json").exists() or (root / "before.sha256").exists()):
        # Historical flat originals used the public run ID as their HMAC key.
        # Preserve them for audit, but never treat them as keyed same-token proof.
        raise Blocked("LEGACY_BEFORE_ORIGINAL_REQUIRES_SECRET_KEYED_RERUN")
    before_bytes = private_read(str(root / "before" / "original.json"))
    if private_read(str(root / "before" / "original.sha256"), 256).decode("ascii").strip() != hashlib.sha256(before_bytes).hexdigest():
        raise Blocked("ORIGINAL_BEFORE_DIGEST_INVALID")
    try:
        before = json.loads(before_bytes, object_pairs_hook=pairs_unique)
    except (ValueError, TypeError):
        raise Blocked("ORIGINAL_BEFORE_INVALID") from None
    if (not isinstance(before, dict) or before.get("schema") != "baobab.iam.n07.http-observation.v1"
            or before.get("phase") != "before" or before.get("run_id") != profile["run_id"]
            or before.get("dev15_adopter") != dev15_adopter
            or before.get("source_pins") != profile["source_pins"]
            or before.get("protected_accepted") is not False
            or before.get("fully_qualified") is not False
            or before.get("correlation_key_id") != hashlib.sha256(key).hexdigest()
            or not isinstance(before.get("fingerprints"), dict)
            or not isinstance(before.get("cases"), dict)):
        raise Blocked("ORIGINAL_BEFORE_PROVENANCE_INVALID")
    for name in ({dev15_adopter} if dev15_adopter is not None else REQUIRED_ENGINES):
        if before["cases"].get(case_id(name, "allowed")) != "OBSERVED":
            raise Blocked("ORIGINAL_POSITIVE_RESOURCE_NOT_OBSERVED")
        token_hash = before["fingerprints"].get(name)
        if not isinstance(token_hash, str) or not DIGEST.fullmatch(token_hash):
            raise Blocked("ORIGINAL_TOKEN_BINDING_MISSING")
    return before


def observe(p: dict[str, Any], phase: str, key: bytes,
            probe=http_probe, before: dict[str, Any] | None = None, *,
            dev15_adopter: str | None = None) -> dict[str, Any]:
    """HTTP observations only. External N02/N03/CP owner evidence is mandatory."""
    results: dict[str, str] = {}
    fingerprints: dict[str, str] = {}
    for c in p["consumers"]:
        name, base = c["name"], c["origin"]
        if phase == "before":
            path = c.get("anonymous_path") if name in ESTATES else c["resource_path"]
            try:
                status, _, _ = probe(base, path, None)
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
                    # Every denied JWT must still be a current, unexpired
                    # credential. Otherwise a generic expiry rejection can be
                    # mistaken for wrong-audience, foreign-tenant or absent-grant
                    # enforcement by the native resource policy.
                    unexpired_jwt(original)
                    if case == "allowed":
                        fingerprints[name] = fingerprint(key, p["run_id"], p["source_pins"], original)
                    if digest in observed_tokens:
                        raise Blocked("REUSED_INDEPENDENT_NEGATIVE_TOKEN")
                    observed_tokens.add(digest)
                    contract = c["response_contract"] if case == "allowed" else None
                    status, no_store, contract_match = probe(base, c["resource_path"], original, contract)
                    good = (status == 200 and no_store and contract_match
                            if case == "allowed" else status in (401, 403))
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
                if (not isinstance(before, dict) or before.get("fingerprints", {}).get(name)
                        != fingerprint(key, p["run_id"], p["source_pins"], revoked)):
                    raise Blocked("ORIGINAL_PRE_REVOCATION_BINDING_MISSING")
                unexpired_jwt(revoked)
                status, _, _ = probe(base, c["resource_path"], revoked)
                results[case_id(name, "revoked_unexpired")] = (
                    "OBSERVED" if status in (401, 403) else "BLOCKED")
            except (Blocked, OSError):
                results[case_id(name, "revoked_unexpired")] = "BLOCKED"
    return {"schema": "baobab.iam.n07.http-observation.v1",
            **({"dev15_adopter": dev15_adopter} if dev15_adopter is not None else {}),
            "evidence_class": "REAL_HTTP_READBACK_UNATTESTED",
            "environment": "development", "phase": phase,
            "run_id": p["run_id"], "source_pins": p["source_pins"],
            "cases": results, "fingerprints": fingerprints,
            "correlation_key_id": hashlib.sha256(key).hexdigest(),
            "protected_accepted": False,
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
    target_dir = root / phase
    if target_dir.exists() or target_dir.is_symlink():
        raise Blocked("ORIGINAL_EVIDENCE_ALREADY_EXISTS")
    staging = root / ("." + phase + "." + secrets.token_hex(16) + ".staging")
    staging.mkdir(mode=0o700)
    try:
        for filename, data in (("original.json", payload),
                               ("original.sha256", (hashlib.sha256(payload).hexdigest() + "\n").encode("ascii"))):
            fd = os.open(staging / filename,
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        stage_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        if target_dir.exists() or target_dir.is_symlink():
            raise Blocked("ORIGINAL_EVIDENCE_ALREADY_EXISTS")
        os.rename(staging, target_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
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
    parser.add_argument("--dev15-adopter", choices=sorted(REQUIRED_ENGINES),
                        help="observe one DEV-15 headless adopter in the owner-provisioned run")
    parser.add_argument("--correlation-key-file", required=True,
                        help="owner-only 0600 256-bit key, outside the receipt directory")
    args = parser.parse_args()
    try:
        if os.environ.get("BAOBAB_ENVIRONMENT") != "development":
            raise Blocked("PROTECTED_EXECUTION_NOT_AUTHORIZED")
        profile = validate_profile(private_json(args.profile), dev15_adopter=args.dev15_adopter)
        exact_source(profile)
        key = correlation_key(args.correlation_key_file, args.output_dir, args.phase)
        prior = (require_before(profile, args.output_dir, key, dev15_adopter=args.dev15_adopter)
                 if args.phase == "after" else None)
        result = observe(profile, args.phase, key, before=prior, dev15_adopter=args.dev15_adopter)
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
