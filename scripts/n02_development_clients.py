#!/usr/bin/env python3
"""Owner-only REAL Hydra N02 development client lifecycle (not CP acceptance).

Hydra Admin is never browser-exposed. Source records and secrets stay in
0700 run storage; 0600 originals contain identities and exact profile/lease
digests, never credentials. The CP reader remains PROVISIONED in Shared until
separate governed admission; a Hydra client is not a CP permission.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SHA = re.compile(r"[a-f0-9]{40}\Z")
RUN = re.compile(r"[a-f0-9]{32}\Z")
FQDN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\Z")
BROWSER = "baobab-dev-zuribeans-native-browser-bff"
CP_READER = "baobab-dev-zuribeans-cp-principal-validator"
ROLES = (
    ("browser", BROWSER, ["authorization_code"], ["code"], ["baobab-trade"],
     "openid trade:buy"),
    ("cp_reader", CP_READER, ["client_credentials"], ["token"],
     ["baobab-control-plane"], "identity:principal:resolve"),
)


class Refused(Exception):
    pass


def require(ok: bool, code: str) -> None:
    if not ok:
        raise Refused(code)


def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, val in pairs:
        require(key not in result, "DUPLICATE_JSON_FIELD")
        result[key] = val
    return result


def private_bytes(path: str, limit: int = 32768) -> bytes:
    require(isinstance(path, str) and Path(path).is_absolute(), "PRIVATE_ABSOLUTE_FILE_REQUIRED")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid()
                and meta.st_nlink == 1 and 0 < meta.st_size <= limit
                and meta.st_mode & 0o077 == 0, "PRIVATE_OWNER_FILE_REQUIRED")
        result = stream.read(limit + 1)
    require(len(result) <= limit, "PRIVATE_FILE_TOO_LARGE")
    return result


def current_profile(path: str) -> dict:
    doc = json.loads(private_bytes(path), object_pairs_hook=unique)
    require(isinstance(doc, dict)
            and doc.get("schema") == "baobab.iam.n02.disposable-clients.v1"
            and doc.get("environment") == "development"
            and doc.get("protected_acceptance") is False
            and os.environ.get("BAOBAB_ENVIRONMENT") == "development",
            "N02_REGISTER_DEVELOPMENT_ONLY")
    require(isinstance(doc.get("run_id"), str) and RUN.fullmatch(doc["run_id"]),
            "N02_RUN_LEASE_REQUIRED")
    for key in ("iam_source_sha", "shared_source_sha", "cp_source_sha",
                "zuribeans_source_sha", "infrastructure_harness_sha"):
        require(isinstance(doc.get(key), str) and SHA.fullmatch(doc[key]),
                "N02_FULL_SOURCE_TUPLE_REQUIRED")
    root = Path(__file__).resolve().parents[1]
    try:
        revision = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=8, check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                               capture_output=True, text=True, timeout=8, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        raise Refused("N02_CLIENT_REGISTRY_SOURCE_UNVERIFIED") from None
    require(revision == doc["iam_source_sha"] and not dirty,
            "N02_CLIENT_REGISTRY_SOURCE_DRIFT")
    origin = doc.get("estate_origin")
    require(isinstance(origin, str) and origin.startswith("https://"), "N02_HTTPS_ESTATE_REQUIRED")
    estate = urllib.parse.urlsplit(origin)
    require(estate.scheme == "https" and estate.hostname is not None
            and FQDN.fullmatch(estate.hostname) is not None
            and estate.netloc == estate.hostname and estate.path in ("", "/")
            and not estate.username and not estate.password
            and not estate.query and not estate.fragment,
            "N02_APPROVED_FIRST_PARTY_ORIGIN_REQUIRED")
    doc["estate_origin"] = origin.rstrip("/")
    admin = doc.get("hydra_admin_origin")
    require(isinstance(admin, str) and all(32 <= ord(c) < 127 for c in admin),
            "N02_PRIVATE_HYDRA_ADMIN_REQUIRED")
    url = urllib.parse.urlsplit(admin)
    require(url.hostname == "127.0.0.1" and url.scheme in ("http", "https")
            and url.port is not None and 1 <= url.port <= 65535
            and not url.username and not url.password and url.path in ("", "/")
            and not url.query and not url.fragment,
            "N02_PRIVATE_LOOPBACK_HYDRA_ADMIN_REQUIRED")
    doc["hydra_admin_origin"] = admin.rstrip("/")
    lease_end = doc.get("expires_at_unix")
    require(type(lease_end) is int and 30 < lease_end - int(time.time()) <= 3600,
            "N02_BOUNDED_CLIENT_LEASE_REQUIRED")
    for kind in ("browser", "cp_reader"):
        secret = private_bytes(doc.get(kind + "_secret_file"), 4096).decode("utf-8").strip()
        require(32 <= len(secret) <= 1024 and not any(c.isspace() for c in secret),
                "N02_STRONG_PRIVATE_CREDENTIAL_REQUIRED")
    if url.scheme == "https":
        require(isinstance(doc.get("admin_ca_file"), str),
                "N02_ADMIN_TLS_CA_REQUIRED")
        private_bytes(doc["admin_ca_file"], 32768)
    return doc


class Registry:
    def __init__(self, doc: dict):
        self.doc = doc
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None
        context = None
        if doc["hydra_admin_origin"].startswith("https://"):
            context = ssl.create_default_context(cadata=private_bytes(
                doc["admin_ca_file"]).decode("ascii"))
        self.http = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context) if context else urllib.request.HTTPHandler(),
            NoRedirect(),
        )

    def request(self, method: str, path: str, payload: object | None = None) -> tuple[int, object | None]:
        data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        req = urllib.request.Request(self.doc["hydra_admin_origin"] + path,
                                     data=data, method=method,
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json",
                                              "Cache-Control": "no-store"})
        try:
            with self.http.open(req, timeout=8) as response:
                code, raw = response.status, response.read(65537)
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, b""
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Refused("N02_HYDRA_ADMIN_OUTCOME_UNKNOWN") from None
        require(len(raw) <= 65536, "N02_HYDRA_ADMIN_RESPONSE_TOO_LARGE")
        if not raw:
            return code, None
        try:
            return code, json.loads(raw, object_pairs_hook=unique)
        except (ValueError, UnicodeDecodeError):
            raise Refused("N02_HYDRA_ADMIN_RESPONSE_INVALID") from None

    def expected(self, role: tuple) -> dict:
        name, client_id, grants, responses, audiences, scope = role
        metadata = {
            "environment": "development",
            "owner": "baobab-platform/zuribeans",
            "n02_run_id": self.doc["run_id"],
        }
        item = {
            "client_id": client_id,
            "client_secret": private_bytes(self.doc[name + "_secret_file"], 4096).decode().strip(),
            "grant_types": grants,
            "response_types": responses,
            "scope": scope,
            "audience": audiences,
            "token_endpoint_auth_method": "client_secret_basic",
            "metadata": metadata,
            "skip_consent": False,
        }
        if name == "browser":
            item["redirect_uris"] = [self.doc["estate_origin"] + "/auth/callback"]
            item["subject_type"] = "public"
        return item

    def readback(self, role: tuple) -> None:
        expected = self.expected(role)
        status, value = self.request("GET", "/admin/clients/" + role[1])
        require(status == 200 and isinstance(value, dict),
                "N02_HYDRA_CLIENT_READBACK_REQUIRED")
        # Verify exact configured authority and original run lease. No
        # acceptance based on POST's success code or guessed client ID.
        for key in ("client_id", "grant_types", "response_types", "scope",
                    "audience", "token_endpoint_auth_method", "metadata",
                    "skip_consent"):
            require(value.get(key) == expected[key], "N02_HYDRA_CLIENT_PROFILE_DRIFT")
        if role[0] == "browser":
            for key in ("redirect_uris", "subject_type"):
                require(value.get(key) == expected[key], "N02_BROWSER_REDIRECT_PROFILE_DRIFT")
        else:
            require(not value.get("redirect_uris"),
                    "N02_CP_READER_CANNOT_REDIRECT_AS_HUMAN")

    def register(self) -> None:
        for role in ROLES:
            client_id = role[1]
            status, _ = self.request("GET", "/admin/clients/" + client_id)
            require(status == 404, "N02_CLIENT_ID_ALREADY_USED")
            new_status, _ = self.request("POST", "/admin/clients", self.expected(role))
            require(new_status == 201, "N02_HYDRA_CLIENT_ISSUANCE_UNCONFIRMED")
            self.readback(role)

    def teardown(self) -> None:
        for role in reversed(ROLES):
            self.readback(role)  # foreign-run identity must never be deleted
            status, _ = self.request("DELETE", "/admin/clients/" + role[1])
            require(status in (200, 204), "N02_HYDRA_CLIENT_DELETE_UNCONFIRMED")
            missing, _ = self.request("GET", "/admin/clients/" + role[1])
            require(missing == 404, "N02_HYDRA_CLIENT_SURVIVED_TEARDOWN")


def original(directory: str, doc: dict, stage: str) -> None:
    root = Path(directory)
    require(root.is_absolute() and not root.is_symlink(), "N02_PRIVATE_ORIGINAL_DIR_REQUIRED")
    meta = root.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
            and not meta.st_mode & 0o077, "N02_PRIVATE_ORIGINAL_DIR_REQUIRED")
    result = {
        "schema": "baobab.iam.n02.disposable-client-observation.v1",
        "classification": "REAL_HYDRA_ADMIN_CLIENTS_ONLY_UNATTESTED",
        "run_id": doc["run_id"],
        "phase": stage,
        "source": {name: doc[name] for name in (
            "iam_source_sha", "cp_source_sha", "shared_source_sha",
            "zuribeans_source_sha", "infrastructure_harness_sha")},
        "client_ids": [r[1] for r in ROLES],
        "cp_principal_resolved": False,
        "browser_cases_observed": False,
        "protected_acceptance": False,
    }
    raw = json.dumps(result, separators=(",", ":"), sort_keys=True).encode()
    prefix = "n02-clients-" + stage.lower()
    for name, payload in (
        (prefix + ".json", raw),
        (prefix + ".sha256", (hashlib.sha256(raw).hexdigest() + "\n").encode()),
    ):
        fd = os.open(root / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("register", "verify", "teardown"))
    parser.add_argument("--profile", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    try:
        doc = current_profile(args.profile)
        registry = Registry(doc)
        if args.operation == "register":
            registry.register()
        elif args.operation == "verify":
            for role in ROLES:
                registry.readback(role)
        else:
            registry.teardown()
        original(args.evidence_dir, doc, args.operation.upper())
    except (Refused, OSError, ValueError, KeyError, TypeError, UnicodeDecodeError):
        print("N02_HYDRA_CLIENTS_HELD", file=sys.stderr)
        return 2
    print("N02_HYDRA_CLIENTS_REAL_LIFECYCLE_OBSERVED_UNATTESTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
