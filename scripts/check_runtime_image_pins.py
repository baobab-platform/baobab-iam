#!/usr/bin/env python3
"""ADR-IAM-0032: reject mutable/mismatched IAM runtime image declarations.

This is repository lock conformance, not a registry signature, SBOM or
production deployment attestation. Live image/SBOM and PG17 version
qualification are separate protected release gates.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _load(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid mapping: {path.name}")
    return value


def verify(root: Path) -> None:
    provider = _load(root / "provider.lock.yaml")
    keycloak = _load(root / "upstream.lock.yaml")["keycloak"]
    ory = _load(root / "docker-compose.ory.yml")["services"]
    legacy = _load(root / "docker-compose.yml")["services"]
    workflows = _load(root / ".github/workflows/ci.yml")

    if str(provider["postgres"]["version"]) != "17":
        raise ValueError("PostgreSQL generation does not match supported baseline")
    live_pg = workflows["jobs"]["iam-n05-postgres17-lifecycle"]["services"]["postgres"]["image"]
    if not isinstance(live_pg, str) or not live_pg.startswith("postgres@"):
        raise ValueError("disposable PG17 image must be digest pinned")
    if not DIGEST.fullmatch(live_pg.removeprefix("postgres@")):
        raise ValueError("invalid PostgreSQL image digest")
    for name, config in (
        ("keycloak-postgres", legacy["postgres"]),
        ("kratos-postgres", ory["postgres-kratos"]),
        ("hydra-postgres", ory["postgres-hydra"]),
    ):
        if config.get("image") != live_pg:
            raise ValueError(f"{name} image drifted from qualified disposable PostgreSQL pin")

    for name in ("kratos", "hydra"):
        pin = provider[name]
        digest = pin.get("digest")
        version = pin.get("version")
        image = pin.get("image")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError(f"{name} lacks immutable lock digest")
        if not isinstance(version, str) or not isinstance(image, str):
            raise ValueError(f"{name} version/image lock missing")
        expected = f"{image}:{version}@{digest}"
        for service in (name, f"{name}-migrate"):
            if ory[service].get("image") != expected:
                raise ValueError(f"{service} image no longer matches provider lock")

    digest = keycloak.get("digest")
    version = keycloak.get("version")
    image = keycloak.get("image")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ValueError("Keycloak digest missing")
    if not isinstance(version, str) or not isinstance(image, str):
        raise ValueError("Keycloak lock version/image missing")
    expected = f"{image}:{version}@{digest}"
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    runtime_refs = [
        line.split()[1]
        for line in dockerfile.splitlines()
        if line.startswith("FROM ") and image in line
    ]
    if not runtime_refs or any(ref != expected for ref in runtime_refs):
        raise ValueError("Keycloak Dockerfile runtime image drifted from upstream lock")


def main() -> int:
    try:
        verify(Path(__file__).resolve().parents[1])
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"IAM RUNTIME PIN GATE HELD: {exc}", file=sys.stderr)
        return 1
    print("IAM RUNTIME PIN GATE PASS (source image lock only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
