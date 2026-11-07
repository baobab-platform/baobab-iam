#!/usr/bin/env python3
"""IAM-N08 source-only native container and dependency admission gate.

This checks build-policy provenance only. The actual CI image build, Trivy
scan, and real restoration are separate mandatory observations.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "Dockerfile.native-browser-bff"
FEDERATION = ROOT / "Dockerfile.federation-authority"
GO_MOD = ROOT / "go.mod"
GO_SUM = ROOT / "go.sum"
DIGEST = re.compile(r"^golang:1\.27\.3-alpine@sha256:[a-f0-9]{64}$")


class PolicyError(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PolicyError(code)


def check(native: str, federation: str, mod: str, go_sum: str, ignore: str) -> None:
    lines = [line.strip() for line in native.splitlines() if line.strip()
             and not line.lstrip().startswith("#")]
    stages = [l for l in lines if l.startswith("FROM ")]
    require(len(stages) == 2, "TWO_IMMUTABLE_BUILD_STAGES_REQUIRED")
    base = stages[0].split()
    require(len(base) == 4 and base[0] == "FROM" and base[2] == "AS"
            and base[3] == "build" and DIGEST.fullmatch(base[1]) is not None,
            "PINNED_GO_1273_BASE_REQUIRED")
    require(stages[1] == "FROM scratch", "SCRATCH_RUNTIME_REQUIRED")
    fed = re.findall(r"^FROM (golang:[^\s]+) AS build$", federation, re.MULTILINE)
    require(len(fed) == 1 and fed[0] == base[1], "BUILD_TOOLCHAIN_DIGEST_DRIFT")
    require(re.search(r"^go 1\.27\.3$", mod, re.MULTILINE) is not None,
            "MODULE_TOOLCHAIN_DRIFT")
    require("replace (" not in mod and not re.search(r"^replace ", mod, re.MULTILINE),
            "UNREVIEWED_MODULE_REPLACEMENT")
    require(len(go_sum) > 2000 and "github.com/" in go_sum and "golang.org/" in go_sum,
            "VERIFIED_MODULE_SUM_REQUIRED")
    require("GOTOOLCHAIN=local" in native and "CGO_ENABLED=0" in native
            and "GOSUMDB=sum.golang.org" in native
            and "go mod verify" in native, "MODULE_AND_LOCAL_COMPILER_VERIFY_REQUIRED")
    require("go build -trimpath -buildvcs=false" in native
            and '-ldflags="-s -w -buildid="' in native,
            "REPRODUCIBLE_GO_BUILD_REQUIRED")
    require("COPY go.mod go.sum ./" in native
            and "COPY internal/ ./internal/" in native
            and "COPY cmd/native-browser-bff/ ./cmd/native-browser-bff/" in native,
            "EXACT_SOURCE_CONTEXT_REQUIRED")
    require(not re.search(r"^COPY (?:\.|/|config|tests|\.env)\b", native, re.MULTILINE),
            "WIDE_SECRET_BEARING_CONTEXT_FORBIDDEN")
    require("USER 65532:65532" in lines and "ENTRYPOINT [\"/native-browser-bff\"]" in lines,
            "NONROOT_FIXED_ENTRYPOINT_REQUIRED")
    require("COPY --from=build /etc/ssl/certs/ca-certificates.crt" in native,
            "VERIFIED_TLS_ROOTS_REQUIRED")
    require(all(x in ignore.splitlines() for x in (".env", ".env.*", ".git")),
            "SECRET_SOURCE_EXCLUSIONS_REQUIRED")
    require(not any(word in native.lower() for word in (
        "chmod 777", "insecureskipverify", "skip-verify", "latest", "--privileged",
        "curl | sh", "wget | sh")), "UNSAFE_IMAGE_BUILD_FORBIDDEN")


def main() -> int:
    check(NATIVE.read_text(), FEDERATION.read_text(), GO_MOD.read_text(),
          GO_SUM.read_text(), (ROOT / ".dockerignore").read_text())
    print("N08_SOURCE_POLICY_ONLY_NO_RUNTIME_ACCEPTANCE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
