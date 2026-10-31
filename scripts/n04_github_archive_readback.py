#!/usr/bin/env python3
"""IAM-N04: independently anchor a PRIVATE original CI artifact archive to GitHub.

This is immutable Actions source/run/archive provenance, NOT proof that an
engine or legal provider ran correctly. No synthetic/partial run is accepted.
Only exact, reviewed workflow paths are permitted; no arbitrary URL fetch.
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
import sys
import urllib.error
import urllib.request

SHA = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
WORKFLOWS = {
    "baobab-platform/baobab-iam": {
        ".github/workflows/ory-foundation.yml",
        ".github/workflows/ci.yml",
    },
    "baobab-platform/infrastructure": {
        ".github/workflows/dev15-connected.yml",
        ".github/workflows/dev15-native-component.yml",
        ".github/workflows/dev04-int03c.yml",
    },
}


class Held(ValueError):
    pass


def require(ok: bool, code: str) -> None:
    if not ok:
        raise Held(code)


def hash_private_archive(path: str) -> str:
    file = Path(path)
    require(file.is_absolute(), "ORIGINAL_ABSOLUTE_ARCHIVE_REQUIRED")
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and not info.st_mode & 0o077
                and 0 < info.st_size <= 100_000_000,
                "PRIVATE_ORIGINAL_ARCHIVE_REQUIRED")
        digester = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                digester.update(block)
        return "sha256:" + digester.hexdigest()
    finally:
        os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise Held("GITHUB_API_REDIRECT_REFUSED")


def github_json(repository: str, path: str, token: str) -> dict:
    require(repository in WORKFLOWS, "REPOSITORY_NOT_ALLOWED")
    require(bool(token) and len(token) >= 8 and
            not any(char.isspace() for char in token),
            "PRIVATE_READ_ONLY_GITHUB_TOKEN_REQUIRED")
    endpoint = "https://api.github.com/repos/" + repository + path
    request = urllib.request.Request(endpoint, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Cache-Control": "no-store",
        "User-Agent": "baobab-n04-original-artifact-readback",
    })
    client = urllib.request.build_opener(
        NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with client.open(request, timeout=12) as response:
        require(response.status == 200, "GITHUB_READBACK_UNAVAILABLE")
        raw = response.read(1_000_001)
        require(len(raw) <= 1_000_000, "GITHUB_READBACK_TOO_LARGE")
        doc = json.loads(raw, object_pairs_hook=unique)
        require(isinstance(doc, dict), "GITHUB_READBACK_SHAPE")
        return doc


def unique(pairs):
    target = {}
    for key, value in pairs:
        if key in target:
            raise Held("DUPLICATE_GITHUB_JSON_FIELD")
        target[key] = value
    return target


def validate_metadata(run: dict, page: dict, *, repository: str, workflow: str,
                      run_id: int, artifact_id: int, sha: str, archive_digest: str) -> dict:
    require(repository in WORKFLOWS and workflow in WORKFLOWS[repository],
            "UNREVIEWED_GITHUB_WORKFLOW")
    require(run.get("id") == run_id and run.get("head_sha") == sha
            and run.get("path") == workflow
            and run.get("repository", {}).get("full_name") == repository
            and run.get("head_repository", {}).get("full_name") == repository
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("event") in {"push", "pull_request", "workflow_dispatch"},
            "WORKFLOW_SOURCE_OR_COMPLETION_UNTRUSTED")
    items = page.get("artifacts")
    require(isinstance(items, list) and
            type(page.get("total_count")) is int and
            page["total_count"] == len(items) and len(items) <= 100,
            "ARTIFACT_PAGINATION_UNVERIFIED")
    matches = [item for item in items if item.get("id") == artifact_id]
    require(len(matches) == 1, "ORIGINAL_ARTIFACT_NOT_FOUND")
    item = matches[0]
    scope = item.get("workflow_run")
    require(item.get("expired") is False
            and isinstance(item.get("name"), str) and item["name"]
            and item.get("digest") == archive_digest
            and isinstance(scope, dict) and scope.get("id") == run_id
            and scope.get("head_sha") == sha
            and type(item.get("size_in_bytes")) is int
            and item["size_in_bytes"] > 0,
            "GITHUB_ARCHIVE_SOURCE_OR_DIGEST_UNTRUSTED")
    return {
        "schema": "baobab.iam.n04.github-archive-readback.v1",
        "classification": "GITHUB_ACTIONS_ORIGINAL_ARCHIVE_DIGEST_ONLY",
        "repository": repository, "workflow": workflow,
        "run_id": run_id, "run_sha": sha,
        "artifact_id": artifact_id, "artifact_name": item["name"],
        "archive_sha256": archive_digest,
        "original_execution_qualified": False,
        "consumer_registered": False,
        "protected_acceptance": False,
        "production_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", choices=sorted(WORKFLOWS), required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument("--run-source-sha", required=True)
    parser.add_argument("--original-archive", required=True)
    args = parser.parse_args()
    try:
        require(args.workflow in WORKFLOWS[args.repository]
                and args.run_id > 0 and args.artifact_id > 0
                and SHA.fullmatch(args.run_source_sha) is not None,
                "IMMUTABLE_REVIEWED_WORKFLOW_REQUIRED")
        digest = hash_private_archive(args.original_archive)
        token = os.environ.get("GH_TOKEN", "")
        run = github_json(args.repository, "/actions/runs/" + str(args.run_id), token)
        page = github_json(args.repository, "/actions/runs/" +
                           str(args.run_id) + "/artifacts?per_page=100", token)
        result = validate_metadata(run, page,
            repository=args.repository, workflow=args.workflow,
            run_id=args.run_id, artifact_id=args.artifact_id,
            sha=args.run_source_sha, archive_digest=digest)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (Held, OSError, ValueError, KeyError, TypeError, UnicodeError,
            urllib.error.URLError):
        print("HELD N04: original immutable GitHub source/run/archive "
              "provenance missing or refused", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
