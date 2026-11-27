"""N04 independent GitHub Actions artifact provenance: fixture-only negatives."""
from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import n04_github_archive_readback as gate

REPO = "baobab-platform/infrastructure"
WORKFLOW = ".github/workflows/dev15-connected.yml"
SHA = "a" * 40
ID = 41234567890
ARTIFACT_ID = 13012345678
DIGEST = "sha256:" + "c" * 64


def source():
    return {
        "id": ID, "head_sha": SHA, "path": WORKFLOW,
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "status": "completed", "conclusion": "success",
        "event": "pull_request",
    }


def artifacts():
    return {
        "total_count": 1,
        "artifacts": [{
            "id": ARTIFACT_ID, "digest": DIGEST,
            "name": "dev15-connected-pulse-intelligence",
            "size_in_bytes": 1024, "expired": False,
            "workflow_run": {"id": ID, "head_sha": SHA},
        }],
    }


def verify(run, page):
    return gate.validate_metadata(run, page, repository=REPO,
        workflow=WORKFLOW, run_id=ID, artifact_id=ARTIFACT_ID,
        sha=SHA, archive_digest=DIGEST)


class TestN04OriginalActionsProvenance(unittest.TestCase):
    def test_valid_metadata_never_certifies_runtime(self):
        result = verify(source(), artifacts())
        self.assertEqual(result["classification"],
                         "GITHUB_ACTIONS_ORIGINAL_ARCHIVE_DIGEST_ONLY")
        for field in ("original_execution_qualified", "consumer_registered",
                      "protected_acceptance", "production_authorized"):
            self.assertIs(result[field], False)

    def test_wrong_run_status_archive_or_source_denied(self):
        for field, value in (
            ("head_sha", "b" * 40),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("path", ".github/workflows/other.yml"),
            ("repository", {"full_name": "foreign/not-platform"}),
            ("event", "workflow_run"),
        ):
            run = source()
            run[field] = value
            with self.assertRaises(gate.Held, msg=field):
                verify(run, artifacts())

    def test_expired_missing_foreign_or_mutated_artifact_denied(self):
        for field, value in (
            ("digest", "sha256:" + "f" * 64),
            ("expired", True),
            ("workflow_run", {"id": ID, "head_sha": "b" * 40}),
            ("id", 100),
            ("size_in_bytes", 0),
        ):
            a = artifacts()
            a["artifacts"][0][field] = value
            with self.assertRaises(gate.Held, msg=field):
                verify(source(), a)
        a = artifacts()
        a["total_count"] = 2
        with self.assertRaises(gate.Held):
            verify(source(), a)
        a = artifacts()
        a["artifacts"].append(copy.deepcopy(a["artifacts"][0]))
        a["total_count"] = 2
        with self.assertRaises(gate.Held):
            verify(source(), a)

    def test_private_archive_requires_exact_original_permissions_and_digest(self):
        with tempfile.TemporaryDirectory() as root:
            archive = Path(root) / "artifact.zip"
            archive.write_bytes(b"not a real archive, only private fixture bytes")
            archive.chmod(0o600)
            observed = gate.hash_private_archive(str(archive))
            self.assertEqual(observed, "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest())
            archive.chmod(0o644)
            with self.assertRaises(gate.Held):
                gate.hash_private_archive(str(archive))
            archive.chmod(0o600)
            with self.assertRaises(gate.Held):
                gate.hash_private_archive("relative.zip")
            path = Path(root) / "symlink"
            path.symlink_to(archive)
            with self.assertRaises(OSError):
                gate.hash_private_archive(str(path))

    def test_only_reviewed_workflows_and_repositories(self):
        with self.assertRaises(gate.Held):
            gate.validate_metadata(source(), artifacts(),
                repository="baobab-platform/rogue", workflow=WORKFLOW,
                run_id=ID, artifact_id=ARTIFACT_ID, sha=SHA, archive_digest=DIGEST)


if __name__ == "__main__":
    unittest.main()
