"""Negative-first tests for N04 evidence readback. All data below are fixtures.

A unit-test candidate is NOT an actual development receipt or provider approval.
"""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import n04_development_gate as n04

IAM = "a" * 40
SHARED = "b" * 40
CP = "c" * 40
INFRA = "d" * 40
R = "e" * 32
PR = "f" * 32
PAY = "0" * 32


def c403():
    return {
        "schema": "baobab-c4-03-registered-integration/v1",
        "source_commit": IAM, "result": "PASS",
        "checks": {key: True for key in n04.C403},
        "registered_live_services_contacted": True,
        "cp_withdrawal_observed": True,
        "physical_passkey_qualified": False,
        "production_ready": False,
    }


def engine(kind, run):
    caps = {
        "identity.workload-token.issue": {
            "source": "DECLARED_IMPLEMENTED", "development": "OBSERVED",
            "certification": "NOT_QUALIFIED", "protected_authorized": False,
        }
    }
    return {
        "schema": "infrastructure.dev01.lifecycle.observed.v1",
        "run_id": run,
        "source_pins": {"baobab-iam": IAM, "shared": SHARED, "baobab-cp": CP},
        "harness_sha": INFRA, "evidence_class": "REAL_COMPONENT_SYNTHETIC_DATA",
        "lifecycle_passed": True, "teardown_verified": True,
        "protected_acceptance": False, "production_authorized": False,
        "engine_integration": {
            "schema": "infrastructure.engine-integration.observed.v1",
            "run_id": run, "profile_key": n04.PROFILES[kind], "subject_engine": kind,
            "synthetic_only": True, "protected_acceptance": False,
            "production_authorized": False,
            "cases": {case: {"result": "PASS", "reason": "OBSERVED"}
                      for case in n04.ENG},
            "capabilities": caps,
            "independent_observations": {
                "native_cp_resolutions": {"identity.workload-token.issue": 2},
                "native_audits_joined": 2,
                "issuer_cleanup": True, "host_cleanup": True,
                "faults_observed": ["cp", "hydra"],
                "authority_denials": 4, "principal_denial": True,
            },
        }
    }


def n02_browser():
    return {
        "schema": "baobab.iam.n02.browser-observation.v1",
        "classification": "REAL_BROWSER_SYNTHETIC_DATA",
        "source_sha": IAM, "run_id": R,
        "protected_accepted": False,
        "provider_and_cp_independently_attested": False,
        "cases": {case: "OBSERVED" for case in n04.n02.CASE_IDS},
    }


def dev04():
    return {
        "schema": "infrastructure.dev01.lifecycle.observed.v1",
        "run_id": R, "source_pins": {
            "baobab-iam": IAM, "baobab-cp": CP, "shared": SHARED,
        },
        "harness_sha": INFRA,
        "evidence_class": "REAL_COMPONENT_SYNTHETIC_DATA",
        "lifecycle_passed": True, "teardown_verified": True,
        "int03c_qualified": True,
        "protected_acceptance": False, "production_authorized": False,
        "int03c": {
            "schema": "infrastructure.dev04.int03c-observed.v1",
            "run_id": R, "scope": "DEV04_INT03C_DEVELOPMENT_ONLY",
            "protected_acceptance": False,
            "canonical_provider_qualified": False,
            "cases": {case: {
                "result": "PASS", "reason": "OBSERVED",
                "assertions": {"native_observation": True},
            } for case in n04.n02.DEV04_CASES},
        },
    }


class N04Gate(unittest.TestCase):
    def test_c403_exact_closed_checklist_and_never_production(self):
        n04.c403_readback(c403(), IAM)
        for mutation in (
            lambda x: x["checks"].update({"extra": True}),
            lambda x: x["checks"].pop("code_replay_denied"),
            lambda x: x["checks"].update({"cp_withdrawal_observed": False}),
            lambda x: x.update({"source_commit": CP}),
            lambda x: x.update({"registered_live_services_contacted": False}),
            lambda x: x.update({"cp_withdrawal_observed": False}),
            lambda x: x.update({"production_ready": True}),
            lambda x: x.update({"physical_passkey_qualified": True}),
            lambda x: x.update({"result": "BLOCKED"}),
        ):
            row = c403()
            mutation(row)
            with self.assertRaises(n04.Held):
                n04.c403_readback(row, IAM)

    def test_engine_negatives_must_all_be_original_passes(self):
        row = engine("baobab-pulse", PR)
        n04.engine_readback(row, "baobab-pulse", IAM, SHARED, CP)
        for mutate in (
            lambda x: x["engine_integration"]["cases"].pop("ENG-ONB-06"),
            lambda x: x["engine_integration"]["cases"]["ENG-ONB-04"].update(
                {"result": "BLOCKED", "reason": "NOT_EXECUTED"}),
            lambda x: x["engine_integration"]["independent_observations"].update(
                {"host_cleanup": False}),
            lambda x: x["engine_integration"]["independent_observations"].update(
                {"authority_denials": 2}),
            lambda x: x["engine_integration"]["independent_observations"].update(
                {"principal_denial": False}),
            lambda x: x["engine_integration"]["capabilities"][
                "identity.workload-token.issue"].update({"development": "NOT_OBSERVED"}),
            lambda x: x.update({"source_pins": {"baobab-iam": IAM}}),
            lambda x: x.update({"teardown_verified": False}),
            lambda x: x.update({"evidence_class": "SOURCE"}),
            lambda x: x["engine_integration"].update({"subject_engine": "baobab-payments"}),
            lambda x: x["engine_integration"].update({"protected_acceptance": True}),
        ):
            bad = copy.deepcopy(row)
            mutate(bad)
            with self.assertRaises(n04.Held):
                n04.engine_readback(bad, "baobab-pulse", IAM, SHARED, CP)

    def test_c403_sidecar_requires_original_exact_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw = (json.dumps(c403(), sort_keys=True) + "\n").encode()
            artifact = root / "receipt.json"
            checksum = root / "receipt.sha256"
            artifact.write_bytes(raw)
            artifact.chmod(0o600)
            checksum.write_text(hashlib.sha256(raw).hexdigest() + "  receipt.json\n")
            checksum.chmod(0o600)
            self.assertEqual(n04.original(str(artifact), str(checksum), c403=True), c403())
            checksum.write_text(hashlib.sha256(raw).hexdigest() + "\n")
            with self.assertRaises(n04.Held):
                n04.original(str(artifact), str(checksum), c403=True)
            checksum.write_text(hashlib.sha256(raw).hexdigest() + "  receipt.json\n")
            artifact.write_bytes(raw + b" ")
            with self.assertRaises(n04.Held):
                n04.original(str(artifact), str(checksum), c403=True)

    def test_cross_owner_join_is_candidate_only(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            models = {
                "browser": n02_browser(), "int03c": dev04(), "c403": c403(),
                "pulse": engine("baobab-pulse", PR),
                "payments": engine("baobab-payments", PAY),
            }
            files = []
            for key, value in models.items():
                path = root / (key + ".json")
                sidecar = root / (key + ".sha256")
                raw = (json.dumps(value, sort_keys=True) + "\n").encode()
                path.write_bytes(raw)
                sidecar.write_text(
                    hashlib.sha256(raw).hexdigest() +
                    ("  receipt.json\n" if key == "c403" else "\n"))
                path.chmod(0o600)
                sidecar.chmod(0o600)
                files.extend((f"--{key}", str(path), f"--{key}-digest", str(sidecar)))
            args = ["--iam-sha", IAM, "--shared-sha", SHARED, "--cp-sha", CP] + files
            self.assertEqual(n04.readback(args),
                             "N04_ORIGINAL_EVIDENCE_RECONCILED_UNATTESTED")
            # No acceptance if two independent owner runs reuse one run ID.
            models["payments"]["run_id"] = PR
            models["payments"]["engine_integration"]["run_id"] = PR
            path = root / "payments.json"
            sidecar = root / "payments.sha256"
            raw = (json.dumps(models["payments"], sort_keys=True) + "\n").encode()
            path.write_bytes(raw)
            sidecar.write_text(hashlib.sha256(raw).hexdigest() + "\n")
            with self.assertRaises(n04.Held):
                n04.readback(args)

    def test_non_immutable_source_denied(self):
        with self.assertRaises(n04.Held):
            n04.readback(["--iam-sha", "main", "--shared-sha", SHARED,
                          "--cp-sha", CP] + [
                              x for key in ("browser", "int03c", "c403", "pulse", "payments")
                              for x in (f"--{key}", "/not/present",
                                        f"--{key}-digest", "/not/present")])


if __name__ == "__main__":
    unittest.main()
