"""Security regression for source-only N02 evidence binding.

The fixtures are intentionally fabricated to test the parser and MUST NOT be
reported as real provider, CP, Chromium or protected acceptance.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/n02_evidence_gate.py"
spec = importlib.util.spec_from_file_location("n02_evidence_gate", SOURCE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sha = "a" * 40
        self.run_id = "b" * 32
        self.shared_sha = "c" * 40
        self.cp_sha = "d" * 40
        self.harness_sha = "e" * 40

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(json.dumps(value).encode())
        path.chmod(0o600)
        return str(path)

    def browser(self):
        return {
            "schema": "baobab.iam.n02.browser-observation.v1",
            "classification": "REAL_BROWSER_SYNTHETIC_DATA",
            "source_sha": self.sha, "run_id": self.run_id,
            "shared_source_sha": self.shared_sha, "cp_source_sha": self.cp_sha,
            "infrastructure_harness_sha": self.harness_sha,
            "provider_and_cp_independently_attested": False,
            "protected_accepted": False,
            "cases": {name: "OBSERVED" for name in gate.CASE_IDS},
        }

    def dev04(self):
        return {
            "schema": "infrastructure.dev01.lifecycle.observed.v1",
            "run_id": self.run_id, "harness_sha": self.harness_sha,
            "source_pins": {"baobab-iam": self.sha, "shared": self.shared_sha,
                            "baobab-cp": self.cp_sha},
            "evidence_class": "REAL_COMPONENT_SYNTHETIC_DATA",
            "lifecycle_passed": True, "teardown_verified": True,
            "int03c_qualified": True, "protected_acceptance": False,
            "production_authorized": False,
            "int03c": {
                "schema": "infrastructure.dev04.int03c-observed.v1",
                "run_id": self.run_id, "scope": "DEV04_INT03C_DEVELOPMENT_ONLY",
                "protected_acceptance": False, "canonical_provider_qualified": False,
                "cases": {
                    name: {
                        "result": "PASS", "reason": "OBSERVED",
                        "assertions": {"actual_live_evidence": True},
                    } for name in gate.DEV04_CASES
                },
            },
        }

    def test_bound_development_receipts_are_not_protected(self):
        browser = self.browser()
        dev04 = self.dev04()
        self.assertEqual(gate.browser_readback(browser, self.sha), self.run_id)
        gate.dev04_readback(dev04, self.sha, self.run_id)
        gate.joined_source_readback(browser, dev04)
        with self.assertRaises(gate.Blocked):
            gate.protected_packet({}, b"browser", b"dev04", self.sha,
                self.run_id, "/fake/packet", "/fake/pub", "/fake/sig")

    def test_refuse_source_run_replay_drift_and_false_protected_claims(self):
        cases = [
            ("wrong_source", lambda b, d: b.update(source_sha="c"*40)),
            ("wrong_run", lambda b, d: d.update(run_id="c"*32)),
            ("source_drift", lambda b, d: d["source_pins"].update({"baobab-iam": "d"*40})),
            ("fake_protected", lambda b, d: d.update(protected_acceptance=True)),
            ("fake_canonical", lambda b, d: d["int03c"].update(canonical_provider_qualified=True)),
            ("fake_browser", lambda b, d: b.update(protected_accepted=True)),
            ("missing_browser", lambda b, d: b["cases"].pop(next(iter(b["cases"])))),
            ("skip_browser", lambda b, d: b["cases"].update({next(iter(b["cases"])): "BLOCKED"})),
            ("skip_cp", lambda b, d: d["int03c"]["cases"][next(iter(d["int03c"]["cases"]))].update(result="BLOCKED")),
            ("missing_teardown", lambda b, d: d.update(teardown_verified=False)),
        ]
        for name, mutate in cases:
            with self.subTest(name=name):
                b, d = self.browser(), self.dev04()
                mutate(b, d)
                with self.assertRaises(gate.Blocked):
                    run = gate.browser_readback(b, self.sha)
                    gate.dev04_readback(d, self.sha, run)
                    gate.joined_source_readback(b, d)

    def test_refuse_unbound_peer_source_and_malformed_original_case(self):
        for key, value in (("shared_source_sha", "f"*40),
                           ("cp_source_sha", "f"*40),
                           ("infrastructure_harness_sha", "f"*40)):
            browser, receipt = self.browser(), self.dev04()
            browser[key] = value
            with self.subTest(key=key), self.assertRaises(gate.Blocked):
                gate.joined_source_readback(browser, receipt)
        browser, receipt = self.browser(), self.dev04()
        receipt["int03c"]["cases"][next(iter(gate.DEV04_CASES))] = None
        with self.assertRaises(gate.Blocked):
            gate.dev04_readback(receipt, self.sha, self.run_id)
        browser = self.browser()
        del browser["cp_source_sha"]
        with self.assertRaises(gate.Blocked):
            gate.browser_readback(browser, self.sha)

    def test_digest_sidecar_validates_original_bytes(self):
        original = self.write("original.json", self.browser())
        raw = Path(original).read_bytes()
        sidecar = self.root / "digest.txt"
        sidecar.write_text(hashlib.sha256(raw).hexdigest()+"\n")
        sidecar.chmod(0o600)
        gate.digest_sidecar(raw, str(sidecar))
        with self.assertRaises(gate.Blocked):
            gate.digest_sidecar(raw+b"tampered", str(sidecar))
        with self.assertRaises(gate.Blocked):
            gate.digest_sidecar(raw, "/tmp/not-a-real-iam-evidence-digest")

    def test_public_reviewer_key_from_packet_is_not_trusted(self):
        packet = {
            "schema": "baobab.iam.n02.protected-review-packet.v1",
            "environment": "protected-staging", "source_sha": self.sha,
            "run_id": self.run_id,
            "browser_sha256": hashlib.sha256(b"browser").hexdigest(),
            "int03c_sha256": hashlib.sha256(b"dev04").hexdigest(),
            "observed_evidence_digests": {x: "e"*64 for x in gate.PROTECTED_CHECKS},
            "maker_id": "maker", "checker_id": "checker", "witness_id": "witness",
        }
        packet_path = self.write("packet.json", packet)
        with self.assertRaises((gate.Blocked, FileNotFoundError)):
            gate.protected_packet(packet, b"browser", b"dev04", self.sha,
                self.run_id, packet_path, "/not/real/independent.pub", "/not/real/signature")


if __name__ == "__main__":
    unittest.main()
