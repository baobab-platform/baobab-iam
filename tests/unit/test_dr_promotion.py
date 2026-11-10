import copy
import unittest

from scripts.operations.check_dr_promotion import REQUIRED, ROLES, verify


def valid_record():
    return {
        "domain_id": "domain-a", "old_region": "region-a",
        "candidate_region": "region-b", "issuer": "https://iam.example.test",
        "backup_checkpoint": "lsn-100", "recovery_checkpoint": "lsn-200",
        "old_writer_reachable": False, "candidate_writer_enabled": False,
        "unresolved_revocations": 0, "unresolved_replication_gap": False,
        "attestations": {
            name: {"verified": True, "role": ROLES[name],
                   "actor": "operator" if name == "old_writer_fenced" else "reviewer",
                   "evidence_ref": "evidence/" + name}
            for name in REQUIRED
        },
    }


class DRPromotionPreflightTests(unittest.TestCase):
    def test_complete_preflight_is_not_promotion(self):
        self.assertTrue(verify(valid_record()))

    def test_missing_each_attestation_denied(self):
        for name in REQUIRED:
            with self.subTest(name=name):
                record = valid_record()
                del record["attestations"][name]
                with self.assertRaises(ValueError):
                    verify(record)

    def test_each_unverified_attestation_denied(self):
        for name in REQUIRED:
            with self.subTest(name=name):
                record = valid_record()
                record["attestations"][name]["verified"] = False
                with self.assertRaises(ValueError):
                    verify(record)

    def test_security_critical_denials(self):
        for key, value in (
            ("old_writer_reachable", True),
            ("candidate_writer_enabled", True),
            ("unresolved_revocations", 1),
            ("unresolved_replication_gap", True),
            ("issuer", "http://iam.example.test"),
            ("candidate_region", "region-a"),
        ):
            with self.subTest(key=key):
                record = valid_record()
                record[key] = value
                with self.assertRaises(ValueError):
                    verify(record)

    def test_no_self_attested_fencing_and_replay(self):
        record = valid_record()
        record["attestations"]["security_journal_replayed"]["actor"] = "operator"
        with self.assertRaises(ValueError):
            verify(record)

    def test_no_self_attested_incident_and_fencing(self):
        record = valid_record()
        record["attestations"]["incident_declared"]["actor"] = "operator"
        with self.assertRaises(ValueError):
            verify(record)

    def test_missing_receipt_and_wrong_role(self):
        record = valid_record()
        record["attestations"]["old_writer_fenced"]["evidence_ref"] = ""
        with self.assertRaises(ValueError):
            verify(record)
        record = valid_record()
        record["attestations"]["old_writer_fenced"]["role"] = "security"
        with self.assertRaises(ValueError):
            verify(record)


if __name__ == "__main__":
    unittest.main()
