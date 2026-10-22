"""Exact accepted INT-03C native proof plan; no credential issuance."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

MODULE=Path(__file__).resolve().parents[2]/"scripts/int03c_native_fixture.py"
spec=importlib.util.spec_from_file_location("int03c_native_fixture",MODULE)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Governed(unittest.TestCase):
    def rows(self):
        return dict(mod.EXPECTED)

    def test_exact_two_clients_and_no_cms_authority(self):
        plan=mod.make_plan(self.rows())
        self.assertFalse(plan["identities_created"])
        self.assertFalse(plan["qualified"])
        self.assertEqual(len(plan["provisioning_specs"]),2)
        self.assertEqual({s["logical_client_id"] for s in plan["provisioning_specs"]},
                         {mod.OWNER,mod.VERIFIER})
        for row in plan["provisioning_specs"]:
            self.assertEqual(row["allowed_scopes"],["context:resolve"])
            self.assertEqual(row["audiences"],["baobab-control-plane"])
            self.assertTrue(row["require_new"])
            self.assertEqual(row["access_token_ttl_seconds"],60)

    def test_extra_scope_or_wrong_environment_denied(self):
        for change in ({"allowed_scopes":["context:validate"]},
                       {"environment":"production"},
                       {"allowed_audiences":["baobab-cms"]},
                       {"status":"PROVISIONED"}):
            rows=self.rows()
            rows[mod.OWNER]=dict(rows[mod.OWNER],**change)
            with self.assertRaises(ValueError):
                mod.make_plan(rows)

    def test_exact_committed_shared_revision_is_required(self):
        import subprocess
        with patch.object(mod.subprocess,"run",side_effect=subprocess.CalledProcessError(1,"git")):
            with self.assertRaises(subprocess.CalledProcessError):
                mod.committed_registry(Path(__file__).resolve().parents[2])


if __name__=="__main__":
    unittest.main()
