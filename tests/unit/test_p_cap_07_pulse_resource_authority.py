from __future__ import annotations

import json
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHARED_PIN = "70f92ee179888e9fd38e31ae9225060d76833944"  # FB-05 (shared#251): adds the staging evidence provisioner
PULSE_SCOPES = {
    "intelligence:evidence:search",
    "intelligence:research-mission:manage",
    "intelligence:restricted",
}


def load_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text())


class PulseResourceAuthorityTests(unittest.TestCase):
    def test_shared_authority_pin_and_pulse_validator_client(self) -> None:
        lock = yaml.safe_load((ROOT / "contracts.lock.yaml").read_text())
        self.assertEqual(lock["source"]["commit"], SHARED_PIN)

        validator = load_json("config/clients/baobab-pulse-workload.json")
        self.assertEqual(validator["clientId"], "baobab-pulse-workload")
        self.assertTrue(validator["serviceAccountsEnabled"])
        self.assertFalse(validator["bearerOnly"])
        self.assertIn("context:validate", validator["defaultClientScopes"])
        self.assertTrue(
            PULSE_SCOPES.isdisjoint(validator["defaultClientScopes"])
        )
        self.assertTrue(
            PULSE_SCOPES.isdisjoint(validator["optionalClientScopes"])
        )

    def test_pulse_resource_server_remains_bearer_only(self) -> None:
        resource = load_json("config/clients/baobab-pulse.json")
        self.assertEqual(resource["clientId"], "baobab-pulse")
        self.assertTrue(resource["bearerOnly"])
        self.assertFalse(resource["serviceAccountsEnabled"])
        self.assertFalse(resource["publicClient"])
        self.assertFalse(resource["directAccessGrantsEnabled"])
        self.assertFalse(resource["standardFlowEnabled"])

    def test_pulse_scopes_have_exact_resource_server_audience(self) -> None:
        paths = {
            "intelligence:evidence:search":
                "config/scopes/intelligence-evidence-search.json",
            "intelligence:research-mission:manage":
                "config/scopes/intelligence-research-mission-manage.json",
            "intelligence:restricted":
                "config/scopes/intelligence-restricted.json",
        }
        for expected_name, path in paths.items():
            with self.subTest(scope=expected_name):
                scope = load_json(path)
                self.assertEqual(scope["name"], expected_name)
                self.assertEqual(
                    scope["attributes"]["include.in.token.scope"],
                    "true",
                )
                mappers = scope["protocolMappers"]
                self.assertEqual(len(mappers), 1)
                mapper = mappers[0]
                self.assertEqual(
                    mapper["protocolMapper"],
                    "oidc-audience-mapper",
                )
                self.assertEqual(
                    mapper["config"]["included.custom.audience"],
                    "baobab-pulse",
                )
                self.assertEqual(
                    mapper["config"]["access.token.claim"],
                    "true",
                )

    def test_no_client_receives_intelligence_scope_implicitly(self) -> None:
        for path in sorted((ROOT / "config" / "clients").glob("*.json")):
            with self.subTest(client=path.name):
                client = json.loads(path.read_text())
                attached = set(client.get("defaultClientScopes", []))
                attached.update(client.get("optionalClientScopes", []))
                self.assertTrue(
                    PULSE_SCOPES.isdisjoint(attached),
                    (
                        f"{path.name} silently receives Pulse business authority: "
                        f"{sorted(PULSE_SCOPES & attached)}"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
