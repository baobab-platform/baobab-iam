from __future__ import annotations

import json
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHARED_PIN = "c33d0bebd2ce8a5962ca6b3637409212239f4933"  # Shared #348 adds unassigned runtime read vocabulary; existing Pulse authority stays unchanged
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

    def test_federation_consumer_uses_the_exact_shared_registry_pin(self) -> None:
        # Static scope registration is ineffective if a compiled federation
        # consumer still validates against another immutable Shared revision.
        pin = yaml.safe_load((ROOT / "contracts.lock.yaml").read_text())["source"]["commit"]
        source = (ROOT / "internal/federation/consume.go").read_text()
        self.assertIn(f'const SharedCommit = "{pin}"', source)

    def test_documentary_restriction_scope_is_non_default_and_unallocated(self) -> None:
        # Definition is intentionally NOT client admission. Adding it to an
        # optional or default scope leaks the assessor capability to clients.
        definition = load_json("config/scopes/documentary-restriction-assess.json")
        self.assertEqual(definition["name"], "documentary:restriction-assess")
        self.assertLessEqual(len(definition["description"]), 255)
        self.assertEqual(definition["attributes"]["include.in.token.scope"], "true")
        self.assertEqual(len(definition["protocolMappers"]), 1)
        mapper = definition["protocolMappers"][0]
        self.assertEqual(mapper["protocolMapper"], "oidc-audience-mapper")
        self.assertEqual(mapper["config"]["included.custom.audience"], "baobab-control-plane")
        self.assertEqual(mapper["config"]["access.token.claim"], "true")
        self.assertEqual(mapper["config"]["id.token.claim"], "false")
        for path in sorted((ROOT / "config" / "clients").glob("*.json")):
            client = load_json(str(path.relative_to(ROOT)))
            allocated = set(client.get("defaultClientScopes", []))
            allocated.update(client.get("optionalClientScopes", []))
            with self.subTest(client=path.name):
                self.assertNotIn("documentary:restriction-assess", allocated)


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
