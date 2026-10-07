from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SHARED_PIN = "363e0ead9ebb5aa87f5f813b63b785b7f63cc39e"
PULSE_SCOPES = {
    "intelligence:evidence:search",
    "intelligence:research-mission:manage",
    "intelligence:restricted",
}


def _json(path: str) -> dict:
    return json.loads((ROOT / path).read_text())


def test_p_cap_07_shared_authority_pin_and_pulse_validator_client() -> None:
    lock = yaml.safe_load((ROOT / "contracts.lock.yaml").read_text())
    assert lock["source"]["commit"] == SHARED_PIN

    validator = _json("config/clients/baobab-pulse-workload.json")
    assert validator["clientId"] == "baobab-pulse-workload"
    assert validator["serviceAccountsEnabled"] is True
    assert validator["bearerOnly"] is False
    assert "context:validate" in validator["defaultClientScopes"]
    assert PULSE_SCOPES.isdisjoint(validator["defaultClientScopes"])
    assert PULSE_SCOPES.isdisjoint(validator["optionalClientScopes"])


def test_pulse_resource_server_remains_bearer_only() -> None:
    resource = _json("config/clients/baobab-pulse.json")
    assert resource["clientId"] == "baobab-pulse"
    assert resource["bearerOnly"] is True
    assert resource["serviceAccountsEnabled"] is False
    assert resource["publicClient"] is False
    assert resource["directAccessGrantsEnabled"] is False
    assert resource["standardFlowEnabled"] is False


def test_pulse_scopes_have_exact_resource_server_audience() -> None:
    paths = {
        "intelligence:evidence:search":
            "config/scopes/intelligence-evidence-search.json",
        "intelligence:research-mission:manage":
            "config/scopes/intelligence-research-mission-manage.json",
        "intelligence:restricted":
            "config/scopes/intelligence-restricted.json",
    }
    for expected_name, path in paths.items():
        scope = _json(path)
        assert scope["name"] == expected_name
        assert scope["attributes"]["include.in.token.scope"] == "true"
        mappers = scope["protocolMappers"]
        assert len(mappers) == 1
        mapper = mappers[0]
        assert mapper["protocolMapper"] == "oidc-audience-mapper"
        assert mapper["config"]["included.custom.audience"] == "baobab-pulse"
        assert mapper["config"]["access.token.claim"] == "true"


def test_p_cap_07_does_not_auto_grant_intelligence_scopes_to_any_client() -> None:
    for path in sorted((ROOT / "config" / "clients").glob("*.json")):
        client = json.loads(path.read_text())
        attached = set(client.get("defaultClientScopes", []))
        attached.update(client.get("optionalClientScopes", []))
        assert PULSE_SCOPES.isdisjoint(attached), (
            f"{path.name} silently receives Pulse business authority: "
            f"{sorted(PULSE_SCOPES & attached)}"
        )
