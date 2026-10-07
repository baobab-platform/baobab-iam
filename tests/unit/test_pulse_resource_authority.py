"""P-CAP-07 Pulse resource-server authority configuration invariants."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLIENTS = ROOT / "config" / "clients"
SCOPES = ROOT / "config" / "scopes"

PULSE_SCOPES = {
    "intelligence:evidence:search",
    "intelligence:research-mission:manage",
    "intelligence:restricted",
}


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


def test_pulse_validator_has_context_validate_but_no_business_scope() -> None:
    client = load_json(CLIENTS / "baobab-pulse-workload.json")
    defaults = set(client["defaultClientScopes"])
    optionals = set(client["optionalClientScopes"])

    assert "context:resolve" in defaults
    assert "context:validate" in defaults
    assert defaults.isdisjoint(PULSE_SCOPES)
    assert optionals.isdisjoint(PULSE_SCOPES)


def test_pulse_resource_server_remains_bearer_only() -> None:
    client = load_json(CLIENTS / "baobab-pulse.json")
    assert client["bearerOnly"] is True
    assert client["serviceAccountsEnabled"] is False


def test_intelligence_scopes_all_target_only_pulse_audience() -> None:
    files = {
        "intelligence:evidence:search": SCOPES / "intelligence-evidence-search.json",
        "intelligence:research-mission:manage": SCOPES
        / "intelligence-research-mission-manage.json",
        "intelligence:restricted": SCOPES / "intelligence-restricted.json",
    }
    for name, path in files.items():
        scope = load_json(path)
        assert scope["name"] == name
        assert scope["attributes"]["include.in.token.scope"] == "true"
        mappers = scope["protocolMappers"]
        assert len(mappers) == 1
        assert mappers[0]["config"]["included.custom.audience"] == "baobab-pulse"
        assert mappers[0]["config"]["access.token.claim"] == "true"


def test_p_cap_07_does_not_silently_grant_intelligence_scopes_to_existing_clients() -> None:
    for path in CLIENTS.glob("*.json"):
        client = load_json(path)
        assigned = set(client.get("defaultClientScopes", [])) | set(
            client.get("optionalClientScopes", [])
        )
        leaked = assigned & PULSE_SCOPES
        assert not leaked, f"{path.name} unexpectedly receives {sorted(leaked)}"
