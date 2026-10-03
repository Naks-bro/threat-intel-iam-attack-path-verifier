"""Offline preview is explicit, isolated from the configured database and read-only."""

from fastapi.testclient import TestClient
from pytest import MonkeyPatch

from fyp_iam.api.app import create_app
from fyp_iam.api.schemas import FoundryOverviewResponse, FoundryRuleResponse


def test_preview_is_valid_and_non_persistent(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("FYP_DATABASE_URL", "postgresql+psycopg://invalid:invalid@invalid/postgres")
    monkeypatch.setattr(
        "fyp_iam.api.app.persist_foundry",
        lambda _url: (_ for _ in ()).throw(AssertionError("database write attempted")),
    )
    client = TestClient(create_app(foundry_preview=True))
    assert client.get("/health").json()["mode"] == "foundry_preview"
    response = client.get("/v1/foundry/overview")
    assert response.status_code == 200
    overview = FoundryOverviewResponse.model_validate(response.json())
    assert overview.storage == "preview"
    assert overview.database == "not_connected"
    assert len(overview.candidates) == 1
    assert overview.candidates[0].channel == "preview_only"
    rule_response = client.get(f"/v1/foundry/rules/{overview.candidates[0].version_id}")
    rule = FoundryRuleResponse.model_validate(rule_response.json())
    assert rule.publication is None
    assert len(rule.scenarios) == 6
    required = [item for item in rule.validations if not item.optional]
    optional = [item for item in rule.validations if item.optional]
    assert len(required) == 10
    assert all(item.result == "pass" for item in required)
    assert len(optional) == 4
    assert all(item.result == "unavailable" for item in optional)
    assert next(item for item in required if item.validator_name == "condition_keys").findings == [
        "This candidate declares no condition key"
    ]
    recomputed = client.post("/v1/foundry/runs")
    assert recomputed.status_code == 200
    assert recomputed.json()["storage"] == "preview"
    assert client.get("/v1/foundry/rules/unknown").status_code == 404


def test_normal_app_without_database_does_not_serve_preview() -> None:
    client = TestClient(create_app(database_url=None))
    assert client.get("/v1/foundry/overview").json()["registry"] == "unavailable"
    assert client.post("/v1/foundry/runs").status_code == 503
