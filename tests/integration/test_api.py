from pathlib import Path

from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app
from fyp_iam.fixtures.cases import positive_case


def _client(fixture_dir: Path) -> TestClient:
    return TestClient(create_app(fixture_dir))


def test_health_reports_local_mode(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "local_fixtures"
    assert body["aws"] == "not_connected"
    assert body["neo4j"] == "not_connected"


def test_analysis_endpoint_returns_a_fixture_finding(fixture_dir: Path) -> None:
    case = positive_case()
    response = _client(fixture_dir).post(
        "/v1/analyses",
        json={
            "rules": [rule.model_dump(mode="json", by_alias=True) for rule in case.rules],
            "snapshot": case.snapshot.model_dump(mode="json", by_alias=True),
            "evaluated_at": case.evaluated_at.isoformat().replace("+00:00", "Z"),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["findings"][0]["explanation"]["verification_status"] == "supported_by_fixture"
    assert body["verifications"][0]["policy_simulation"]["status"] == "not_run"
    assert body["verifications"][0]["sandbox"]["status"] == "not_mapped"


def test_fixture_endpoint_loads_the_positive_case(fixture_dir: Path) -> None:
    response = _client(fixture_dir).post("/v1/analyses/fixtures/positive")
    assert response.status_code == 200
    assert response.json()["findings"][0]["priority"] == "high"


def test_invalid_payload_is_rejected(fixture_dir: Path) -> None:
    response = _client(fixture_dir).post("/v1/analyses", json={"rules": [], "snapshot": {}})
    assert response.status_code == 422


def test_fixture_names_cannot_escape_the_directory(fixture_dir: Path) -> None:
    client = _client(fixture_dir)
    assert client.post("/v1/analyses/fixtures/NotAllowed").status_code == 400
    assert client.post("/v1/analyses/fixtures/not_a_case").status_code == 404


def test_fixture_list_contains_the_six_cases(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/v1/fixtures")
    assert response.status_code == 200
    assert response.json()["fixtures"] == [
        "condition_dependent",
        "cyclic",
        "explicit_deny",
        "hard_negative",
        "missing_context",
        "positive",
    ]
