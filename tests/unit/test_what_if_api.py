"""HTTP contract checks for the offline counterfactual preview."""

from pathlib import Path

from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app


def test_credential_what_if_returns_structural_delta(fixture_dir: Path) -> None:
    client = TestClient(create_app(fixture_dir, database_url=None, foundry_preview=True))
    response = client.post(
        "/v1/analyses/fixtures/credential_creation/what-if",
        json={"edge_id": "edge_developer_create_key"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["baseline_candidate_paths"] == 1
    assert body["hypothetical_candidate_paths"] == 0
    assert body["disappeared_candidate_paths"] == 1
    assert body["appeared_candidate_paths"] == 0
    assert body["comparison_complete"] is True
    assert body["original_snapshot_id"] != body["hypothetical_snapshot_id"]
    assert "not an AWS policy change" in body["limitation"]
    assert client.post("/v1/analyses/fixtures/credential_creation").json()["findings"]


def test_what_if_rejects_invalid_inputs(fixture_dir: Path) -> None:
    client = TestClient(create_app(fixture_dir, database_url=None, foundry_preview=True))
    path = "/v1/analyses/fixtures/credential_creation/what-if"
    assert client.post(path, json={"edge_id": "missing"}).status_code == 422
    assert client.post(path, json={"edge_id": "../escape"}).status_code == 422
    extra = client.post(path, json={"edge_id": "edge_developer_create_key", "extra": 1})
    assert extra.status_code == 422
    unknown = client.post("/v1/analyses/fixtures/unknown/what-if", json={"edge_id": "x"})
    assert unknown.status_code == 404
