from pathlib import Path

from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app
from fyp_iam.contracts.models import AuthorizationEffect
from fyp_iam.engine2.records import (
    IdentityRecord,
    IdentityStatement,
    SyntheticAccount,
    TrustStatement,
)
from fyp_iam.fixtures.builders import assume_chain_rule
from fyp_iam.fixtures.cases import positive_case


def _client(fixture_dir: Path) -> TestClient:
    return TestClient(create_app(fixture_dir))


def test_health_reports_local_mode(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "local_fixtures"
    assert body["aws"] == "not_connected"
    assert body["engine1"] == "local_intake"
    assert body["engine2"] == "synthetic_normalizer"
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


def test_analysis_endpoint_scopes_one_identity_and_records_empty_result(fixture_dir: Path) -> None:
    case = positive_case()
    payload = {
        "rules": [rule.model_dump(mode="json", by_alias=True) for rule in case.rules],
        "snapshot": case.snapshot.model_dump(mode="json", by_alias=True),
        "evaluated_at": case.evaluated_at.isoformat().replace("+00:00", "Z"),
    }
    start_id = case.snapshot.nodes[0].node_id
    response = _client(fixture_dir).post(
        "/v1/analyses", json={**payload, "start_node_id": start_id}
    )
    assert response.status_code == 200
    assert response.json()["start_node_id"] == start_id
    assert all(path["start_node_id"] == start_id for path in response.json()["attack_paths"])

    empty = _client(fixture_dir).post(
        "/v1/analyses", json={**payload, "start_node_id": "principal:role/admin"}
    )
    assert empty.status_code == 200
    assert empty.json()["start_node_id"] == "principal:role/admin"
    assert empty.json()["attack_paths"] == []
    assert empty.json()["input_rule_refs"]
    assert empty.json()["input_rule_digest"].startswith("sha256:")

    missing = _client(fixture_dir).post(
        "/v1/analyses", json={**payload, "start_node_id": "principal:user/absent"}
    )
    assert missing.status_code == 422

    non_principal = _client(fixture_dir).post(
        "/v1/analyses", json={**payload, "start_node_id": "service:lambda.amazonaws.com"}
    )
    assert non_principal.status_code == 422


def test_fixture_endpoint_scopes_a_start_identity(fixture_dir: Path) -> None:
    response = _client(fixture_dir).post(
        "/v1/analyses/fixtures/credential_creation",
        params={"start_node_id": "principal:user/developer"},
    )
    assert response.status_code == 200
    assert response.json()["start_node_id"] == "principal:user/developer"
    assert len(response.json()["attack_paths"]) == 1

    missing = _client(fixture_dir).post(
        "/v1/analyses/fixtures/credential_creation",
        params={"start_node_id": "principal:user/absent"},
    )
    assert missing.status_code == 422


def test_local_analysis_api_rejects_real_account_input(fixture_dir: Path) -> None:
    case = positive_case()
    payload = case.snapshot.model_dump(mode="json", by_alias=True)
    payload["collection"]["permissions_profile"] = "real-read-only-account"
    response = _client(fixture_dir).post(
        "/v1/analyses",
        json={
            "rules": [rule.model_dump(mode="json", by_alias=True) for rule in case.rules],
            "snapshot": payload,
            "start_node_id": "principal:user/alice",
        },
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "local_fixture_only"


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


def test_synthetic_records_become_a_finding(fixture_dir: Path) -> None:
    account = SyntheticAccount(
        snapshot_id="snapshot_api_chain",
        identities=[
            IdentityRecord(
                node_id="principal:user/alice",
                display_name="alice",
                subtype="iam_user",
                identity_statements=[
                    IdentityStatement(
                        statement_id="stmt_alice_dev",
                        effect=AuthorizationEffect.allow,
                        actions=["sts:AssumeRole"],
                        resource_ids=["principal:role/dev"],
                    )
                ],
            ),
            IdentityRecord(
                node_id="principal:role/dev",
                display_name="dev",
                subtype="iam_role",
                identity_statements=[
                    IdentityStatement(
                        statement_id="stmt_dev_admin",
                        effect=AuthorizationEffect.allow,
                        actions=["sts:AssumeRole"],
                        resource_ids=["principal:role/admin"],
                    )
                ],
                trust_statements=[
                    TrustStatement(
                        statement_id="trust_dev_alice",
                        effect=AuthorizationEffect.allow,
                        actions=["sts:AssumeRole"],
                        principal_ids=["principal:user/alice"],
                    )
                ],
            ),
            IdentityRecord(
                node_id="principal:role/admin",
                display_name="admin",
                subtype="iam_role",
                trust_statements=[
                    TrustStatement(
                        statement_id="trust_admin_dev",
                        effect=AuthorizationEffect.allow,
                        actions=["sts:AssumeRole"],
                        principal_ids=["principal:role/dev"],
                    )
                ],
            ),
        ],
    )
    rule = assume_chain_rule("rule_api_synthetic")
    response = _client(fixture_dir).post(
        "/v1/analyses/synthetic",
        json={
            "rules": [rule.model_dump(mode="json", by_alias=True)],
            "account": account.model_dump(mode="json"),
            "start_node_id": "principal:user/alice",
            "evaluated_at": "2026-10-02T12:00:00Z",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assume = [edge for edge in body["snapshot"]["edges"] if edge["edge_type"] == "CAN_ASSUME"]
    assert len(assume) == 2
    assert body["report"]["findings"][0]["explanation"]["verification_status"] == (
        "supported_by_fixture"
    )
    assert body["report"]["verifications"][0]["policy_simulation"]["status"] == "not_run"
    assert body["report"]["start_node_id"] == "principal:user/alice"
    assert body["coverage"]["reconciled"] is True
    assert body["coverage"]["can_assume_count"] == 2
    assert body["coverage"]["permissions_boundary"] == "absent"
    assert body["coverage"]["service_control_policy"] == "not_collected"


def test_invalid_synthetic_account_is_rejected(fixture_dir: Path) -> None:
    response = _client(fixture_dir).post(
        "/v1/analyses/synthetic", json={"rules": [], "account": {}}
    )
    assert response.status_code == 422


def test_fixture_list_contains_the_seven_cases(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/v1/fixtures")
    assert response.status_code == 200
    assert response.json()["fixtures"] == [
        "condition_dependent",
        "credential_creation",
        "cyclic",
        "explicit_deny",
        "hard_negative",
        "missing_context",
        "positive",
    ]
