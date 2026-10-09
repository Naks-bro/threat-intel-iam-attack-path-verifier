from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

import fyp_iam.api.review_api as api
from fyp_iam.api.app import create_app
from fyp_iam.engine1.foundry.review import ReviewCommand, ReviewRecord, review_record_hash
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable


def command():
    digest = "sha256:" + "1" * 64
    return ReviewCommand(
        request_id="review_api_test",
        rule_version_id="version_test",
        rule_semantic_hash=digest,
        evidence_snapshot_hash=digest,
        quality_report_hash=digest,
        verifier_request_hash=digest,
        verifier_response_hash=digest,
        scope="read_only_account_analysis",
        decision="approved",
    )


def local_client(**options):
    app = create_app(
        database_url="postgresql+psycopg://localhost/fyp_iam",
        local_reviewer_alias="configured_operator",
        **options,
    )
    return TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 1234))


def test_review_is_disabled_by_default_and_in_preview():
    for app in (
        create_app(database_url=None),
        create_app(database_url=None, local_reviewer_alias="operator", foundry_preview=True),
    ):
        with TestClient(app) as client:
            response = client.post("/v1/foundry/reviews", json=command().model_dump())
            assert response.status_code == 503
            assert response.json() == {"detail": "local_review_disabled"}


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.invalid"},
        {"Origin": "null"},
        {"Host": "evil.invalid"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Forwarded-Proto": "http"},
    ],
)
def test_browser_rebinding_and_proxy_headers_cannot_enable_review(monkeypatch, headers):
    monkeypatch.setattr(
        api, "record_review", lambda *_: pytest.fail("Unsafe boundary reached storage")
    )
    with local_client() as client:
        response = client.post("/v1/foundry/reviews", json=command().model_dump(), headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "local_review_boundary_required"}


def test_nonloopback_peer_is_rejected():
    app = create_app(database_url="private-url", local_reviewer_alias="operator")
    with TestClient(app, base_url="http://localhost:8765", client=("192.0.2.1", 1234)) as client:
        assert client.post("/v1/foundry/reviews", json=command().model_dump()).status_code == 403


@pytest.mark.parametrize(
    "changes",
    [
        {"reviewer_alias": "browser_identity"},
        {"comment": "arn:aws:fixture_sensitive"},
        {"decision": "rejected"},
        {"scope": "write_to_live_aws"},
    ],
)
def test_review_validation_does_not_echo_inputs(monkeypatch, changes):
    monkeypatch.setattr(
        api, "record_review", lambda *_: pytest.fail("Invalid request reached storage")
    )
    with local_client() as client:
        response = client.post("/v1/foundry/reviews", json={**command().model_dump(), **changes})
    assert response.status_code == 422
    assert response.json() == {"detail": "review_request_invalid"}


def test_recorded_identity_is_operator_configuration_not_browser_input(monkeypatch):
    observed = []

    def persist(url, submitted, alias):
        observed.append((url, submitted, alias))
        draft = ReviewRecord.model_construct(
            decision_id="decision_test",
            command=submitted,
            reviewer_alias=alias,
            decided_at=datetime.now(UTC),
            record_hash="sha256:" + "0" * 64,
        )
        return ReviewRecord.model_validate(
            {**draft.model_dump(), "record_hash": review_record_hash(draft)}
        )

    monkeypatch.setattr(api, "record_review", persist)
    with local_client() as client:
        response = client.post(
            "/v1/foundry/reviews",
            json=command().model_dump(),
            headers={"Origin": "http://127.0.0.1:5173", "X-Request-ID": "review_trace"},
        )
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == "review_trace"
        record = ReviewRecord.model_validate(response.json())
        assert record.reviewer_alias == "configured_operator"
        assert record.identity_boundary == "local_operator_alias"
        monkeypatch.setattr(api, "review_state", lambda *_: record)
        state = client.get("/v1/foundry/rules/version_test/review?scope=read_only_account_analysis")
        assert state.status_code == 200
        assert state.json()["release_eligibility"] == "not_evaluated"
    assert observed[0][1] == command()
    assert observed[0][2] == "configured_operator"


@pytest.mark.parametrize(
    "failure,status,code",
    [
        (api.ReviewConflict("private input"), 409, "review_conflict"),
        (api.ReviewInProgress(), 409, "foundry_run_in_progress"),
        (DatabaseUnavailable("password=private"), 503, "database_unavailable"),
    ],
)
def test_review_failures_have_fixed_transport_codes(monkeypatch, failure, status, code):
    def failed(*_):
        raise failure

    monkeypatch.setattr(api, "record_review", failed)
    with local_client() as client:
        response = client.post("/v1/foundry/reviews", json=command().model_dump())
    assert response.status_code == status
    assert response.json() == {"detail": code}


def test_review_state_distinguishes_missing_rule_from_no_decision(monkeypatch):
    monkeypatch.setattr(api, "review_state", lambda *_: None)
    with local_client() as client:
        response = client.get("/v1/foundry/rules/version_test/review?scope=isolated_lab_validation")
        assert response.status_code == 200 and response.json()["latest"] is None

        def missing(*_):
            raise api.ReviewNotFound

        monkeypatch.setattr(api, "review_state", missing)
        assert (
            client.get(
                "/v1/foundry/rules/version_test/review?scope=synthetic_benchmark"
            ).status_code
            == 404
        )
        assert client.get("/v1/foundry/rules/version_test/review?scope=bad").json() == {
            "detail": "review_request_invalid"
        }


def test_enabled_operator_without_database_is_unavailable():
    app = create_app(database_url=None, local_reviewer_alias="operator")
    with TestClient(app, base_url="http://localhost:8765", client=("127.0.0.1", 1234)) as client:
        response = client.post("/v1/foundry/reviews", json=command().model_dump())
    assert response.status_code == 503 and response.json()["detail"] == "database_unavailable"


@pytest.mark.parametrize("alias", ["", "browser space", "AKIA" + "A" * 16])
def test_invalid_operator_configuration_is_rejected_without_echo(alias):
    with pytest.raises(ValueError) as failure:
        create_app(database_url=None, local_reviewer_alias=alias)
    assert str(failure.value) == "Invalid local review operator alias"


def test_local_entrypoint_reads_only_operator_process_configuration(monkeypatch):
    import fyp_iam.api.local_review_app as entrypoint

    seen = []
    monkeypatch.setattr(entrypoint, "create_app", lambda **options: seen.append(options))
    monkeypatch.setenv("FYP_LOCAL_REVIEWER_ALIAS", "configured_operator")
    entrypoint.create_local_review_app()
    monkeypatch.delenv("FYP_LOCAL_REVIEWER_ALIAS")
    entrypoint.create_local_review_app()
    assert seen == [{"local_reviewer_alias": "configured_operator"}, {"local_reviewer_alias": None}]


def test_openapi_documents_closed_input_and_actual_safe_error_contract():
    schema = create_app(database_url=None).openapi()
    command_schema = schema["components"]["schemas"]["ReviewCommand"]
    assert command_schema["additionalProperties"] is False
    assert "reviewer_alias" not in command_schema["properties"]
    responses = schema["paths"]["/v1/foundry/reviews"]["post"]["responses"]
    for code in ("403", "409", "422", "503"):
        assert responses[code]["content"]["application/json"]["schema"]["$ref"].endswith(
            "/ReviewAPIError"
        )
