import pytest
from fastapi.testclient import TestClient

import fyp_iam.api.review_api as api
from fyp_iam.api.app import create_app
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable


def command():
    return {
        "request_id": "release_request",
        "rule_version_id": "version_test",
        "scope": "synthetic_benchmark",
        "review_decision_id": "review_test",
        "review_record_hash": "sha256:" + "1" * 64,
    }


@pytest.mark.parametrize("operation", ["publish", "export"])
@pytest.mark.parametrize(
    "failure,status,code",
    [
        (api.ReleaseConflict(), 409, "release_conflict"),
        (api.ReviewInProgress(), 409, "foundry_run_in_progress"),
        (DatabaseUnavailable("private detail"), 503, "database_unavailable"),
    ],
)
def test_release_errors_are_fixed_not_raw_driver_outputs(
    monkeypatch, operation, failure, status, code
):
    def failed(*args):
        raise failure

    monkeypatch.setattr(
        api, "record_release" if operation == "publish" else "export_release", failed
    )
    app = create_app(database_url="private-url", local_reviewer_alias="operator")
    with TestClient(app, base_url="http://localhost:8765", client=("127.0.0.1", 1234)) as client:
        response = (
            client.post("/v1/foundry/releases", json=command())
            if operation == "publish"
            else client.get(
                "/v1/foundry/releases/release_test/export",
                params={"scope": "synthetic_benchmark"},
            )
        )
    assert response.status_code == status and response.json() == {"detail": code}


def test_release_mode_is_disabled_by_default_and_input_is_closed(monkeypatch):
    monkeypatch.setattr(api, "record_release", lambda *a: pytest.fail("unsafe storage call"))
    with TestClient(create_app(database_url=None)) as client:
        assert client.post("/v1/foundry/releases", json=command()).json() == {
            "detail": "local_review_disabled"
        }
    app = create_app(database_url="private-url", local_reviewer_alias="operator")
    with TestClient(app, base_url="http://localhost:8765", client=("127.0.0.1", 1234)) as client:
        assert client.post(
            "/v1/foundry/releases", json={**command(), "publisher_alias": "browser"}
        ).json() == {
            "detail": "review_request_invalid",
        }
        assert (
            client.post(
                "/v1/foundry/releases", json=command(), headers={"Origin": "https://evil.invalid"}
            ).status_code
            == 403
        )
        assert client.get(
            "/v1/foundry/releases/release_test/export", params={"scope": "invalid"}
        ).json() == {
            "detail": "review_request_invalid",
        }


def test_openapi_requires_exact_review_without_a_caller_approved_rule():
    schema = create_app(database_url=None).openapi()
    model = schema["components"]["schemas"]["StableReleaseCommand"]
    assert model["additionalProperties"] is False
    assert set(model["required"]) == {
        "request_id",
        "rule_version_id",
        "scope",
        "review_decision_id",
        "review_record_hash",
    }
    assert (
        schema["components"]["schemas"]["StableRuleRelease"]["properties"]["channel"]["const"]
        == "stable"
    )
