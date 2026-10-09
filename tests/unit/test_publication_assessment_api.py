from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import fyp_iam.api.review_api as api
import fyp_iam.engine1.foundry.publication_store as store
from fyp_iam.api.app import create_app
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable

ROUTE = "/v1/foundry/rules/version_test/publication-assessment"
PARAMS = {"scope": "read_only_account_analysis"}


@pytest.mark.parametrize(
    "failure,status,code",
    [
        (store.ReviewNotFound(), 404, "rule_not_found"),
        (store.ReviewInProgress(), 409, "foundry_run_in_progress"),
        (DatabaseUnavailable("private secret"), 503, "database_unavailable"),
    ],
)
def test_api_sanitizes_assessment_failures(monkeypatch, failure, status, code):
    def failed(*args, **kwargs):
        raise failure

    monkeypatch.setattr(api, "publication_assessment", failed)
    app = create_app(database_url="private-url", local_reviewer_alias="operator")
    with TestClient(app, base_url="http://localhost:8765", client=("127.0.0.1", 1234)) as client:
        response = client.get(ROUTE, params=PARAMS)
        assert response.status_code == status
        assert response.json() == {"detail": code}
        assert client.get(ROUTE, params={"scope": "bad"}).json() == {
            "detail": "review_request_invalid"
        }


def test_assessment_is_disabled_and_rejects_remote_origin_before_storage(monkeypatch):
    monkeypatch.setattr(
        api, "publication_assessment", lambda *a, **kw: pytest.fail("storage reached")
    )
    with TestClient(create_app(database_url=None)) as client:
        assert client.get(ROUTE, params=PARAMS).json() == {"detail": "local_review_disabled"}
    app = create_app(database_url="private-url", local_reviewer_alias="operator")
    with TestClient(app, base_url="http://localhost:8765", client=("127.0.0.1", 1234)) as client:
        assert (
            client.get(ROUTE, params=PARAMS, headers={"Origin": "https://evil.invalid"}).status_code
            == 403
        )


def test_repository_requires_lock_before_reading_any_assurance():
    session = MagicMock()
    session.scalar.return_value = False
    with pytest.raises(store.ReviewInProgress):
        store.read_assessment(session, "version_test", "synthetic_benchmark", "stable")
    session.get.assert_not_called()
    session.scalar.return_value = True
    session.get.return_value = None
    with pytest.raises(store.ReviewNotFound):
        store.read_assessment(session, "version_test", "synthetic_benchmark", "stable")
    session.add.assert_not_called()


def test_repository_driver_errors_are_redacted(monkeypatch):
    def failed(*a, **kw):
        raise RuntimeError("password=private")

    monkeypatch.setattr(store, "create_engine", failed)
    with pytest.raises(DatabaseUnavailable) as failure:
        store.publication_assessment("private-url", "version_test", "synthetic_benchmark", "stable")
    assert str(failure.value) == "Publication inputs could not be verified"
    assert failure.value.__suppress_context__


def test_openapi_assessment_cannot_claim_publication_or_export():
    schema = create_app(database_url=None).openapi()
    model = schema["components"]["schemas"]["PublicationAssessment"]
    assert model["additionalProperties"] is False
    for key in ("published", "export_available"):
        assert model["properties"][key]["const"] is False
