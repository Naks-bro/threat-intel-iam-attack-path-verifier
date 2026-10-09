"""Loopback review and redacted export for one paired observation."""

import pytest
from fastapi.testclient import TestClient
from tests.unit.test_paired_observation import _observe

from fyp_iam.api.app import create_app
from fyp_iam.engine2.paired_observation import PairedObservationReport
from fyp_iam.engine4.handoff_report import (
    AUTHORITY_LIMIT,
    HandoffDecision,
    HandoffReviewLedger,
    HandoffReviewRejected,
)

_EXPORT_KEYS = {
    "snapshot_digest",
    "rule_version",
    "reviewer_alias",
    "observed_facts",
    "inferences",
    "unknowns",
    "authority_limit",
}


def _report() -> PairedObservationReport:
    return _observe()


def _client(**options: object) -> TestClient:
    app = create_app(
        database_url=None,
        local_reviewer_alias="configured_operator",
        **options,
    )
    return TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 1234))


@pytest.mark.parametrize("decision", ["accept", "reject", "needs-context"])
def test_decision_exports_only_the_recorded_digest(decision: HandoffDecision) -> None:
    report = _report()
    ledger = HandoffReviewLedger()
    receipt = ledger.record(report, decision, "configured_operator")
    exported = ledger.export(report.report_digest)
    assert receipt.decision == decision
    assert receipt.report_digest == report.report_digest
    assert set(exported.model_dump()) == _EXPORT_KEYS
    assert exported.snapshot_digest == report.snapshot_digest
    assert exported.rule_version == report.rule_version
    assert exported.reviewer_alias == "configured_operator"
    assert exported.authority_limit == AUTHORITY_LIMIT
    assert exported.authority_limit.casefold() == (
        "local operator review is not authenticated authority and not exploit proof."
    )
    changed = "sha256:" + "ab" * 32
    with pytest.raises(HandoffReviewRejected, match="^report_digest_rejected$"):
        ledger.export(changed)


def test_changed_report_digest_is_not_stored() -> None:
    report = _report().model_copy(update={"report_digest": "sha256:" + "cd" * 32})
    ledger = HandoffReviewLedger()
    with pytest.raises(HandoffReviewRejected, match="^report_digest_rejected$"):
        ledger.record(report, "accept", "configured_operator")
    with pytest.raises(HandoffReviewRejected, match="^report_digest_rejected$"):
        ledger.export(report.report_digest)


def test_nonloopback_host_is_refused_without_echoing_sensitive_body() -> None:
    app = create_app(database_url=None, local_reviewer_alias="configured_operator")
    poisoned = {
        "account": "123456789012",
        "principal": "arn:aws:iam::123456789012:user/Example",
        "policy": {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]
            }
        },
    }
    with TestClient(app, base_url="http://127.0.0.1:8765", client=("192.0.2.1", 1234)) as client:
        response = client.post("/v1/handoff/reviews", json=poisoned)
    assert response.status_code == 403
    assert response.json() == {"detail": "local_review_boundary_required"}
    body = response.text
    assert "arn:aws" not in body
    assert "123456789012" not in body
    assert "PolicyDocument" not in body
    assert "iam:*" not in body


def test_loopback_export_uses_the_configured_alias_and_rejects_a_changed_digest() -> None:
    report = _report()
    forged = report.model_copy(update={"report_digest": "sha256:" + "ef" * 32})
    with _client() as client:
        rejected = client.post(
            "/v1/handoff/reviews",
            json={"report": forged.model_dump(mode="json"), "decision": "accept"},
        )
        assert rejected.status_code == 409
        assert rejected.json() == {"detail": "report_digest_rejected"}
        recorded = client.post(
            "/v1/handoff/reviews",
            json={"report": report.model_dump(mode="json"), "decision": "needs-context"},
            headers={"Origin": "http://127.0.0.1:5173"},
        )
        assert recorded.status_code == 200
        assert recorded.json()["reviewer_alias"] == "configured_operator"
        assert recorded.json()["decision"] == "needs-context"
        exported = client.get(f"/v1/handoff/reviews/{report.report_digest}/export")
        assert exported.status_code == 200
        payload = exported.json()
        assert set(payload) == _EXPORT_KEYS
        assert payload["authority_limit"] == AUTHORITY_LIMIT
        assert "arn:aws" not in exported.text
        changed = client.get("/v1/handoff/reviews/" + ("sha256:" + "11" * 32) + "/export")
        assert changed.status_code == 409
        assert changed.json() == {"detail": "report_digest_rejected"}
        assert report.report_digest not in changed.text
