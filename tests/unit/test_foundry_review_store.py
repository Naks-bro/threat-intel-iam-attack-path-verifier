from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import fyp_iam.engine1.foundry.review_store as store
from fyp_iam.engine1.foundry.models import RuleVersionRow, ScopedReviewRow
from fyp_iam.engine1.foundry.review import ReviewCommand


def prepared(monkeypatch):
    digest = "sha256:" + "1" * 64
    command = ReviewCommand(
        request_id="review_test",
        rule_version_id="version_test",
        rule_semantic_hash=digest,
        evidence_snapshot_hash=digest,
        quality_report_hash=digest,
        verifier_request_hash=digest,
        verifier_response_hash=digest,
        scope="read_only_account_analysis",
        decision="approved",
    )
    version = RuleVersionRow(version_id="version_test", semantic_hash=digest)
    quality = SimpleNamespace(evidence_snapshot_hash=digest, report_hash=digest)
    verifier = SimpleNamespace(
        evidence_snapshot_hash=digest, request_hash=digest, response_hash=digest
    )
    monkeypatch.setattr(store, "read_latest_quality_report", lambda *_: quality)
    monkeypatch.setattr(store, "read_latest_verifier_summary", lambda *_: verifier)
    session = MagicMock()
    session.scalar.return_value = True
    session.get.side_effect = [None, version]
    return session, command


def test_append_and_retry_are_immutable_without_implicit_commit(monkeypatch):
    session, command = prepared(monkeypatch)
    record = store.append_review(session, command, "operator_test")
    row = session.add.call_args.args[0]
    assert isinstance(row, ScopedReviewRow)
    assert store.decode_review(row) == record
    session.commit.assert_not_called()
    session.get.side_effect = None
    session.get.return_value = row
    session.reset_mock()
    assert store.append_review(session, command, "operator_test") == record
    session.add.assert_not_called()
    with pytest.raises(store.ReviewConflict):
        store.append_review(session, command, "different_operator")


@pytest.mark.parametrize(
    "field",
    [
        "rule_version_id",
        "rule_semantic_hash",
        "evidence_snapshot_hash",
        "quality_report_hash",
        "verifier_request_hash",
        "verifier_response_hash",
    ],
)
def test_stale_review_is_not_added(monkeypatch, field):
    session, command = prepared(monkeypatch)
    value = "other_version" if field == "rule_version_id" else "sha256:" + "2" * 64
    command = command.model_copy(update={field: value})
    # A different requested version must not resolve to the prepared version.
    if field == "rule_version_id":
        session.get.side_effect = [None, None]
    with pytest.raises(store.ReviewConflict):
        store.append_review(session, command, "operator_test")
    session.add.assert_not_called()


@pytest.mark.parametrize("reader", ["read_latest_quality_report", "read_latest_verifier_summary"])
def test_missing_assurance_cannot_be_reviewed(monkeypatch, reader):
    session, command = prepared(monkeypatch)
    monkeypatch.setattr(store, reader, lambda *_: None)
    with pytest.raises(store.ReviewConflict):
        store.append_review(session, command, "operator_test")
    session.add.assert_not_called()


def test_busy_lock_and_tampered_record_fail_closed(monkeypatch):
    session, command = prepared(monkeypatch)
    session.scalar.return_value = False
    with pytest.raises(store.ReviewInProgress):
        store.append_review(session, command, "operator_test")
    session.get.assert_not_called()
    session.scalar.return_value = True
    store.append_review(session, command, "operator_test")
    row = session.add.call_args.args[0]
    row.scope = "isolated_lab_validation"
    with pytest.raises(ValueError, match="binding mismatch"):
        store.decode_review(row)


@pytest.mark.parametrize("operation", ["record", "read"])
def test_transaction_wrapper_suppresses_driver_details(monkeypatch, operation):
    from fyp_iam.engine1.workbench.errors import DatabaseUnavailable

    def failed(*_args, **_kwargs):
        raise RuntimeError("driver password=fixture_secret")

    session, command = prepared(monkeypatch)
    monkeypatch.setattr(store, "create_engine", failed)
    with pytest.raises(DatabaseUnavailable) as failure:
        if operation == "record":
            store.record_review("private-url", command, "operator_test")
        else:
            store.review_state("private-url", command.rule_version_id, command.scope)
    assert "fixture_secret" not in str(failure.value)
    assert failure.value.__suppress_context__
