from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from fyp_iam.engine1.foundry.review import ReviewCommand, ReviewRecord, review_record_hash


def command(**changes):
    return ReviewCommand.model_validate(
        {
            "request_id": "review_test",
            "rule_version_id": "version_test",
            **dict.fromkeys(
                [
                    "rule_semantic_hash",
                    "evidence_snapshot_hash",
                    "quality_report_hash",
                    "verifier_request_hash",
                    "verifier_response_hash",
                ],
                "sha256:" + "1" * 64,
            ),
            "scope": "read_only_account_analysis",
            "decision": "approved",
            **changes,
        }
    )


@pytest.mark.parametrize("decision", ["rejected", "revision_requested"])
def test_nonapproval_requires_explanation(decision):
    with pytest.raises(ValidationError):
        command(decision=decision, comment="  ")
    assert command(decision=decision, comment="Needs context").comment == "Needs context"


@pytest.mark.parametrize(
    "changes",
    [
        {"scope": "write_to_live_aws"},
        {"decision": "published"},
        {"reviewer_alias": "caller_supplied"},
        {"comment": "arn:aws:fixture"},
        {"verifier_request_hash": "not-a-digest"},
        {"comment": "hidden\x00text"},
    ],
)
def test_review_contract_rejects_unsafe_or_unsupported_inputs(changes):
    with pytest.raises(ValidationError):
        command(**changes)


def test_record_is_hash_bound_and_has_explicit_alias_boundary():
    draft = ReviewRecord.model_construct(
        decision_id="decision_test",
        command=command(),
        reviewer_alias="operator_test",
        decided_at=datetime.now(UTC),
        record_hash="sha256:" + "0" * 64,
    )
    record = ReviewRecord.model_validate(
        {
            **draft.model_dump(),
            "record_hash": review_record_hash(draft),
        }
    )
    assert record.identity_boundary == "local_operator_alias"
    with pytest.raises(ValidationError):
        ReviewRecord.model_validate({**record.model_dump(), "reviewer_alias": "different"})
    with pytest.raises(ValidationError):
        ReviewRecord.model_validate({**record.model_dump(), "decided_at": datetime(2026, 10, 3)})
