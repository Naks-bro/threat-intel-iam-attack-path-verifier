import asyncio
from datetime import UTC, datetime
from itertools import product

import pytest

from fyp_iam.engine1.foundry.adapters import assemble_snapshot
from fyp_iam.engine1.foundry.publication import assess_publication
from fyp_iam.engine1.foundry.quality import build_quality_report
from fyp_iam.engine1.foundry.review import ReviewCommand, ReviewRecord, review_record_hash
from fyp_iam.engine1.foundry.verifier_models import VerifierRecordSummary
from fyp_iam.engine1.foundry.verifier_pipeline import compile_verified_snapshot


@pytest.fixture(scope="module")
def assurance():
    result = asyncio.run(compile_verified_snapshot(assemble_snapshot()))
    candidate, ai = result["candidate"], result["ai_verification"]
    quality = build_quality_report(candidate, result["validations"])
    verifier = VerifierRecordSummary(
        packet_id="packet_test",
        pipeline_run_id="pipeline_test",
        recorded_at=datetime.now(UTC),
        rule_version_id=quality.rule_version_id,
        rule_semantic_hash=quality.rule_semantic_hash,
        evidence_snapshot_hash=quality.evidence_snapshot_hash,
        request_hash=ai["request_hash"],
        response_hash=ai["response_hash"],
        provider=ai["provider"],
        model=ai["model"],
        prompt_version=ai["prompt_version"],
        ontology_version="test",
        verdict=ai["verdict"],
        findings=ai["findings"],
        citations=["evidence_test"],
        evidence=[
            {
                "evidence_id": "evidence_test",
                "source_key": "mitre-attack",
                "source_version": "test",
                "content_hash": "sha256:" + "1" * 64,
            }
        ],
    )
    return candidate, result["validations"], quality, verifier


def reviewed(quality, verifier, decision="approved", scope="synthetic_benchmark", **changes):
    command = ReviewCommand.model_validate(
        {
            "request_id": "review_test",
            "rule_version_id": quality.rule_version_id,
            "rule_semantic_hash": quality.rule_semantic_hash,
            "evidence_snapshot_hash": quality.evidence_snapshot_hash,
            "quality_report_hash": quality.report_hash,
            "verifier_request_hash": verifier.request_hash,
            "verifier_response_hash": verifier.response_hash,
            "scope": scope,
            "decision": decision,
            "comment": "Test decision only",
            **changes,
        }
    )
    draft = ReviewRecord.model_construct(
        decision_id="decision_test",
        command=command,
        reviewer_alias="test_operator",
        decided_at=datetime.now(UTC),
        record_hash="sha256:" + "0" * 64,
    )
    return ReviewRecord.model_validate(
        {**draft.model_dump(), "record_hash": review_record_hash(draft)}
    )


@pytest.mark.parametrize(
    "quality_pass,verdict,decision,channel",
    list(
        product(
            [True, False],
            ["pass", "needs_review", "reject"],
            [None, "approved", "rejected", "revision_requested"],
            ["stable", "experimental"],
        )
    ),
)
def test_quality_verifier_review_channel_matrix(
    assurance, quality_pass, verdict, decision, channel
):
    candidate, rows, quality, verifier = assurance
    verifier = verifier.model_copy(update={"verdict": verdict})
    if not quality_pass:
        rows = [
            {**row, "result": "skipped"} if row["validator_name"] == "ontology" else row
            for row in rows
        ]
        quality = build_quality_report(candidate, rows)
    review = reviewed(quality, verifier, decision) if decision else None
    result = assess_publication(
        version_id=quality.rule_version_id,
        semantic_hash=quality.rule_semantic_hash,
        scope="synthetic_benchmark",
        channel=channel,
        quality=quality,
        verifier=verifier,
        review=review,
        allow_experimental=True,
    )
    expected = (
        quality_pass
        and verdict == "pass"
        and (decision == "approved" or (channel == "experimental" and decision is None))
    )
    assert result.eligible_for_publication == expected
    assert not result.published and not result.export_available


@pytest.mark.parametrize(
    "field",
    [
        "rule_version_id",
        "rule_semantic_hash",
        "evidence_snapshot_hash",
        "quality_report_hash",
        "verifier_request_hash",
        "verifier_response_hash",
        "scope",
    ],
)
def test_stale_or_wrong_scope_approval_never_allows_publication(assurance, field):
    _, _, quality, verifier = assurance
    value = "other_version" if field == "rule_version_id" else "sha256:" + "2" * 64
    if field == "scope":
        value = "read_only_account_analysis"
    result = assess_publication(
        version_id=quality.rule_version_id,
        semantic_hash=quality.rule_semantic_hash,
        scope="synthetic_benchmark",
        channel="stable",
        quality=quality,
        verifier=verifier,
        review=reviewed(quality, verifier, **{field: value}),
    )
    assert "review_binding_mismatch" in result.blockers
    assert not result.eligible_for_publication


@pytest.mark.parametrize("scope", ["read_only_account_analysis", "isolated_lab_validation"])
def test_fake_or_renamed_provider_cannot_enable_real_scope(assurance, scope):
    _, _, quality, verifier = assurance
    for provider in ("fake", "claimed_real_provider"):
        record = verifier.model_copy(update={"provider": provider})
        result = assess_publication(
            version_id=quality.rule_version_id,
            semantic_hash=quality.rule_semantic_hash,
            scope=scope,
            channel="stable",
            quality=quality,
            verifier=record,
            review=reviewed(quality, record, scope=scope),
        )
        assert "verifier_policy_unconfigured" in result.blockers
        assert not result.eligible_for_publication


def test_missing_inputs_and_default_experimental_refusal(assurance):
    _, _, quality, _ = assurance
    result = assess_publication(
        version_id=quality.rule_version_id,
        semantic_hash=quality.rule_semantic_hash,
        scope="synthetic_benchmark",
        channel="experimental",
        quality=None,
        verifier=None,
        review=None,
    )
    assert result.blockers == ("quality_missing", "verifier_missing", "experimental_not_opted_in")
