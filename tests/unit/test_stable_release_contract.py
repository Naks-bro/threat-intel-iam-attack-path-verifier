import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

import fyp_iam.engine1.foundry.release_store as store
from fyp_iam.contracts.models import (
    ApprovedRule,
    AuthorizationEffect,
    EdgeType,
    VerificationStatus,
)
from fyp_iam.contracts.releases import (
    StableReleaseCommand,
    StableRuleRelease,
    approval_comment,
    digest,
    release_hash,
)
from fyp_iam.engine1.foundry.models import RuleVersionRow
from fyp_iam.engine1.foundry.pipeline import build_foundry
from fyp_iam.engine3.releases import analyze_published_release
from fyp_iam.fixtures.builders import make_edge, make_snapshot, principal
from fyp_iam.fixtures.cases import positive_case


def sample_release():
    overview = build_foundry(persisted=False, storage="not_written")
    candidate = ApprovedRule.model_validate(overview["candidate"]["rule"])
    now = datetime.now(UTC)
    command = StableReleaseCommand(
        request_id="release_request",
        rule_version_id="version_test",
        scope="synthetic_benchmark",
        review_decision_id="review_test",
        review_record_hash="sha256:" + "1" * 64,
    )
    body = candidate.model_dump(mode="json")
    body.update(
        status="approved",
        approval={
            "decision": "approved",
            "reviewer_id": "operator",
            "decided_at": now.isoformat(),
            "comment": approval_comment(command),
        },
    )
    draft = StableRuleRelease.model_construct(
        release_id="release_test",
        command=command,
        rule_semantic_hash=digest(candidate.model_dump_json()),
        evidence_snapshot_hash="sha256:" + "2" * 64,
        quality_report_hash="sha256:" + "3" * 64,
        verifier_request_hash="sha256:" + "4" * 64,
        verifier_response_hash="sha256:" + "5" * 64,
        reviewer_alias="operator",
        publisher_alias="publisher",
        reviewed_at=now,
        published_at=now,
        candidate_json=candidate.model_dump_json(),
        rule_json=ApprovedRule.model_validate(body).model_dump_json(),
        record_hash="sha256:" + "0" * 64,
    )
    return StableRuleRelease.model_validate(
        {**draft.model_dump(), "record_hash": release_hash(draft)}
    )


def credential_snapshot(
    *,
    target_subtype: str = "iam_user",
    iam_action: str | None = "iam:CreateAccessKey",
    effect: AuthorizationEffect = AuthorizationEffect.allow,
    complete: bool = True,
):
    return make_snapshot(
        "snapshot_credentials",
        [
            principal("principal:operator", "operator", "iam_user"),
            principal("principal:target", "target", target_subtype),
        ],
        [
            make_edge(
                "edge_credentials",
                EdgeType.CAN_CREATE_AS,
                "principal:operator",
                "principal:target",
                "policy_credentials",
                iam_action=iam_action,
                effect=effect,
            )
        ],
        complete=complete,
    )


@pytest.mark.parametrize(
    ("target_subtype", "iam_action", "effect", "complete", "expected"),
    [
        (
            "iam_user",
            "iam:CreateAccessKey",
            AuthorizationEffect.allow,
            True,
            "supported_by_fixture",
        ),
        ("iam_user", "iam:CreateAccessKey", AuthorizationEffect.deny, True, "denied_by_fixture"),
        ("iam_user", "iam:CreateAccessKey", AuthorizationEffect.allow, False, "inconclusive"),
        ("iam_role", "iam:CreateAccessKey", AuthorizationEffect.allow, True, None),
        ("iam_user", "iam:CreateUser", AuthorizationEffect.allow, True, None),
        ("iam_user", None, AuthorizationEffect.allow, True, None),
    ],
)
def test_published_credential_rule_matches_only_action_bound_iam_users(
    target_subtype, iam_action, effect, complete, expected
):
    release = sample_release()
    report = analyze_published_release(
        release.release_id,
        credential_snapshot(
            target_subtype=target_subtype,
            iam_action=iam_action,
            effect=effect,
            complete=complete,
        ),
        scope="synthetic_benchmark",
        export_loader=lambda *_: release,
    )
    if expected is None:
        assert report.findings == []
        return
    assert len(report.findings) == len(report.verifications) == len(report.attack_paths) == 1
    assert report.verifications[0].status == VerificationStatus(expected)
    assert report.attack_paths[0].hops[0].required_action == "iam:CreateAccessKey"
    assert "policy_credentials" in report.findings[0].explanation.evidence
    assert report.findings[0].explanation.simulator == "not_run"


def test_stable_release_roundtrip_preserves_proposed_candidate():
    release = sample_release()
    assert StableRuleRelease.model_validate_json(release.model_dump_json()) == release
    assert json.loads(release.candidate_json)["status"] == "proposed"
    assert json.loads(release.rule_json)["status"] == "approved"


def prepared_store(monkeypatch):
    release = sample_release()
    version = RuleVersionRow(
        version_id=release.command.rule_version_id,
        semantic_hash=release.rule_semantic_hash,
        rule_json=release.candidate_json,
    )
    review = SimpleNamespace(
        reviewer_alias=release.reviewer_alias,
        decided_at=release.reviewed_at,
        command=SimpleNamespace(
            evidence_snapshot_hash=release.evidence_snapshot_hash,
            quality_report_hash=release.quality_report_hash,
            verifier_request_hash=release.verifier_request_hash,
            verifier_response_hash=release.verifier_response_hash,
        ),
    )
    monkeypatch.setattr(store, "_current", lambda *_: (version, review))
    session = MagicMock()
    session.scalar.return_value = True
    session.get.return_value = None
    return release, version, review, session


def test_append_release_retry_and_export_do_not_mutate_candidate(monkeypatch):
    release, version, _, session = prepared_store(monkeypatch)
    recorded = store.append_release(session, release.command, "publisher")
    row = session.add.call_args.args[0]
    assert store.decode_release(row) == recorded
    assert version.rule_json == release.candidate_json
    assert json.loads(version.rule_json)["status"] == "proposed"
    session.commit.assert_not_called()
    session.get.return_value = row
    assert store.append_release(session, release.command, "publisher") == recorded
    with pytest.raises(store.ReleaseConflict):
        store.append_release(session, release.command, "other_publisher")
    assert store.read_export(session, recorded.release_id, "synthetic_benchmark") == recorded
    with pytest.raises(store.ReleaseConflict):
        store.read_export(session, recorded.release_id, "read_only_account_analysis")
    row.scope = "isolated_lab_validation"
    with pytest.raises(ValueError):
        store.decode_release(row)


def test_release_refuses_busy_or_missing_and_ineligible_inputs(monkeypatch):
    release, _, _, session = prepared_store(monkeypatch)
    session.scalar.return_value = False
    with pytest.raises(store.ReviewInProgress):
        store.append_release(session, release.command, "publisher")
    session.get.assert_not_called()
    session.scalar.return_value = True
    with pytest.raises(store.ReleaseNotFound):
        store.read_export(session, "release_absent", "synthetic_benchmark")

    def blocked(*_):
        raise store.ReleaseConflict

    monkeypatch.setattr(store, "_current", blocked)
    with pytest.raises(store.ReleaseConflict):
        store.append_release(session, release.command, "publisher")
    session.add.assert_not_called()


@pytest.mark.parametrize("operation", ["record", "export"])
def test_release_wrapper_hides_driver_details(monkeypatch, operation):
    from fyp_iam.engine1.workbench.errors import DatabaseUnavailable

    def failed(*a, **kw):
        raise RuntimeError("password=private")

    monkeypatch.setattr(store, "create_engine", failed)
    with pytest.raises(DatabaseUnavailable) as failure:
        if operation == "record":
            store.record_release("private-url", sample_release().command, "publisher")
        else:
            store.export_release("private-url", "release_test", "synthetic_benchmark")
    assert "private" not in str(failure.value) and failure.value.__suppress_context__


def test_engine3_calls_current_exporter_on_every_analysis():
    release = sample_release()
    seen = []

    def loader(release_id, scope):
        seen.append((release_id, scope))
        return release

    for _ in range(2):
        result = analyze_published_release(
            release.release_id,
            positive_case().snapshot,
            scope="synthetic_benchmark",
            export_loader=loader,
        )
        assert result.snapshot_id == positive_case().snapshot.snapshot_id
    assert len(seen) == 2
    private_snapshot = positive_case().snapshot.model_copy(deep=True)
    private_snapshot.collection.permissions_profile = "real-read-only-account"
    with pytest.raises(ValueError, match="explicitly synthetic"):
        analyze_published_release(
            release.release_id,
            private_snapshot,
            scope="synthetic_benchmark",
            export_loader=loader,
        )
    with pytest.raises(ValueError, match="target mismatch"):
        analyze_published_release(
            release.release_id,
            positive_case().snapshot,
            scope="read_only_account_analysis",
            export_loader=loader,
        )
    bad = release.model_copy(update={"channel": "experimental"})
    with pytest.raises(ValidationError):
        analyze_published_release(
            bad.release_id,
            positive_case().snapshot,
            scope="synthetic_benchmark",
            export_loader=lambda *_: bad,
        )


@pytest.mark.parametrize(
    "case", ["quality_blocked", "missing_review", "changed_review_id", "changed_review_hash"]
)
def test_current_release_check_does_not_accept_old_approved_history(monkeypatch, case):
    release = sample_release()
    monkeypatch.setattr(
        store,
        "read_assessment",
        lambda *_: SimpleNamespace(
            eligible_for_publication=case != "quality_blocked",
        ),
    )
    review = SimpleNamespace(
        decision_id=release.command.review_decision_id,
        record_hash=release.command.review_record_hash,
    )
    if case == "changed_review_id":
        review.decision_id = "review_other"
    if case == "changed_review_hash":
        review.record_hash = "sha256:" + "9" * 64
    monkeypatch.setattr(
        store, "read_latest_review", lambda *_: None if case == "missing_review" else review
    )
    with pytest.raises(store.ReleaseConflict):
        store._current(MagicMock(), release.command)


@pytest.mark.parametrize(
    "field", ["candidate_json", "rule_json", "rule_semantic_hash", "record_hash"]
)
def test_modified_payload_without_new_identity_is_refused(field):
    release = sample_release()
    body = release.model_dump()
    if field.endswith("json"):
        rule = json.loads(body[field])
        rule["title"] = "Modified rule"
        body[field] = json.dumps(rule)
    else:
        body[field] = "sha256:" + "9" * 64
    with pytest.raises(ValidationError):
        StableRuleRelease.model_validate(body)


def test_rehashed_structural_mutation_or_real_scope_still_fails():
    release = sample_release()
    rule = json.loads(release.rule_json)
    rule["title"] = "Structural change after approval"
    for changes in (
        {"rule_json": ApprovedRule.model_validate(rule).model_dump_json()},
        {"command": release.command.model_copy(update={"scope": "read_only_account_analysis"})},
        {"channel": "experimental"},
    ):
        draft = release.model_copy(update=changes)
        with pytest.raises(ValidationError):
            StableRuleRelease.model_validate(
                {**draft.model_dump(), "record_hash": release_hash(draft)}
            )
