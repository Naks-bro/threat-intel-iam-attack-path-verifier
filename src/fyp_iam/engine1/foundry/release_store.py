"""Transactional stable creation and current-input export, never AWS execution."""

from datetime import UTC, datetime

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from fyp_iam.contracts.models import ApprovedRule
from fyp_iam.contracts.releases import (
    ReleaseScope,
    StableReleaseCommand,
    StableRuleRelease,
    approval_comment,
    release_hash,
)
from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.foundry.models import RuleVersionRow, StableReleaseRow
from fyp_iam.engine1.foundry.publication_store import read_assessment
from fyp_iam.engine1.foundry.review import ReviewRecord
from fyp_iam.engine1.foundry.review_store import (
    ReviewInProgress,
    ReviewNotFound,
    read_latest_review,
)
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable


class ReleaseConflict(Exception):
    """Release input is stale, ineligible or the idempotency key conflicts."""


class ReleaseNotFound(Exception):
    """No durable scoped stable release exists with this id."""


def decode_release(row: StableReleaseRow) -> StableRuleRelease:
    release = StableRuleRelease.model_validate_json(row.record_json)
    if (
        release.release_id != row.release_id
        or release.command.request_id != row.request_id
        or release.command.rule_version_id != row.rule_version_id
        or release.command.review_decision_id != row.review_decision_id
        or release.command.scope != row.scope
        or release.record_hash != row.record_hash
        or release.published_at != row.published_at
    ):
        raise ValueError("Stored stable release binding mismatch")
    return release


def _current(
    session: Session, command: StableReleaseCommand
) -> tuple[RuleVersionRow, ReviewRecord]:
    assessment = read_assessment(session, command.rule_version_id, command.scope, "stable")
    review = read_latest_review(session, command.rule_version_id, command.scope)
    if (
        not assessment.eligible_for_publication
        or review is None
        or review.decision_id != command.review_decision_id
        or review.record_hash != command.review_record_hash
    ):
        raise ReleaseConflict
    version = session.get(RuleVersionRow, command.rule_version_id)
    if version is None:
        raise ReviewNotFound
    return version, review


def append_release(
    session: Session, command: StableReleaseCommand, alias: str
) -> StableRuleRelease:
    command = StableReleaseCommand.model_validate_json(command.model_dump_json())
    if not session.scalar(select(func.pg_try_advisory_xact_lock(349812, 1))):
        raise ReviewInProgress
    release_id = stable_id("release", command.request_id)
    existing = session.get(StableReleaseRow, release_id)
    if existing is not None:
        prior = decode_release(existing)
        if prior.command != command or prior.publisher_alias != alias:
            raise ReleaseConflict
        # Returning archival idempotent history is not an export eligibility verdict.
        return prior
    version, review = _current(session, command)
    candidate = ApprovedRule.model_validate_json(version.rule_json)
    body = candidate.model_dump(mode="json")
    body.update(
        status="approved",
        approval={
            "decision": "approved",
            "reviewer_id": review.reviewer_alias,
            "decided_at": review.decided_at.isoformat(),
            "comment": approval_comment(command),
        },
    )
    draft = StableRuleRelease.model_construct(
        release_id=release_id,
        command=command,
        rule_semantic_hash=version.semantic_hash,
        evidence_snapshot_hash=review.command.evidence_snapshot_hash,
        quality_report_hash=review.command.quality_report_hash,
        verifier_request_hash=review.command.verifier_request_hash,
        verifier_response_hash=review.command.verifier_response_hash,
        reviewer_alias=review.reviewer_alias,
        publisher_alias=alias,
        reviewed_at=review.decided_at,
        published_at=datetime.now(UTC),
        candidate_json=candidate.model_dump_json(),
        rule_json=ApprovedRule.model_validate(body).model_dump_json(),
        record_hash="sha256:" + "0" * 64,
    )
    release = StableRuleRelease.model_validate(
        {**draft.model_dump(), "record_hash": release_hash(draft)}
    )
    session.add(
        StableReleaseRow(
            release_id=release.release_id,
            request_id=command.request_id,
            rule_version_id=command.rule_version_id,
            review_decision_id=command.review_decision_id,
            scope=command.scope,
            record_json=release.model_dump_json(),
            record_hash=release.record_hash,
            published_at=release.published_at,
        )
    )
    session.flush()
    return release


def read_export(session: Session, release_id: str, scope: ReleaseScope) -> StableRuleRelease:
    row = session.get(StableReleaseRow, release_id)
    if row is None:
        raise ReleaseNotFound
    release = decode_release(row)
    if release.command.scope != scope:
        raise ReleaseConflict
    version, review = _current(session, release.command)
    if (
        release.candidate_json
        != ApprovedRule.model_validate_json(version.rule_json).model_dump_json()
        or release.rule_semantic_hash != version.semantic_hash
        or release.evidence_snapshot_hash != review.command.evidence_snapshot_hash
        or release.quality_report_hash != review.command.quality_report_hash
        or release.verifier_request_hash != review.command.verifier_request_hash
        or release.verifier_response_hash != review.command.verifier_response_hash
        or release.reviewer_alias != review.reviewer_alias
        or release.reviewed_at != review.decided_at
    ):
        raise ValueError("Stored stable release assurance mismatch")
    return release


def record_release(url: str, command: StableReleaseCommand, alias: str) -> StableRuleRelease:
    engine = None
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with Session(engine) as session, session.begin():
            return append_release(session, command, alias)
    except (ReleaseConflict, ReviewInProgress, ReviewNotFound):
        raise
    except Exception:
        raise DatabaseUnavailable("PostgreSQL did not commit the stable release") from None
    finally:
        if engine is not None:
            engine.dispose()


def export_release(url: str, release_id: str, scope: ReleaseScope) -> StableRuleRelease:
    engine = None
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with Session(engine) as session, session.begin():
            return read_export(session, release_id, scope)
    except (ReleaseConflict, ReleaseNotFound, ReviewInProgress, ReviewNotFound):
        raise
    except Exception:
        raise DatabaseUnavailable("Stable release export could not be verified") from None
    finally:
        if engine is not None:
            engine.dispose()
