"""Append-only scoped review operations inside a caller-owned transaction."""

from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.foundry.models import RuleVersionRow, ScopedReviewRow
from fyp_iam.engine1.foundry.quality_store import read_latest_quality_report
from fyp_iam.engine1.foundry.review import (
    ReviewCommand,
    ReviewRecord,
    ReviewScope,
    review_record_hash,
)
from fyp_iam.engine1.foundry.verifier_store import read_latest_verifier_summary
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable


class ReviewConflict(Exception):
    """An idempotency key or reviewed input no longer matches."""


class ReviewInProgress(Exception):
    """A foundry pipeline/review transaction already owns the shared lock."""


class ReviewNotFound(Exception):
    """The requested rule has no stored immutable version."""


def decode_review(row: ScopedReviewRow) -> ReviewRecord:
    try:
        record = ReviewRecord.model_validate_json(row.record_json)
    except ValidationError:
        raise ValueError("Stored review record is invalid") from None
    if (
        record.decision_id != row.decision_id
        or record.command.request_id != row.request_id
        or record.command.rule_version_id != row.rule_version_id
        or record.command.scope != row.scope
        or record.record_hash != row.record_hash
        or record.decided_at != row.decided_at
    ):
        raise ValueError("Stored review record binding mismatch")
    return record


def append_review(session: Session, command: ReviewCommand, reviewer_alias: str) -> ReviewRecord:
    """Record a local operator decision, not publish or authorize any cloud call.

    Serialize with pipeline runs. Same request+operator retries return original
    history even if later inputs change; that history is not current eligibility.
    A new request must bind the currently rechecked quality/verifier inputs.
    """
    command = ReviewCommand.model_validate_json(command.model_dump_json())
    draft = ReviewRecord.model_construct(
        decision_id=stable_id("review", command.request_id),
        command=command,
        reviewer_alias=reviewer_alias,
        decided_at=datetime.now(UTC),
        record_hash="sha256:" + "0" * 64,
    )
    record = ReviewRecord.model_validate(
        {**draft.model_dump(), "record_hash": review_record_hash(draft)}
    )
    if not session.scalar(select(func.pg_try_advisory_xact_lock(349812, 1))):
        raise ReviewInProgress
    existing = session.get(ScopedReviewRow, record.decision_id)
    if existing is not None:
        prior = decode_review(existing)
        if prior.command != command or prior.reviewer_alias != reviewer_alias:
            raise ReviewConflict("Review request id already has a different decision")
        return prior
    version = session.get(RuleVersionRow, command.rule_version_id)
    if version is None:
        raise ReviewConflict("Reviewed rule version is unavailable")
    quality = read_latest_quality_report(session, version)
    verifier = read_latest_verifier_summary(session, version)
    if (
        quality is None
        or verifier is None
        or command.rule_semantic_hash != version.semantic_hash
        or command.evidence_snapshot_hash != quality.evidence_snapshot_hash
        or command.evidence_snapshot_hash != verifier.evidence_snapshot_hash
        or command.quality_report_hash != quality.report_hash
        or command.verifier_request_hash != verifier.request_hash
        or command.verifier_response_hash != verifier.response_hash
    ):
        raise ReviewConflict("Reviewed assurance inputs are stale or unavailable")
    session.add(
        ScopedReviewRow(
            decision_id=record.decision_id,
            request_id=command.request_id,
            rule_version_id=command.rule_version_id,
            scope=command.scope,
            record_json=record.model_dump_json(),
            record_hash=record.record_hash,
            decided_at=record.decided_at,
        )
    )
    session.flush()
    return record


def read_latest_review(
    session: Session, version_id: str, scope: ReviewScope
) -> ReviewRecord | None:
    row = session.scalar(
        select(ScopedReviewRow)
        .where(ScopedReviewRow.rule_version_id == version_id, ScopedReviewRow.scope == scope)
        .order_by(ScopedReviewRow.decided_at.desc(), ScopedReviewRow.decision_id.desc())
        .limit(1)
    )
    return decode_review(row) if row is not None else None


def record_review(url: str, command: ReviewCommand, reviewer_alias: str) -> ReviewRecord:
    """Commit one exact local-operator decision; no publication/cloud side effect."""
    engine = None
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with Session(engine) as session, session.begin():
            record = append_review(session, command, reviewer_alias)
        return record
    except (ReviewConflict, ReviewInProgress):
        raise
    except Exception:
        raise DatabaseUnavailable("PostgreSQL did not commit the review") from None
    finally:
        if engine is not None:
            engine.dispose()


def review_state(url: str, version_id: str, scope: ReviewScope) -> ReviewRecord | None:
    engine = None
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with Session(engine) as session:
            if session.get(RuleVersionRow, version_id) is None:
                raise ReviewNotFound
            return read_latest_review(session, version_id, scope)
    except ReviewNotFound:
        raise
    except Exception:
        raise DatabaseUnavailable("Stored review could not be verified") from None
    finally:
        if engine is not None:
            engine.dispose()
