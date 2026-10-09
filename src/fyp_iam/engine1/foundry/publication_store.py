"""Read-only current eligibility under the same lock as pipeline and review writes."""

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from fyp_iam.engine1.foundry.models import RuleVersionRow
from fyp_iam.engine1.foundry.publication import Channel, PublicationAssessment, assess_publication
from fyp_iam.engine1.foundry.quality_store import read_latest_quality_report
from fyp_iam.engine1.foundry.review import ReviewScope
from fyp_iam.engine1.foundry.review_store import (
    ReviewInProgress,
    ReviewNotFound,
    read_latest_review,
)
from fyp_iam.engine1.foundry.verifier_store import read_latest_verifier_summary
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable


def read_assessment(
    session: Session,
    version_id: str,
    scope: ReviewScope,
    channel: Channel,
    *,
    allow_experimental: bool = False,
) -> PublicationAssessment:
    if not session.scalar(select(func.pg_try_advisory_xact_lock(349812, 1))):
        raise ReviewInProgress
    version = session.get(RuleVersionRow, version_id)
    if version is None:
        raise ReviewNotFound
    return assess_publication(
        version_id=version.version_id,
        semantic_hash=version.semantic_hash,
        scope=scope,
        channel=channel,
        quality=read_latest_quality_report(session, version),
        verifier=read_latest_verifier_summary(session, version),
        review=read_latest_review(session, version_id, scope),
        allow_experimental=allow_experimental,
    )


def publication_assessment(
    url: str,
    version_id: str,
    scope: ReviewScope,
    channel: Channel,
    *,
    allow_experimental: bool = False,
) -> PublicationAssessment:
    engine = None
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with Session(engine) as session, session.begin():
            return read_assessment(
                session,
                version_id,
                scope,
                channel,
                allow_experimental=allow_experimental,
            )
    except (ReviewNotFound, ReviewInProgress):
        raise
    except Exception:
        raise DatabaseUnavailable("Publication inputs could not be verified") from None
    finally:
        if engine is not None:
            engine.dispose()
