"""Transactional PostgreSQL quality artifacts. No implicit commits or approval."""

from datetime import datetime

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.foundry.models import (
    QualityObservationRow,
    QualityReportRow,
    RuleVersionRow,
)
from fyp_iam.engine1.foundry.quality import QualityReport


def _check_binding(report: QualityReport, version: RuleVersionRow | None) -> None:
    if (
        version is None
        or report.rule_version_id != version.version_id
        or report.rule_semantic_hash != version.semantic_hash
    ):
        raise ValueError("Quality report rule binding mismatch")


def decode_quality_report(payload: str, version: RuleVersionRow) -> QualityReport:
    try:
        report = QualityReport.model_validate_json(payload)
    except ValidationError:
        # Pydantic errors include inputs; never expose persisted evidence through them.
        raise ValueError("Stored quality report is invalid") from None
    _check_binding(report, version)
    return report


def write_quality_report(
    session: Session, report: QualityReport, pipeline_run_id: str, observed_at: datetime
) -> None:
    # Revalidate even a model constructed via model_copy/model_construct.
    report = QualityReport.model_validate_json(report.model_dump_json())
    _check_binding(report, session.get(RuleVersionRow, report.rule_version_id))
    body = report.model_dump(mode="json")
    for stage in body["stages"]:
        stage["duration_ms"] = None
    canonical = QualityReport.model_validate(body)
    session.execute(
        insert(QualityReportRow)
        .values(
            report_id=report.report_id,
            rule_version_id=report.rule_version_id,
            report_hash=report.report_hash,
            rule_semantic_hash=report.rule_semantic_hash,
            evidence_snapshot_hash=report.evidence_snapshot_hash,
            report_version=report.report_version,
            status=report.status,
            report_json=canonical.model_dump_json(),
            created_at=observed_at,
        )
        .on_conflict_do_nothing(index_elements=["report_id"])
    )
    session.execute(
        insert(QualityObservationRow)
        .values(
            observation_id=stable_id("qobs", pipeline_run_id, report.report_id),
            report_id=report.report_id,
            rule_version_id=report.rule_version_id,
            pipeline_run_id=pipeline_run_id,
            observed_at=observed_at,
            report_json=report.model_dump_json(),
        )
        .on_conflict_do_nothing(index_elements=["pipeline_run_id", "report_id"])
    )


def read_latest_quality_report(session: Session, version: RuleVersionRow) -> QualityReport | None:
    observation = session.scalar(
        select(QualityObservationRow)
        .where(QualityObservationRow.rule_version_id == version.version_id)
        .order_by(
            QualityObservationRow.observed_at.desc(), QualityObservationRow.observation_id.desc()
        )
        .limit(1)
    )
    if observation is None:
        return None
    artifact = session.get(QualityReportRow, observation.report_id)
    if artifact is None:
        raise ValueError("Stored quality artifact is missing")
    report = decode_quality_report(observation.report_json, version)
    canonical = decode_quality_report(artifact.report_json, version)
    if (
        report.report_id != observation.report_id
        or report.report_hash != canonical.report_hash
        or canonical.report_id != artifact.report_id
        or canonical.report_hash != artifact.report_hash
        or canonical.rule_version_id != artifact.rule_version_id
        or canonical.rule_semantic_hash != artifact.rule_semantic_hash
        or canonical.evidence_snapshot_hash != artifact.evidence_snapshot_hash
        or canonical.status != artifact.status
        or canonical.report_version != artifact.report_version
    ):
        raise ValueError("Stored quality artifact binding mismatch")
    return report
