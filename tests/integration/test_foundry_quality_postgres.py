"""Quality persistence in a migrated, disposable loopback PostgreSQL database only."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from fyp_iam.api.app import create_app
from fyp_iam.engine1.foundry.models import (
    PipelineRunRow,
    QualityObservationRow,
    QualityReportRow,
    RuleVersionRow,
)
from fyp_iam.engine1.foundry.pipeline import build_foundry
from fyp_iam.engine1.foundry.quality import QualityReport, build_quality_report
from fyp_iam.engine1.foundry.quality_store import read_latest_quality_report, write_quality_report
from fyp_iam.engine1.foundry.store import persist_foundry, read_rule

pytestmark = pytest.mark.postgres


def _test_url() -> str:
    raw = os.environ.get("FYP_TEST_DATABASE_URL") or os.environ.get("FYP_DATABASE_URL", "")
    if not raw:
        pytest.skip("Disposable PostgreSQL is not configured")
    url = make_url(raw)
    if url.host not in {"localhost", "127.0.0.1", "::1"} or url.database != "fyp_iam":
        pytest.skip("Quality integration tests require loopback database fyp_iam")
    return raw


def test_report_survives_new_engine_and_repeated_runs() -> None:
    url = _test_url()
    first = persist_foundry(url)
    report = QualityReport.model_validate(first["quality_report"])
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            before = session.scalar(
                select(func.count())
                .select_from(QualityObservationRow)
                .where(QualityObservationRow.rule_version_id == report.rule_version_id)
            )
        second = persist_foundry(url)
        assert second["quality_report"] == first["quality_report"]
        # A separate connection/engine reads stored artifacts, not the compiler's response.
        dossier = read_rule(url, report.rule_version_id)
        assert dossier is not None and dossier["quality_report"] == report.model_dump(mode="json")
        with Session(engine) as session:
            artifacts = session.scalars(
                select(QualityReportRow).where(
                    QualityReportRow.rule_version_id == report.rule_version_id
                )
            ).all()
            assert len(artifacts) == 1
            after = session.scalar(
                select(func.count())
                .select_from(QualityObservationRow)
                .where(QualityObservationRow.rule_version_id == report.rule_version_id)
            )
            assert after == before + 1
    finally:
        engine.dispose()


def test_partial_report_preserves_history_and_run_idempotency() -> None:
    url = _test_url()
    overview = persist_foundry(url)
    original = QualityReport.model_validate(overview["quality_report"])
    inputs = build_foundry(persisted=False, storage="not_written")
    candidate = inputs["candidate"]
    validations = inputs["validations"]
    assert isinstance(candidate, dict) and isinstance(validations, list)
    partial = build_quality_report(
        candidate, [v for v in validations if v["validator_name"] != "ontology"]
    )
    engine = create_engine(url)
    try:
        # All deliberate mutations below roll back; no truncation or historical deletion.
        with Session(engine) as session:
            version = session.get(RuleVersionRow, original.rule_version_id)
            assert version is not None
            run_id = session.scalar(
                select(PipelineRunRow.run_id).order_by(PipelineRunRow.started_at.desc()).limit(1)
            )
            assert run_id is not None
            observed_at = datetime.now(UTC) + timedelta(seconds=1)
            write_quality_report(session, partial, run_id, observed_at)
            write_quality_report(session, partial, run_id, observed_at)
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(QualityReportRow)
                    .where(QualityReportRow.rule_version_id == version.version_id)
                )
                == 2
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(QualityObservationRow)
                    .where(QualityObservationRow.report_id == partial.report_id)
                )
                == 1
            )
            latest = read_latest_quality_report(session, version)
            assert latest is not None and latest.status == "incomplete"
            assert session.get(QualityReportRow, original.report_id) is not None
            artifact = session.get(QualityReportRow, partial.report_id)
            assert artifact is not None
            artifact.report_hash = "sha256:" + "0" * 64
            with pytest.raises(ValueError, match="binding"):
                read_latest_quality_report(session, version)
            session.rollback()
    finally:
        engine.dispose()


def test_persisted_api_returns_bound_quality_and_missing_rule() -> None:
    url = _test_url()
    overview = persist_foundry(url)
    report = QualityReport.model_validate(overview["quality_report"])
    with TestClient(create_app(database_url=url)) as client:
        response = client.get(f"/v1/foundry/rules/{report.rule_version_id}")
        assert response.status_code == 200
        assert response.json()["quality_report"] == report.model_dump(mode="json")
        assert client.get("/v1/foundry/rules/version_missing").status_code == 404
