"""Storage boundary guarantees without substituting SQLite for PostgreSQL."""

from copy import deepcopy
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects import postgresql

from fyp_iam.engine1.foundry.models import QualityObservationRow, QualityReportRow, RuleVersionRow
from fyp_iam.engine1.foundry.pipeline import build_foundry
from fyp_iam.engine1.foundry.quality import QualityReport
from fyp_iam.engine1.foundry.quality_store import (
    decode_quality_report,
    read_latest_quality_report,
    write_quality_report,
)


def _inputs():
    overview = build_foundry(persisted=False, storage="not_written")
    report = QualityReport.model_validate(overview["quality_report"])
    version = RuleVersionRow(
        version_id=report.rule_version_id, semantic_hash=report.rule_semantic_hash
    )
    return report, version


def test_write_uses_idempotent_artifact_and_separate_run_observation():
    report, version = _inputs()
    session = MagicMock()
    session.get.return_value = version
    write_quality_report(session, report, "pipeline_test", datetime.now(UTC))
    assert session.execute.call_count == 2
    statements = [call.args[0] for call in session.execute.call_args_list]
    sql = [str(stmt.compile(dialect=postgresql.dialect())) for stmt in statements]
    assert "quality_reports" in sql[0] and "ON CONFLICT" in sql[0]
    assert "quality_observations" in sql[1] and "ON CONFLICT" in sql[1]
    params = statements[0].compile(dialect=postgresql.dialect()).params
    assert QualityReport.model_validate_json(params["report_json"]) == report


@pytest.mark.parametrize("bad_binding", ["version", "hash", "missing"])
def test_write_rejects_unbound_version_before_any_insert(bad_binding):
    report, version = _inputs()
    if bad_binding == "version":
        version.version_id = "different_version"
    elif bad_binding == "hash":
        version.semantic_hash = "sha256:" + "0" * 64
    session = MagicMock()
    session.get.return_value = None if bad_binding == "missing" else version
    with pytest.raises(ValueError, match="binding"):
        write_quality_report(session, report, "pipeline_test", datetime.now(UTC))
    session.execute.assert_not_called()


def test_decode_rejects_corrupted_report_without_exposing_payload():
    report, version = _inputs()
    payload = deepcopy(report.model_dump(mode="json"))
    payload["status"] = "fail"
    import json

    with pytest.raises(ValueError, match="Stored quality report is invalid") as exc:
        decode_quality_report(json.dumps(payload), version)
    assert report.report_hash not in str(exc.value)


def test_decode_checks_surrounding_rule_hash():
    report, version = _inputs()
    version.semantic_hash = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="binding"):
        decode_quality_report(report.model_dump_json(), version)


def test_missing_report_is_none_not_inferred_success():
    _, version = _inputs()
    session = MagicMock()
    session.scalar.return_value = None
    assert read_latest_quality_report(session, version) is None
    stmt = session.scalar.call_args.args[0]
    sql = str(stmt.compile(dialect=postgresql.dialect()))
    assert "ORDER BY" in sql and "LIMIT" in sql


def test_schema_allows_unknown_duration():
    from fyp_iam.engine1.foundry.models import ValidationRunRow

    assert ValidationRunRow.__table__.c.duration_ms.nullable


def test_observed_timing_is_preserved_without_changing_artifact():
    report, version = _inputs()
    body = report.model_dump(mode="json")
    body["stages"][0]["duration_ms"] = 37
    observed = QualityReport.model_validate(body)
    session = MagicMock()
    session.get.return_value = version
    write_quality_report(session, observed, "pipeline_test", datetime.now(UTC))
    params = [
        call.args[0].compile(dialect=postgresql.dialect()).params
        for call in session.execute.call_args_list
    ]
    canonical = QualityReport.model_validate_json(params[0]["report_json"])
    measurement = QualityReport.model_validate_json(params[1]["report_json"])
    assert canonical == report
    assert measurement.stages[0].duration_ms == 37
    assert measurement.report_hash == canonical.report_hash


def _stored_session(report):
    session = MagicMock()
    session.scalar.return_value = QualityObservationRow(
        report_id=report.report_id,
        rule_version_id=report.rule_version_id,
        report_json=report.model_dump_json(),
    )
    session.get.return_value = QualityReportRow(
        report_id=report.report_id,
        rule_version_id=report.rule_version_id,
        report_hash=report.report_hash,
        rule_semantic_hash=report.rule_semantic_hash,
        evidence_snapshot_hash=report.evidence_snapshot_hash,
        status=report.status,
        report_version=report.report_version,
        report_json=report.model_dump_json(),
    )
    return session


def test_read_validates_and_returns_stored_report():
    report, version = _inputs()
    assert read_latest_quality_report(_stored_session(report), version) == report


@pytest.mark.parametrize(
    "field", ["report_hash", "evidence_snapshot_hash", "status", "rule_version_id"]
)
def test_read_rejects_inconsistent_artifact_metadata(field):
    report, version = _inputs()
    session = _stored_session(report)
    setattr(session.get.return_value, field, "corrupted")
    with pytest.raises(ValueError, match="binding"):
        read_latest_quality_report(session, version)


def test_read_rejects_missing_linked_artifact():
    report, version = _inputs()
    session = _stored_session(report)
    session.get.return_value = None
    with pytest.raises(ValueError, match="missing"):
        read_latest_quality_report(session, version)


def test_legacy_writer_no_longer_invents_measurements():
    from fyp_iam.engine1.foundry.store import _write_validations

    session = MagicMock()
    _write_validations(
        session, build_foundry(persisted=False, storage="not_written"), datetime.now(UTC)
    )
    assert session.execute.call_count == 14
    for call in session.execute.call_args_list:
        assert call.args[0].compile(dialect=postgresql.dialect()).params["duration_ms"] is None


def test_frozen_migration_emits_additive_postgres_sql():
    import importlib.util
    from io import StringIO
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    root = Path(__file__).resolve().parents[2]
    path = root / "alembic/versions/20261003_0005_foundry_quality_reports.py"
    spec = importlib.util.spec_from_file_location("quality_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output}
    )
    with Operations.context(context):
        migration.upgrade()
    sql = output.getvalue()
    assert "CREATE TABLE IF NOT EXISTS foundry.quality_reports" in sql
    assert "CREATE TABLE IF NOT EXISTS foundry.quality_observations" in sql
    assert "ALTER COLUMN duration_ms DROP NOT NULL" in sql
    assert "REVOKE ALL" in sql
    assert "DROP TABLE" not in sql and "UPDATE " not in sql
    with pytest.raises(RuntimeError, match="archival"):
        migration.downgrade()
