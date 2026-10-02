"""PostgreSQL mappings. SQLite is rejected before an engine is opened."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    select,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.workbench.domain import WorkbenchSnapshot
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable
from fyp_iam.engine1.workbench.services import rule_limitations


class Base(DeclarativeBase):
    pass


class SourceRow(Base):
    __tablename__ = "sources"

    source_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_name: Mapped[str] = mapped_column(String(64))
    source_version: Mapped[str] = mapped_column(String(64))
    official_reference: Mapped[str] = mapped_column(Text)


class SourceRunRow(Base):
    __tablename__ = "source_runs"

    run_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.source_id"))
    status: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    record_count: Mapped[int] = mapped_column(Integer)
    error_count: Mapped[int] = mapped_column(Integer)
    content_hash: Mapped[str] = mapped_column(String(80))


class RawArtifactRow(Base):
    __tablename__ = "raw_artifacts"

    artifact_row_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.source_id"))
    run_id: Mapped[str] = mapped_column(ForeignKey("source_runs.run_id"))
    pin_id: Mapped[str] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(80), unique=True)
    byte_count: Mapped[int] = mapped_column(Integer)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NormalizedRecordRow(Base):
    __tablename__ = "normalized_records"

    record_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    artifact_row_id: Mapped[str] = mapped_column(ForeignKey("raw_artifacts.artifact_row_id"))
    source_native_id: Mapped[str] = mapped_column(String(32))
    technique_name: Mapped[str] = mapped_column(String(200))
    parser_version: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(16))
    aws_iam_relevant: Mapped[bool] = mapped_column(Boolean)


class EvidenceClaimRow(Base):
    __tablename__ = "evidence_claims"

    claim_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    record_id: Mapped[str] = mapped_column(ForeignKey("normalized_records.record_id"))
    claim_type: Mapped[str] = mapped_column(String(64))
    location: Mapped[str] = mapped_column(String(64))


class EvidenceRelationRow(Base):
    __tablename__ = "evidence_relations"

    relation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    from_record_id: Mapped[str] = mapped_column(ForeignKey("normalized_records.record_id"))
    relation_type: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(64))
    rationale: Mapped[str] = mapped_column(Text)
    review_state: Mapped[str] = mapped_column(String(32))


class RuleCandidateRow(Base):
    __tablename__ = "rule_candidates"

    candidate_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    record_id: Mapped[str] = mapped_column(ForeignKey("normalized_records.record_id"))
    lifecycle: Mapped[str] = mapped_column(String(32))
    rule_id: Mapped[str | None] = mapped_column(String(80), nullable=True)


class RuleVersionRow(Base):
    __tablename__ = "rule_versions"

    version_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("rule_candidates.candidate_id"))
    rule_version: Mapped[int] = mapped_column(Integer)
    rule_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_method: Mapped[str] = mapped_column(String(64))


class ValidationResultRow(Base):
    __tablename__ = "validation_results"

    validation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("rule_candidates.candidate_id"))
    status: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(Text)


class ReviewDecisionRow(Base):
    __tablename__ = "review_decisions"

    decision_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("rule_candidates.candidate_id"))
    decision: Mapped[str] = mapped_column(String(32))
    reviewer_id: Mapped[str] = mapped_column(String(64))
    comment: Mapped[str] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublishedRuleRow(Base):
    __tablename__ = "published_rules"

    publication_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("rule_candidates.candidate_id"))
    rule_version: Mapped[int] = mapped_column(Integer)
    evidence_snapshot_hash: Mapped[str] = mapped_column(String(80))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[str] = mapped_column(String(80))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    detail: Mapped[str] = mapped_column(Text)


class PostgresWorkbenchStore:
    """Writes the workbench tables. A missing server raises DatabaseUnavailable."""

    def __init__(self, url: str) -> None:
        if not url or url.startswith("sqlite"):
            raise DatabaseUnavailable("PostgreSQL is required for workbench persistence")
        self._engine = create_engine(url, pool_pre_ping=True)
        self._session_factory = sessionmaker(self._engine, expire_on_commit=False)

    def dispose(self) -> None:
        self._engine.dispose()

    def save_import(self, snapshot: WorkbenchSnapshot) -> str:
        try:
            with self._session_factory() as session, session.begin():
                digest = snapshot.content_hash
                existing = session.scalar(
                    select(RawArtifactRow).where(RawArtifactRow.content_hash == digest)
                )
                if existing is not None:
                    return "unchanged"
                _insert_import(session, snapshot)
                return "created"
        except DatabaseUnavailable:
            raise
        except Exception as exc:
            raise DatabaseUnavailable("PostgreSQL did not commit the import") from exc

    def get_import(self, pin_id: str) -> WorkbenchSnapshot | None:
        try:
            with self._session_factory() as session:
                artifact = session.scalar(
                    select(RawArtifactRow).where(RawArtifactRow.pin_id == pin_id)
                )
                if artifact is None:
                    return None
                return _load_snapshot(session, artifact)
        except Exception as exc:
            raise DatabaseUnavailable("PostgreSQL did not return the import") from exc


def database_status(url: str | None) -> tuple[str, str]:
    """Return ``(ok|unavailable, detail)``. The detail never includes the URL."""

    if not url:
        return "unavailable", "not_configured"
    if url.startswith("sqlite"):
        return "unavailable", "sqlite_rejected"
    engine = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 3})
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        return "unavailable", "unreachable"
    finally:
        engine.dispose()
    return "ok", "reachable"


def _insert_import(session: Session, snapshot: WorkbenchSnapshot) -> None:
    retrieved = snapshot.retrieved_at
    source_id = stable_id("source", snapshot.source_name, snapshot.source_version)
    run_id = stable_id("run", snapshot.pin_id, snapshot.content_hash)
    artifact_row_id = stable_id("artifact", snapshot.pin_id, snapshot.content_hash)
    candidate_id = stable_id("candidate", snapshot.record_id, snapshot.lifecycle)
    if session.get(SourceRow, source_id) is None:
        session.add(
            SourceRow(
                source_id=source_id,
                source_name=snapshot.source_name,
                source_version=snapshot.source_version,
                official_reference=snapshot.official_reference,
            )
        )
    session.add(
        SourceRunRow(
            run_id=run_id,
            source_id=source_id,
            status="completed",
            started_at=retrieved,
            finished_at=retrieved,
            record_count=1,
            error_count=0,
            content_hash=snapshot.content_hash,
        )
    )
    session.add(
        RawArtifactRow(
            artifact_row_id=artifact_row_id,
            source_id=source_id,
            run_id=run_id,
            pin_id=snapshot.pin_id,
            content_hash=snapshot.content_hash,
            byte_count=snapshot.byte_count,
            retrieved_at=retrieved,
        )
    )
    session.add(
        NormalizedRecordRow(
            record_id=snapshot.record_id,
            artifact_row_id=artifact_row_id,
            source_native_id=snapshot.technique_id,
            technique_name=snapshot.technique_name,
            parser_version=snapshot.parser_version,
            schema_version="0.1",
            aws_iam_relevant=snapshot.aws_iam_relevant,
        )
    )
    session.add(
        EvidenceClaimRow(
            claim_id=stable_id("claim", snapshot.record_id, "excerpt"),
            record_id=snapshot.record_id,
            claim_type="technique_excerpt",
            location="excerpt",
        )
    )
    session.add(
        RuleCandidateRow(
            candidate_id=candidate_id,
            record_id=snapshot.record_id,
            lifecycle=snapshot.lifecycle,
            rule_id=snapshot.rule_id,
        )
    )
    if snapshot.rule_json is not None and snapshot.rule_version is not None:
        session.add(
            RuleVersionRow(
                version_id=stable_id("version", candidate_id, str(snapshot.rule_version)),
                candidate_id=candidate_id,
                rule_version=snapshot.rule_version,
                rule_json=snapshot.rule_json,
                created_by_method=snapshot.parser_version,
            )
        )
    session.add(
        ValidationResultRow(
            validation_id=stable_id("validation", candidate_id, snapshot.validation_status),
            candidate_id=candidate_id,
            status=snapshot.validation_status,
            detail=snapshot.explanation,
        )
    )
    session.add(
        AuditEventRow(
            event_id=stable_id("audit", run_id, "import_completed"),
            action="import_completed",
            object_type="raw_artifact",
            object_id=artifact_row_id,
            recorded_at=retrieved,
            detail=snapshot.lifecycle,
        )
    )


def _load_snapshot(session: Session, artifact: RawArtifactRow) -> WorkbenchSnapshot:
    source = session.get(SourceRow, artifact.source_id)
    record = session.scalar(
        select(NormalizedRecordRow).where(
            NormalizedRecordRow.artifact_row_id == artifact.artifact_row_id
        )
    )
    if source is None or record is None:
        raise DatabaseUnavailable("stored import is missing its source or normalized record")
    candidate = session.scalar(
        select(RuleCandidateRow).where(RuleCandidateRow.record_id == record.record_id)
    )
    if candidate is None:
        raise DatabaseUnavailable("stored import is missing its candidate")
    version = session.scalar(
        select(RuleVersionRow).where(RuleVersionRow.candidate_id == candidate.candidate_id)
    )
    validation = session.scalar(
        select(ValidationResultRow).where(
            ValidationResultRow.candidate_id == candidate.candidate_id
        )
    )
    if validation is None:
        raise DatabaseUnavailable("stored import is missing its validation result")
    rule_json = version.rule_json if version is not None else None
    return WorkbenchSnapshot(
        pin_id=artifact.pin_id,
        source_name=source.source_name,
        source_version=source.source_version,
        official_reference=source.official_reference,
        retrieved_at=artifact.retrieved_at,
        content_hash=artifact.content_hash,
        byte_count=artifact.byte_count,
        record_id=record.record_id,
        technique_id=record.source_native_id,
        technique_name=record.technique_name,
        parser_version=record.parser_version,
        aws_iam_relevant=record.aws_iam_relevant,
        lifecycle=candidate.lifecycle,
        rule_id=candidate.rule_id,
        rule_version=version.rule_version if version is not None else None,
        rule_json=rule_json,
        validation_status=validation.status,
        explanation=validation.detail,
        limitations=rule_limitations(rule_json, validation.detail),
    )
