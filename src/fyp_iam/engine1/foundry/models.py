"""Foundry tables. SQLite is not a target. See ADR-009."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_STATUS = "status in ('queued','running','succeeded','partial','failed','cancelled')"


class Base(DeclarativeBase):
    """Foundry tables live in the non-exposed ``foundry`` schema."""

    metadata = MetaData(schema="foundry")


class SourceRow(Base):
    __tablename__ = "sources"
    __table_args__ = (
        UniqueConstraint("source_key"),
        CheckConstraint("authority_tier in (1, 2, 3)", name="ck_sources_tier"),
        CheckConstraint(
            "source_type in ('taxonomy','service_reference','community_behavior',"
            "'contextual','threat_catalog')",
            name="ck_sources_type",
        ),
    )

    source_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_key: Mapped[str] = mapped_column(String(64))
    authority_tier: Mapped[int] = mapped_column(Integer)
    source_type: Mapped[str] = mapped_column(String(32))
    official_url: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean)
    schedule_cron: Mapped[str | None] = mapped_column(String(64), nullable=True)


class SourceVersionRow(Base):
    __tablename__ = "source_versions"
    __table_args__ = (UniqueConstraint("source_id", "content_hash"),)

    version_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.source_id"))
    version_label: Mapped[str] = mapped_column(String(64))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str] = mapped_column(String(80))


class PipelineRunRow(Base):
    __tablename__ = "pipeline_runs"
    __table_args__ = (CheckConstraint(_STATUS, name="ck_pipeline_status"),)

    run_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    status: Mapped[str] = mapped_column(String(32))
    attempt: Mapped[int] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(String(32))
    parent_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("pipeline_runs.run_id"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_count: Mapped[int] = mapped_column(Integer)
    created_count: Mapped[int] = mapped_column(Integer)
    updated_count: Mapped[int] = mapped_column(Integer)
    unchanged_count: Mapped[int] = mapped_column(Integer)
    rejected_count: Mapped[int] = mapped_column(Integer)
    error_json: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(80))


class IngestionRunRow(Base):
    __tablename__ = "ingestion_runs"
    __table_args__ = (CheckConstraint(_STATUS, name="ck_ingestion_status"),)

    ingestion_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    pipeline_run_id: Mapped[str] = mapped_column(ForeignKey("pipeline_runs.run_id"))
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.source_id"))
    source_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("source_versions.version_id"), nullable=True
    )
    attempt: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_count: Mapped[int] = mapped_column(Integer)
    created_count: Mapped[int] = mapped_column(Integer)
    updated_count: Mapped[int] = mapped_column(Integer)
    unchanged_count: Mapped[int] = mapped_column(Integer)
    rejected_count: Mapped[int] = mapped_column(Integer)
    error_json: Mapped[str] = mapped_column(Text)
    retry_of: Mapped[str | None] = mapped_column(
        ForeignKey("ingestion_runs.ingestion_id"), nullable=True
    )
    parser_version: Mapped[str] = mapped_column(String(64))


class RawArtifactRow(Base):
    __tablename__ = "raw_artifacts"
    __table_args__ = (
        UniqueConstraint("source_version_id", "source_native_id", "content_hash"),
        CheckConstraint(
            "payload is not null or storage_uri is not null",
            name="ck_artifact_payload",
        ),
    )

    artifact_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source_version_id: Mapped[str] = mapped_column(ForeignKey("source_versions.version_id"))
    ingestion_id: Mapped[str] = mapped_column(ForeignKey("ingestion_runs.ingestion_id"))
    source_native_id: Mapped[str] = mapped_column(String(128))
    mime_type: Mapped[str] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(80))
    byte_count: Mapped[int] = mapped_column(Integer)
    payload: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    storage_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    parser_version: Mapped[str] = mapped_column(String(64))


class NormalizedEntityRow(Base):
    __tablename__ = "normalized_entities"
    __table_args__ = (
        UniqueConstraint("entity_type", "native_id", "source_version_id"),
        CheckConstraint(
            "entity_type in ('technique','attack_behavior','cloud_behavior','aws_service',"
            "'aws_action','aws_resource','condition_key','vulnerability','mitigation',"
            "'attack_primitive_ref','scenario')",
            name="ck_entity_type",
        ),
    )

    entity_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32))
    native_id: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(200))
    source_version_id: Mapped[str] = mapped_column(ForeignKey("source_versions.version_id"))
    artifact_id: Mapped[str] = mapped_column(ForeignKey("raw_artifacts.artifact_id"))
    attributes_json: Mapped[str] = mapped_column(Text)


class EvidenceClaimRow(Base):
    __tablename__ = "evidence_claims"
    __table_args__ = (
        UniqueConstraint(
            "artifact_id",
            "subject_entity_id",
            "predicate",
            "object_value",
            "source_location",
            name="uq_claim_identity",
        ),
    )

    claim_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    subject_entity_id: Mapped[str] = mapped_column(ForeignKey("normalized_entities.entity_id"))
    predicate: Mapped[str] = mapped_column(String(64))
    object_value: Mapped[str] = mapped_column(Text)
    object_entity_id: Mapped[str | None] = mapped_column(
        ForeignKey("normalized_entities.entity_id"), nullable=True
    )
    artifact_id: Mapped[str] = mapped_column(ForeignKey("raw_artifacts.artifact_id"))
    source_location: Mapped[str] = mapped_column(String(128))
    extraction_method: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(16))
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvidenceRelationRow(Base):
    __tablename__ = "evidence_relations"
    __table_args__ = (
        UniqueConstraint(
            "from_entity_id",
            "to_entity_id",
            "relation_type",
            "mapping_method",
            name="uq_relation_identity",
        ),
        CheckConstraint(
            "review_state in ('proposed','accepted','rejected')",
            name="ck_relation_review",
        ),
    )

    relation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    from_entity_id: Mapped[str] = mapped_column(ForeignKey("normalized_entities.entity_id"))
    to_entity_id: Mapped[str] = mapped_column(ForeignKey("normalized_entities.entity_id"))
    relation_type: Mapped[str] = mapped_column(String(64))
    mapping_method: Mapped[str] = mapped_column(String(64))
    mapping_confidence: Mapped[str] = mapped_column(String(16))
    review_state: Mapped[str] = mapped_column(String(32))
    rationale: Mapped[str] = mapped_column(Text)


class EvidenceRelationClaimRow(Base):
    __tablename__ = "evidence_relation_claims"

    relation_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_relations.relation_id"), primary_key=True
    )
    claim_id: Mapped[str] = mapped_column(ForeignKey("evidence_claims.claim_id"), primary_key=True)


class AttackPrimitiveRow(Base):
    __tablename__ = "attack_primitives"
    __table_args__ = (
        UniqueConstraint("primitive_key", "generator_version"),
        CheckConstraint(
            "attack_mapping_state in ('mapped','unmapped')",
            name="ck_primitive_mapping",
        ),
    )

    primitive_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    primitive_key: Mapped[str] = mapped_column(String(64))
    outcome_category: Mapped[str] = mapped_column(String(64))
    required_actions_json: Mapped[str] = mapped_column(Text)
    required_resources_json: Mapped[str] = mapped_column(Text)
    preconditions_json: Mapped[str] = mapped_column(Text)
    state_transition: Mapped[str] = mapped_column(Text)
    resulting_capability: Mapped[str] = mapped_column(Text)
    limitations: Mapped[str] = mapped_column(Text)
    mapping_confidence: Mapped[str] = mapped_column(String(16))
    attack_mapping_state: Mapped[str] = mapped_column(String(16))
    generator_version: Mapped[str] = mapped_column(String(64))


class PrimitiveRelationRow(Base):
    __tablename__ = "primitive_relations"

    primitive_id: Mapped[str] = mapped_column(
        ForeignKey("attack_primitives.primitive_id"), primary_key=True
    )
    relation_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_relations.relation_id"), primary_key=True
    )


class RuleCandidateRow(Base):
    __tablename__ = "rule_candidates"
    __table_args__ = (
        CheckConstraint(
            "lifecycle in ('generated','validated','experimental','needs_review','rejected')",
            name="ck_candidate_lifecycle",
        ),
    )

    candidate_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    lifecycle: Mapped[str] = mapped_column(String(32))
    generator_name: Mapped[str] = mapped_column(String(64))
    template_version: Mapped[str] = mapped_column(String(64))


class CandidatePrimitiveRow(Base):
    __tablename__ = "candidate_primitives"

    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("rule_candidates.candidate_id"), primary_key=True
    )
    primitive_id: Mapped[str] = mapped_column(
        ForeignKey("attack_primitives.primitive_id"), primary_key=True
    )


class CandidateEntityRow(Base):
    __tablename__ = "candidate_entities"

    candidate_id: Mapped[str] = mapped_column(
        ForeignKey("rule_candidates.candidate_id"), primary_key=True
    )
    entity_id: Mapped[str] = mapped_column(
        ForeignKey("normalized_entities.entity_id"), primary_key=True
    )


class RuleVersionRow(Base):
    __tablename__ = "rule_versions"
    __table_args__ = (UniqueConstraint("candidate_id", "rule_version"),)

    version_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("rule_candidates.candidate_id"))
    rule_version: Mapped[int] = mapped_column(Integer)
    rule_json: Mapped[str] = mapped_column(Text)
    semantic_hash: Mapped[str] = mapped_column(String(80))
    parent_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("rule_versions.version_id"), nullable=True
    )
    generator_version: Mapped[str] = mapped_column(String(64))


class ValidationRunRow(Base):
    __tablename__ = "validation_runs"

    validation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    validator_name: Mapped[str] = mapped_column(String(64))
    validator_version: Mapped[str] = mapped_column(String(64))
    result: Mapped[str] = mapped_column(String(16))
    findings_json: Mapped[str] = mapped_column(Text)
    corpus_version: Mapped[str] = mapped_column(String(64))
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


class QualityReportRow(Base):
    """Immutable semantic artifact; measurement times belong to observations."""

    __tablename__ = "quality_reports"
    __table_args__ = (
        UniqueConstraint("rule_version_id", "report_hash", name="uq_quality_version_hash"),
        CheckConstraint(
            "status in ('pass','fail','needs_review','incomplete')", name="ck_quality_status"
        ),
    )

    report_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    report_hash: Mapped[str] = mapped_column(String(80))
    rule_semantic_hash: Mapped[str] = mapped_column(String(80))
    evidence_snapshot_hash: Mapped[str] = mapped_column(String(80))
    report_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    report_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class QualityObservationRow(Base):
    """One report observed in one run; repeated identical writes are idempotent."""

    __tablename__ = "quality_observations"
    __table_args__ = (
        UniqueConstraint("pipeline_run_id", "report_id", name="uq_quality_run_report"),
        Index("ix_quality_latest", "rule_version_id", "observed_at", "observation_id"),
    )

    observation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("quality_reports.report_id"))
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    pipeline_run_id: Mapped[str] = mapped_column(ForeignKey("pipeline_runs.run_id"))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    report_json: Mapped[str] = mapped_column(Text)


class VerifierPacketRow(Base):
    """Append-only application record of one exact request/result in a run."""

    __tablename__ = "verifier_packets"
    __table_args__ = (
        UniqueConstraint(
            "pipeline_run_id", "request_hash", "response_hash", name="uq_verifier_run_binding"
        ),
        CheckConstraint("octet_length(request_json) <= 65536", name="ck_verifier_request_size"),
        CheckConstraint("octet_length(response_json) <= 262144", name="ck_verifier_response_size"),
    )

    packet_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    pipeline_run_id: Mapped[str] = mapped_column(ForeignKey("pipeline_runs.run_id"))
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    request_hash: Mapped[str] = mapped_column(String(80))
    response_hash: Mapped[str] = mapped_column(String(80))
    request_json: Mapped[str] = mapped_column(Text)
    response_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AIVerificationRow(Base):
    __tablename__ = "ai_verifications"
    __table_args__ = (
        CheckConstraint(
            "verdict in ('pass','needs_review','reject')",
            name="ck_ai_verdict",
        ),
    )

    verification_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(64))
    schema_version: Mapped[str] = mapped_column(String(16))
    evidence_snapshot_hash: Mapped[str] = mapped_column(String(80))
    verdict: Mapped[str] = mapped_column(String(16))
    findings_json: Mapped[str] = mapped_column(Text)
    citations_json: Mapped[str] = mapped_column(Text)
    response_hash: Mapped[str] = mapped_column(String(80))


class ReviewDecisionRow(Base):
    __tablename__ = "review_decisions"

    decision_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    reviewer_alias: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(32))
    comment: Mapped[str] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScopedReviewRow(Base):
    """Bound reviews; legacy review_decisions are not upgraded by inference."""

    __tablename__ = "scoped_reviews"
    __table_args__ = (
        UniqueConstraint("request_id"),
        CheckConstraint("octet_length(record_json) <= 16384", name="ck_scoped_review_size"),
        Index("ix_scoped_review_version_scope", "rule_version_id", "scope", "decided_at"),
    )

    decision_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(80))
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    scope: Mapped[str] = mapped_column(String(32))
    record_json: Mapped[str] = mapped_column(Text)
    record_hash: Mapped[str] = mapped_column(String(80))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class StableReleaseRow(Base):
    """Scoped stable history; legacy publications never imply scoped approval."""

    __tablename__ = "stable_releases"
    __table_args__ = (
        UniqueConstraint("request_id"),
        CheckConstraint("octet_length(record_json) <= 131072", name="ck_stable_release_size"),
    )

    release_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(80))
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    review_decision_id: Mapped[str] = mapped_column(ForeignKey("scoped_reviews.decision_id"))
    scope: Mapped[str] = mapped_column(String(32))
    record_json: Mapped[str] = mapped_column(Text)
    record_hash: Mapped[str] = mapped_column(String(80))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PublicationRow(Base):
    __tablename__ = "publications"
    __table_args__ = (
        UniqueConstraint("rule_version_id", "channel"),
        CheckConstraint("channel in ('experimental','stable')", name="ck_publication_channel"),
    )

    publication_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    evidence_snapshot_hash: Mapped[str] = mapped_column(String(80))
    channel: Mapped[str] = mapped_column(String(16))
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AISuggestionRow(Base):
    __tablename__ = "ai_suggestions"

    suggestion_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    verification_id: Mapped[str] = mapped_column(ForeignKey("ai_verifications.verification_id"))
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.version_id"))
    suggestion_json: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[str] = mapped_column(String(80))
    correlation_id: Mapped[str] = mapped_column(String(80))
    before_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    after_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    details_json: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
