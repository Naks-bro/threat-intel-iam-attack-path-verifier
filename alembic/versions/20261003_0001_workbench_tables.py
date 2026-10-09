"""Create the Engine 1 workbench tables."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sources",
        sa.Column("source_id", sa.String(80), primary_key=True),
        sa.Column("source_name", sa.String(64), nullable=False),
        sa.Column("source_version", sa.String(64), nullable=False),
        sa.Column("official_reference", sa.Text(), nullable=False),
    )
    op.create_table(
        "source_runs",
        sa.Column("run_id", sa.String(80), primary_key=True),
        sa.Column("source_id", sa.String(80), sa.ForeignKey("sources.source_id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(80), nullable=False),
    )
    op.create_table(
        "raw_artifacts",
        sa.Column("artifact_row_id", sa.String(80), primary_key=True),
        sa.Column("source_id", sa.String(80), sa.ForeignKey("sources.source_id"), nullable=False),
        sa.Column("run_id", sa.String(80), sa.ForeignKey("source_runs.run_id"), nullable=False),
        sa.Column("pin_id", sa.String(64), nullable=False),
        sa.Column("content_hash", sa.String(80), nullable=False, unique=True),
        sa.Column("byte_count", sa.Integer(), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "normalized_records",
        sa.Column("record_id", sa.String(80), primary_key=True),
        sa.Column(
            "artifact_row_id",
            sa.String(80),
            sa.ForeignKey("raw_artifacts.artifact_row_id"),
            nullable=False,
        ),
        sa.Column("source_native_id", sa.String(32), nullable=False),
        sa.Column("technique_name", sa.String(200), nullable=False),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("aws_iam_relevant", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "evidence_claims",
        sa.Column("claim_id", sa.String(80), primary_key=True),
        sa.Column(
            "record_id",
            sa.String(80),
            sa.ForeignKey("normalized_records.record_id"),
            nullable=False,
        ),
        sa.Column("claim_type", sa.String(64), nullable=False),
        sa.Column("location", sa.String(64), nullable=False),
    )
    op.create_table(
        "evidence_relations",
        sa.Column("relation_id", sa.String(80), primary_key=True),
        sa.Column(
            "from_record_id",
            sa.String(80),
            sa.ForeignKey("normalized_records.record_id"),
            nullable=False,
        ),
        sa.Column("relation_type", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("review_state", sa.String(32), nullable=False),
    )
    op.create_table(
        "rule_candidates",
        sa.Column("candidate_id", sa.String(80), primary_key=True),
        sa.Column(
            "record_id",
            sa.String(80),
            sa.ForeignKey("normalized_records.record_id"),
            nullable=False,
        ),
        sa.Column("lifecycle", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(80), nullable=True),
    )
    op.create_table(
        "rule_versions",
        sa.Column("version_id", sa.String(80), primary_key=True),
        sa.Column(
            "candidate_id",
            sa.String(80),
            sa.ForeignKey("rule_candidates.candidate_id"),
            nullable=False,
        ),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("rule_json", sa.Text(), nullable=True),
        sa.Column("created_by_method", sa.String(64), nullable=False),
    )
    op.create_table(
        "validation_results",
        sa.Column("validation_id", sa.String(80), primary_key=True),
        sa.Column(
            "candidate_id",
            sa.String(80),
            sa.ForeignKey("rule_candidates.candidate_id"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
    )
    op.create_table(
        "review_decisions",
        sa.Column("decision_id", sa.String(80), primary_key=True),
        sa.Column(
            "candidate_id",
            sa.String(80),
            sa.ForeignKey("rule_candidates.candidate_id"),
            nullable=False,
        ),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("reviewer_id", sa.String(64), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "published_rules",
        sa.Column("publication_id", sa.String(80), primary_key=True),
        sa.Column(
            "candidate_id",
            sa.String(80),
            sa.ForeignKey("rule_candidates.candidate_id"),
            nullable=False,
        ),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("evidence_snapshot_hash", sa.String(80), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(80), primary_key=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=False),
        sa.Column("object_id", sa.String(80), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
    )


def downgrade() -> None:
    for name in (
        "audit_events",
        "published_rules",
        "review_decisions",
        "validation_results",
        "rule_versions",
        "rule_candidates",
        "evidence_relations",
        "evidence_claims",
        "normalized_records",
        "raw_artifacts",
        "source_runs",
        "sources",
    ):
        op.drop_table(name)
