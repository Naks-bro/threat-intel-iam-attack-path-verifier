"""Add immutable quality artifacts and run observations; preserve legacy rows.

Frozen SQL deliberately avoids importing evolving application metadata. The
IF NOT EXISTS clauses also support fresh installs where legacy migration 0002
creates current metadata. Never backfill quality from legacy validation rows.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0005"
down_revision: str | None = "20261003_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text("""
        CREATE TABLE IF NOT EXISTS foundry.quality_reports (
            report_id varchar(80) PRIMARY KEY,
            rule_version_id varchar(80) NOT NULL REFERENCES foundry.rule_versions(version_id),
            report_hash varchar(80) NOT NULL,
            rule_semantic_hash varchar(80) NOT NULL,
            evidence_snapshot_hash varchar(80) NOT NULL,
            report_version varchar(64) NOT NULL,
            status varchar(16) NOT NULL,
            report_json text NOT NULL,
            created_at timestamptz NOT NULL,
            CONSTRAINT uq_quality_version_hash UNIQUE (rule_version_id, report_hash),
            CONSTRAINT ck_quality_status CHECK
                (status IN ('pass','fail','needs_review','incomplete'))
        )
    """)
    )
    op.execute(
        sa.text("""
        CREATE TABLE IF NOT EXISTS foundry.quality_observations (
            observation_id varchar(80) PRIMARY KEY,
            report_id varchar(80) NOT NULL REFERENCES foundry.quality_reports(report_id),
            rule_version_id varchar(80) NOT NULL REFERENCES foundry.rule_versions(version_id),
            pipeline_run_id varchar(80) NOT NULL REFERENCES foundry.pipeline_runs(run_id),
            observed_at timestamptz NOT NULL,
            report_json text NOT NULL,
            CONSTRAINT uq_quality_run_report UNIQUE (pipeline_run_id, report_id)
        )
    """)
    )
    # New table: no existing production rows require a concurrent-index phase.
    op.execute(
        sa.text("""
        CREATE INDEX IF NOT EXISTS ix_quality_latest ON foundry.quality_observations
        (rule_version_id, observed_at, observation_id)
    """)
    )
    op.execute(
        sa.text("ALTER TABLE foundry.validation_runs ALTER COLUMN duration_ms DROP NOT NULL")
    )
    op.execute(
        sa.text("REVOKE ALL ON foundry.quality_reports, foundry.quality_observations FROM PUBLIC")
    )
    op.execute(
        sa.text("""
        DO $$
        DECLARE role_name text;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
                    EXECUTE format(
                        'REVOKE ALL ON foundry.quality_reports, '
                        'foundry.quality_observations FROM %I',
                        role_name
                    );
                END IF;
            END LOOP;
        END $$;
    """)
    )


def downgrade() -> None:
    raise RuntimeError(
        "Quality history is archival data; use a reviewed forward migration rather than deleting it"
    )
