"""Add exact-input scoped review history without inferring legacy approvals."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0007"
down_revision: str | None = "20261003_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Migration 0002 imports current Base metadata; support both creation paths.
    op.execute(
        sa.text("""
        CREATE TABLE IF NOT EXISTS foundry.scoped_reviews (
            decision_id varchar(80) PRIMARY KEY,
            request_id varchar(80) NOT NULL UNIQUE,
            rule_version_id varchar(80) NOT NULL REFERENCES foundry.rule_versions(version_id),
            scope varchar(32) NOT NULL,
            record_json text NOT NULL,
            record_hash varchar(80) NOT NULL,
            decided_at timestamptz NOT NULL,
            CONSTRAINT ck_scoped_review_size CHECK (octet_length(record_json) <= 16384)
        )
    """)
    )
    op.execute(
        sa.text("""
        CREATE INDEX IF NOT EXISTS ix_scoped_review_version_scope
        ON foundry.scoped_reviews (rule_version_id, scope, decided_at)
    """)
    )
    op.execute(sa.text("REVOKE ALL ON foundry.scoped_reviews FROM PUBLIC"))
    op.execute(
        sa.text("""
        DO $$ DECLARE role_name text;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
                    EXECUTE format('REVOKE ALL ON foundry.scoped_reviews FROM %I', role_name);
                END IF;
            END LOOP;
        END $$;
    """)
    )


def downgrade() -> None:
    raise RuntimeError("Review history is archival; use a reviewed forward migration")
