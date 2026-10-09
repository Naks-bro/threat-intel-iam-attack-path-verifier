"""Retain scoped stable releases without inferring legacy approval."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261007_0008"
down_revision: str | None = "20261003_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 0002 imports current metadata, so fresh and deployed upgrades must both work.
    op.execute(
        sa.text("""
        CREATE TABLE IF NOT EXISTS foundry.stable_releases (
            release_id varchar(80) PRIMARY KEY,
            request_id varchar(80) NOT NULL UNIQUE,
            rule_version_id varchar(80) NOT NULL REFERENCES foundry.rule_versions(version_id),
            review_decision_id varchar(80) NOT NULL REFERENCES foundry.scoped_reviews(decision_id),
            scope varchar(32) NOT NULL,
            record_json text NOT NULL,
            record_hash varchar(80) NOT NULL,
            published_at timestamptz NOT NULL,
            CONSTRAINT ck_stable_release_size CHECK (octet_length(record_json) <= 131072)
        )
    """)
    )
    op.execute(sa.text("REVOKE ALL ON foundry.stable_releases FROM PUBLIC"))
    op.execute(
        sa.text("""
        DO $$ DECLARE role_name text;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
                    EXECUTE format('REVOKE ALL ON foundry.stable_releases FROM %I', role_name);
                END IF;
            END LOOP;
        END $$;
    """)
    )


def downgrade() -> None:
    raise RuntimeError("Stable release history is archival; use a reviewed forward migration")
