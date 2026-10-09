"""Retain exact verifier requests/results without rewriting prior AI history."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0006"
down_revision: str | None = "20261003_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text("""
        CREATE TABLE IF NOT EXISTS foundry.verifier_packets (
            packet_id varchar(80) PRIMARY KEY,
            pipeline_run_id varchar(80) NOT NULL REFERENCES foundry.pipeline_runs(run_id),
            rule_version_id varchar(80) NOT NULL REFERENCES foundry.rule_versions(version_id),
            request_hash varchar(80) NOT NULL,
            response_hash varchar(80) NOT NULL,
            request_json text NOT NULL,
            response_json text NOT NULL,
            created_at timestamptz NOT NULL,
            CONSTRAINT uq_verifier_run_binding
                UNIQUE (pipeline_run_id, request_hash, response_hash),
            CONSTRAINT ck_verifier_request_size CHECK (octet_length(request_json) <= 65536),
            CONSTRAINT ck_verifier_response_size CHECK (octet_length(response_json) <= 262144)
        )
    """)
    )
    op.execute(sa.text("REVOKE ALL ON foundry.verifier_packets FROM PUBLIC"))
    op.execute(
        sa.text("""
        DO $$ DECLARE role_name text;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
                    EXECUTE format('REVOKE ALL ON foundry.verifier_packets FROM %I', role_name);
                END IF;
            END LOOP;
        END $$;
    """)
    )


def downgrade() -> None:
    raise RuntimeError("Verifier history is archival; use a reviewed forward migration")
