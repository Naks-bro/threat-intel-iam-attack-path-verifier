"""Keep foundry tables out of the exposed public schema.

Supabase API roles are revoked when they exist. CI PostgreSQL does not have those
roles, and this migration does not create them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0004"
down_revision: str | None = "20261003_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REVOKE = """
DO $$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated']
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('REVOKE ALL ON SCHEMA foundry FROM %I', role_name);
            EXECUTE format(
                'REVOKE ALL ON ALL TABLES IN SCHEMA foundry FROM %I', role_name
            );
            EXECUTE format(
                'ALTER DEFAULT PRIVILEGES IN SCHEMA foundry REVOKE ALL ON TABLES FROM %I',
                role_name
            );
        END IF;
    END LOOP;
END $$;
"""


def upgrade() -> None:
    op.execute(sa.text("CREATE SCHEMA IF NOT EXISTS foundry"))
    op.execute(sa.text("REVOKE ALL ON SCHEMA foundry FROM PUBLIC"))
    from fyp_iam.engine1.foundry.models import Base

    for table in Base.metadata.tables.values():
        op.execute(
            sa.text(
                f"""
                DO $$
                BEGIN
                    IF to_regclass('public.{table.name}') IS NOT NULL
                       AND to_regclass('foundry.{table.name}') IS NULL THEN
                        EXECUTE 'ALTER TABLE public.{table.name} SET SCHEMA foundry';
                    END IF;
                END $$;
                """
            )
        )
    op.execute(sa.text(_REVOKE))


def downgrade() -> None:
    op.execute(sa.text("GRANT USAGE ON SCHEMA foundry TO PUBLIC"))
