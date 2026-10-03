"""Widen foundry checks and add AI suggestion rows. No production data is migrated."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0003"
down_revision: str | None = "20261003_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ENTITY = (
    "entity_type in ('technique','attack_behavior','cloud_behavior','aws_service',"
    "'aws_action','aws_resource','condition_key','vulnerability','mitigation',"
    "'attack_primitive_ref','scenario')"
)
_SOURCE = (
    "source_type in ('taxonomy','service_reference','community_behavior',"
    "'contextual','threat_catalog')"
)


def upgrade() -> None:
    op.execute(
        sa.text("ALTER TABLE foundry.normalized_entities DROP CONSTRAINT IF EXISTS ck_entity_type")
    )
    op.create_check_constraint("ck_entity_type", "normalized_entities", _ENTITY, schema="foundry")
    op.execute(sa.text("ALTER TABLE foundry.sources DROP CONSTRAINT IF EXISTS ck_sources_type"))
    op.create_check_constraint("ck_sources_type", "sources", _SOURCE, schema="foundry")
    op.execute(
        sa.text(
            """
            CREATE TABLE IF NOT EXISTS foundry.ai_suggestions (
                suggestion_id VARCHAR(80) PRIMARY KEY,
                verification_id VARCHAR(80) NOT NULL
                    REFERENCES foundry.ai_verifications(verification_id),
                rule_version_id VARCHAR(80) NOT NULL
                    REFERENCES foundry.rule_versions(version_id),
                suggestion_json TEXT NOT NULL,
                recorded_at TIMESTAMPTZ NOT NULL
            )
            """
        )
    )


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS foundry.ai_suggestions"))
    op.execute(
        sa.text("ALTER TABLE foundry.normalized_entities DROP CONSTRAINT IF EXISTS ck_entity_type")
    )
    op.create_check_constraint(
        "ck_entity_type",
        "normalized_entities",
        "entity_type in ('technique','cloud_behavior','aws_action','aws_resource',"
        "'condition_key','vulnerability','mitigation','attack_primitive_ref')",
        schema="foundry",
    )
    op.execute(sa.text("ALTER TABLE foundry.sources DROP CONSTRAINT IF EXISTS ck_sources_type"))
    op.create_check_constraint(
        "ck_sources_type",
        "sources",
        "source_type in ('taxonomy','service_reference','community_behavior','contextual')",
        schema="foundry",
    )
