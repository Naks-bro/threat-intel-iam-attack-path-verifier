"""Replace the checkpoint tables with the foundry schema. No production rows exist."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261003_0002"
down_revision: str | None = "20261003_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CHECKPOINT = (
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
)


def upgrade() -> None:
    op.execute(sa.text("CREATE SCHEMA IF NOT EXISTS foundry"))
    for name in _CHECKPOINT:
        op.execute(sa.text(f"DROP TABLE IF EXISTS public.{name} CASCADE"))
    from fyp_iam.engine1.foundry.models import Base

    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    from fyp_iam.engine1.foundry.models import Base

    Base.metadata.drop_all(op.get_bind())
