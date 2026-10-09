"""Record that redacted snapshot bodies were purged. Unapplied on the managed database.

The tombstone stores hashes and timestamps only. It does not backfill AWS data
and it is not authorization to import a real-account snapshot.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261009_0012"
down_revision: str | None = "20261009_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text("""
        CREATE TABLE foundry.snapshot_purge_tombstones (
            snapshot_id varchar(80) PRIMARY KEY
                REFERENCES foundry.account_snapshots(snapshot_id),
            content_hash varchar(71) NOT NULL,
            handoff_hash varchar(71) NOT NULL,
            data_kind varchar(32) NOT NULL,
            sealed_at timestamptz NOT NULL,
            retention_expires_at timestamptz NOT NULL,
            purged_at timestamptz NOT NULL,
            purge_reason varchar(64) NOT NULL,
            CONSTRAINT ck_snapshot_purge_data_kind CHECK
                (data_kind in ('synthetic','real_account_observed')),
            CONSTRAINT ck_snapshot_purge_content CHECK
                (content_hash ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_snapshot_purge_handoff CHECK
                (handoff_hash ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_snapshot_purge_reason CHECK
                (purge_reason in ('retention_elapsed','operator_purge')),
            CONSTRAINT ck_snapshot_purge_after_seal CHECK (purged_at >= sealed_at),
            CONSTRAINT ck_snapshot_purge_retention CHECK
                (retention_expires_at > sealed_at)
        )
    """)
    )
    op.execute(sa.text("REVOKE ALL ON foundry.snapshot_purge_tombstones FROM PUBLIC"))
    bind = op.get_bind()
    for role in ("anon", "authenticated"):
        exists = bind.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
            {"role": role},
        ).scalar_one()
        if exists:
            op.execute(sa.text(f"REVOKE ALL ON foundry.snapshot_purge_tombstones FROM {role}"))
    op.execute(sa.text("ALTER TABLE foundry.snapshot_purge_tombstones ENABLE ROW LEVEL SECURITY"))


def downgrade() -> None:
    raise RuntimeError("Snapshot purge history is archival; use a reviewed forward migration")
