"""Add an empty private Engine 2 collection/snapshot shell.

This migration is authored but must not run on the managed FYP database until
the 0004→0008 reconciliation, retention controls and owner review are complete.
It contains no backfill, AWS call, policy document or account data.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261009_0009"
down_revision: str | None = "20261007_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text("""
        CREATE TABLE foundry.account_connections (
            connection_id varchar(80) PRIMARY KEY,
            project_key varchar(32) NOT NULL,
            account_alias varchar(80) NOT NULL,
            account_fingerprint varchar(76) NOT NULL,
            provider varchar(16) NOT NULL,
            credential_mode varchar(32) NOT NULL,
            profile_alias varchar(64) NOT NULL,
            selected_region varchar(32) NOT NULL,
            enabled boolean NOT NULL,
            created_at timestamptz NOT NULL,
            CONSTRAINT uq_account_connection_fingerprint
                UNIQUE (project_key, account_fingerprint),
            CONSTRAINT ck_account_connection_project CHECK (project_key = 'fyp'),
            CONSTRAINT ck_account_connection_provider CHECK (provider = 'aws'),
            CONSTRAINT ck_account_connection_credential_mode
                CHECK (credential_mode in ('external_profile','synthetic_fixture')),
            CONSTRAINT ck_account_connection_fingerprint
                CHECK (account_fingerprint ~ '^hmac-sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_account_connection_profile
                CHECK (profile_alias ~ '^[A-Za-z0-9_.-]{1,64}$'),
            CONSTRAINT ck_account_connection_alias
                CHECK (account_alias ~ '^[a-z][a-z0-9-]{0,79}$'),
            CONSTRAINT ck_account_connection_region
                CHECK (selected_region ~ '^[a-z]{2}-[a-z]+-[0-9]$')
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_account_connections_enabled ON foundry.account_connections (enabled)"
        )
    )

    op.execute(
        sa.text("""
        CREATE TABLE foundry.collection_runs (
            collection_run_id varchar(80) PRIMARY KEY,
            connection_id varchar(80) NOT NULL
                REFERENCES foundry.account_connections(connection_id),
            retry_of varchar(80),
            request_id varchar(80) NOT NULL UNIQUE,
            status varchar(16) NOT NULL,
            attempt integer NOT NULL,
            collector_version varchar(80) NOT NULL,
            started_at timestamptz,
            finished_at timestamptz,
            error_code varchar(64),
            CONSTRAINT uq_collection_run_connection UNIQUE (collection_run_id, connection_id),
            CONSTRAINT fk_collection_run_retry_connection
                FOREIGN KEY (retry_of, connection_id)
                REFERENCES foundry.collection_runs(collection_run_id, connection_id),
            CONSTRAINT ck_collection_run_status CHECK
                (status in ('queued','running','succeeded','partial','failed','cancelled')),
            CONSTRAINT ck_collection_run_attempt CHECK (attempt between 1 and 10),
            CONSTRAINT ck_collection_run_collector_version CHECK
                (collector_version ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$'),
            CONSTRAINT ck_collection_run_timestamps CHECK (
                (status = 'queued' and started_at is null and finished_at is null) or
                (status = 'running' and started_at is not null and finished_at is null) or
                (status in ('succeeded','partial','failed','cancelled') and
                 started_at is not null and finished_at >= started_at)
            ),
            CONSTRAINT ck_collection_run_error_code CHECK
                (error_code is null or error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
            CONSTRAINT ck_collection_run_error_state CHECK (
                (status in ('queued','running','succeeded') and error_code is null) or
                (status in ('partial','failed','cancelled') and error_code is not null)
            )
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_collection_runs_connection_started "
            "ON foundry.collection_runs (connection_id, started_at)"
        )
    )

    op.execute(
        sa.text("""
        CREATE TABLE foundry.collection_tasks (
            task_id varchar(80) PRIMARY KEY,
            collection_run_id varchar(80) NOT NULL
                REFERENCES foundry.collection_runs(collection_run_id),
            api_name varchar(80) NOT NULL,
            scope_key varchar(76) NOT NULL,
            sequence_no integer NOT NULL,
            attempt integer NOT NULL,
            status varchar(16) NOT NULL,
            page_count integer NOT NULL,
            item_count integer NOT NULL,
            pagination_complete boolean NOT NULL,
            response_digest varchar(71),
            error_code varchar(64),
            CONSTRAINT uq_collection_task_attempt
                UNIQUE (collection_run_id, api_name, scope_key, attempt),
            CONSTRAINT uq_collection_task_sequence
                UNIQUE (collection_run_id, sequence_no),
            CONSTRAINT uq_collection_task_run UNIQUE (task_id, collection_run_id),
            CONSTRAINT ck_collection_task_api_name CHECK
                (api_name ~ '^(iam|organizations):(Get|List|Describe)[A-Za-z0-9]{1,64}$'),
            CONSTRAINT ck_collection_task_scope CHECK
                (scope_key = 'account' or scope_key ~ '^hmac-sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_collection_task_attempt CHECK (attempt between 1 and 10),
            CONSTRAINT ck_collection_task_sequence CHECK (sequence_no between 0 and 999),
            CONSTRAINT ck_collection_task_counts CHECK (page_count >= 0 and item_count >= 0),
            CONSTRAINT ck_collection_task_status CHECK
                (status in ('succeeded','partial','denied','throttled','failed')),
            CONSTRAINT ck_collection_task_outcome CHECK (
                (status = 'succeeded' and pagination_complete and error_code is null
                 and response_digest is not null) or
                (status <> 'succeeded' and error_code is not null)
            ),
            CONSTRAINT ck_collection_task_response_digest CHECK
                (response_digest is null or response_digest ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_collection_task_error_code CHECK
                (error_code is null or error_code ~ '^[a-z][a-z0-9_]{0,63}$')
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_collection_tasks_run_status "
            "ON foundry.collection_tasks (collection_run_id, status)"
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_collection_tasks_run_scope_api "
            "ON foundry.collection_tasks (collection_run_id, scope_key, api_name)"
        )
    )

    op.execute(
        sa.text("""
        CREATE TABLE foundry.account_snapshots (
            snapshot_id varchar(80) PRIMARY KEY,
            connection_id varchar(80) NOT NULL,
            collection_run_id varchar(80) NOT NULL UNIQUE,
            data_kind varchar(32) NOT NULL,
            seal_status varchar(16) NOT NULL,
            content_hash varchar(71) NOT NULL,
            handoff_hash varchar(71) NOT NULL,
            contract_version varchar(32) NOT NULL,
            sealed_at timestamptz NOT NULL,
            retention_expires_at timestamptz NOT NULL,
            CONSTRAINT fk_account_snapshot_run_connection
                FOREIGN KEY (collection_run_id, connection_id)
                REFERENCES foundry.collection_runs(collection_run_id, connection_id),
            CONSTRAINT uq_account_snapshot_run UNIQUE (snapshot_id, collection_run_id),
            CONSTRAINT ck_account_snapshot_data_kind CHECK
                (data_kind in ('synthetic','real_account_observed')),
            CONSTRAINT ck_account_snapshot_seal CHECK (seal_status in ('complete','partial')),
            CONSTRAINT ck_account_snapshot_digest CHECK
                (content_hash ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_account_snapshot_handoff CHECK
                (handoff_hash ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_account_snapshot_retention CHECK
                (retention_expires_at > sealed_at and
                 ((data_kind = 'real_account_observed' and
                   retention_expires_at <= sealed_at + interval '90 days') or
                  (data_kind = 'synthetic' and
                   retention_expires_at <= sealed_at + interval '2 years')))
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_account_snapshots_connection_sealed "
            "ON foundry.account_snapshots (connection_id, sealed_at)"
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_account_snapshots_connection_content "
            "ON foundry.account_snapshots (connection_id, content_hash)"
        )
    )

    op.execute(
        sa.text("""
        CREATE TABLE foundry.collection_layer_coverage (
            snapshot_id varchar(80) NOT NULL,
            collection_run_id varchar(80) NOT NULL,
            layer varchar(32) NOT NULL,
            sequence_no integer NOT NULL,
            state varchar(16) NOT NULL,
            object_count integer,
            reason_code varchar(64),
            authorization_evaluated boolean NOT NULL,
            PRIMARY KEY (snapshot_id, layer),
            CONSTRAINT uq_layer_coverage_sequence UNIQUE (snapshot_id, sequence_no),
            CONSTRAINT ck_layer_coverage_sequence CHECK (sequence_no between 0 and 6),
            CONSTRAINT fk_layer_coverage_snapshot_run
                FOREIGN KEY (snapshot_id, collection_run_id)
                REFERENCES foundry.account_snapshots(snapshot_id, collection_run_id),
            CONSTRAINT ck_layer_coverage_layer CHECK
                (layer in ('identity_policy','trust_policy','permissions_boundary',
                           'service_control_policy','resource_control_policy',
                           'session_policy','resource_policy')),
            CONSTRAINT ck_layer_coverage_state CHECK (
                (state = 'absent' and object_count = 0) or
                (state = 'collected' and object_count >= 0) or
                (state = 'partial' and (object_count is null or object_count >= 0)
                 and reason_code is not null) or
                (state in ('not_collected','unavailable') and object_count is null
                 and reason_code is not null)
            ),
            CONSTRAINT ck_layer_coverage_unevaluated
                CHECK (authorization_evaluated = false),
            CONSTRAINT ck_layer_coverage_reason CHECK
                (reason_code is null or reason_code ~ '^[a-z][a-z0-9_]{0,63}$')
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_layer_coverage_snapshot_state "
            "ON foundry.collection_layer_coverage (snapshot_id, state)"
        )
    )

    op.execute(
        sa.text("""
        CREATE TABLE foundry.coverage_gaps (
            gap_id varchar(80) PRIMARY KEY,
            snapshot_id varchar(80) NOT NULL,
            collection_run_id varchar(80) NOT NULL,
            task_id varchar(80),
            layer varchar(32) NOT NULL,
            scope_key varchar(76) NOT NULL,
            coverage_state varchar(16) NOT NULL,
            reason_code varchar(64) NOT NULL,
            CONSTRAINT fk_coverage_gap_snapshot_run
                FOREIGN KEY (snapshot_id, collection_run_id)
                REFERENCES foundry.account_snapshots(snapshot_id, collection_run_id),
            CONSTRAINT fk_coverage_gap_task_run
                FOREIGN KEY (task_id, collection_run_id)
                REFERENCES foundry.collection_tasks(task_id, collection_run_id),
            CONSTRAINT uq_coverage_gap_reason
                UNIQUE (snapshot_id, layer, scope_key, reason_code),
            CONSTRAINT ck_coverage_gap_layer CHECK
                (layer in ('identity_policy','trust_policy','permissions_boundary',
                           'service_control_policy','resource_control_policy',
                           'session_policy','resource_policy')),
            CONSTRAINT ck_coverage_gap_state CHECK
                (coverage_state in ('partial','not_collected','unavailable')),
            CONSTRAINT ck_coverage_gap_scope CHECK
                (scope_key = 'account' or scope_key ~ '^hmac-sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_coverage_gap_reason CHECK
                (reason_code ~ '^[a-z][a-z0-9_]{0,63}$')
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_coverage_gaps_snapshot_reason "
            "ON foundry.coverage_gaps (snapshot_id, reason_code)"
        )
    )

    op.execute(
        sa.text("""
        REVOKE ALL ON foundry.account_connections, foundry.collection_runs,
            foundry.collection_tasks, foundry.account_snapshots,
            foundry.collection_layer_coverage, foundry.coverage_gaps FROM PUBLIC
    """)
    )
    op.execute(
        sa.text("""
        DO $$ DECLARE role_name text;
        BEGIN
            FOREACH role_name IN ARRAY ARRAY['anon','authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
                    EXECUTE format(
                        'REVOKE ALL ON foundry.account_connections, foundry.collection_runs, '
                        || 'foundry.collection_tasks, foundry.account_snapshots, '
                        || 'foundry.collection_layer_coverage, foundry.coverage_gaps FROM %I',
                        role_name
                    );
                END IF;
            END LOOP;
        END $$;
    """)
    )
    # New account-data tables start fail-closed even if a future grant changes.
    # No browser-facing policies are created; a backend role plan is separate.
    for table in (
        "account_connections",
        "collection_runs",
        "collection_tasks",
        "account_snapshots",
        "collection_layer_coverage",
        "coverage_gaps",
    ):
        op.execute(sa.text(f"ALTER TABLE foundry.{table} ENABLE ROW LEVEL SECURITY"))


def downgrade() -> None:
    raise RuntimeError("Snapshot evidence is archival; use a reviewed forward migration")
