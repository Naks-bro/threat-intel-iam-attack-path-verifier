"""Draft private, snapshot-scoped observed graph storage; never a permission verdict.

Unapplied on the managed database. No backfill or AWS data. Review the exact
schema and disposable rehearsal before any managed migration is considered.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261009_0011"
down_revision: str | None = "20261009_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("graph_projections", "graph_nodes", "graph_edges", "edge_policy_evidence")


def upgrade() -> None:
    op.execute(
        sa.text("""
        CREATE TABLE foundry.graph_projections (
            snapshot_id varchar(80) PRIMARY KEY
                REFERENCES foundry.account_snapshots(snapshot_id),
            inventory_digest varchar(71) NOT NULL,
            handoff_digest varchar(71) NOT NULL,
            projection_digest varchar(71) NOT NULL,
            resolver_version varchar(80) NOT NULL,
            generated_at timestamptz NOT NULL,
            source_coverage_complete boolean NOT NULL,
            incomplete_reason_codes varchar(80)[] NOT NULL,
            authorization_evaluated boolean NOT NULL DEFAULT false,
            CONSTRAINT ck_graph_projection_inventory_digest CHECK
                (inventory_digest ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_graph_projection_handoff_digest CHECK
                (handoff_digest ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_graph_projection_digest CHECK
                (projection_digest ~ '^sha256:[0-9a-f]{64}$'),
            CONSTRAINT ck_graph_projection_version CHECK
                (resolver_version ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$'),
            CONSTRAINT ck_graph_projection_not_authorization CHECK
                (authorization_evaluated = false),
            CONSTRAINT ck_graph_projection_coverage_reasons CHECK
                (source_coverage_complete = (cardinality(incomplete_reason_codes) = 0)
                 and cardinality(incomplete_reason_codes) <= 32)
        )
    """)
    )
    op.execute(
        sa.text("""
        CREATE TABLE foundry.graph_nodes (
            snapshot_id varchar(80) NOT NULL,
            node_key varchar(36) NOT NULL,
            principal_key varchar(34),
            policy_key varchar(36),
            kind varchar(16) NOT NULL,
            display_alias varchar(32),
            source_digest varchar(71) NOT NULL,
            PRIMARY KEY (snapshot_id, node_key),
            CONSTRAINT fk_graph_node_projection FOREIGN KEY (snapshot_id)
                REFERENCES foundry.graph_projections(snapshot_id),
            CONSTRAINT fk_graph_node_principal FOREIGN KEY (snapshot_id, principal_key)
                REFERENCES foundry.iam_principals(snapshot_id, principal_key),
            CONSTRAINT fk_graph_node_policy FOREIGN KEY (snapshot_id, policy_key)
                REFERENCES foundry.iam_policies(snapshot_id, policy_key),
            CONSTRAINT ck_graph_node_key CHECK
                (node_key ~ '^(p_|pol_|svc_)[0-9a-f]{32}$'),
            CONSTRAINT ck_graph_node_kind CHECK
                (kind in ('iam_user','iam_role','iam_group','policy','service')),
            CONSTRAINT ck_graph_node_key_kind CHECK
                ((kind in ('iam_user','iam_role','iam_group') and
                  principal_key is not null and principal_key = node_key and
                  policy_key is null) or
                 (kind = 'policy' and policy_key is not null and
                  policy_key = node_key and principal_key is null) or
                 (kind = 'service' and node_key ~ '^svc_' and
                  principal_key is null and policy_key is null)),
            CONSTRAINT ck_graph_node_alias CHECK
                ((kind = 'iam_user' and display_alias is not null and
                  display_alias ~ '^user-[0-9a-f]{8}$') or
                 (kind = 'iam_role' and display_alias is not null and
                  display_alias ~ '^role-[0-9a-f]{8}$') or
                 (kind = 'iam_group' and display_alias is not null and
                  display_alias ~ '^group-[0-9a-f]{8}$') or
                 (kind in ('policy','service') and display_alias is null)),
            CONSTRAINT ck_graph_node_digest CHECK
                (source_digest ~ '^sha256:[0-9a-f]{64}$')
        )
    """)
    )
    op.execute(
        sa.text("CREATE INDEX ix_graph_nodes_kind ON foundry.graph_nodes (snapshot_id, kind)")
    )
    op.execute(
        sa.text("""
        CREATE TABLE foundry.graph_edges (
            snapshot_id varchar(80) NOT NULL,
            relation_id varchar(36) NOT NULL,
            kind varchar(40) NOT NULL,
            source_key varchar(36) NOT NULL,
            target_key varchar(36) NOT NULL,
            source_digest varchar(71) NOT NULL,
            effect varchar(8),
            condition_state varchar(16),
            derivation varchar(32) NOT NULL,
            PRIMARY KEY (snapshot_id, relation_id),
            CONSTRAINT fk_graph_edge_projection FOREIGN KEY (snapshot_id)
                REFERENCES foundry.graph_projections(snapshot_id),
            CONSTRAINT fk_graph_edge_source FOREIGN KEY (snapshot_id, source_key)
                REFERENCES foundry.graph_nodes(snapshot_id, node_key),
            CONSTRAINT fk_graph_edge_target FOREIGN KEY (snapshot_id, target_key)
                REFERENCES foundry.graph_nodes(snapshot_id, node_key),
            CONSTRAINT ck_graph_edge_key CHECK
                (relation_id ~ '^rel_[0-9a-f]{32}$'),
            CONSTRAINT ck_graph_edge_kind CHECK
                (kind in ('policy_attachment','permissions_boundary_attachment',
                          'group_membership','role_trust_policy','trust_selector_reference')),
            CONSTRAINT ck_graph_edge_derivation CHECK
                (derivation = 'observed_configuration'),
            CONSTRAINT ck_graph_edge_effect CHECK
                (effect is null or effect in ('allow','deny')),
            CONSTRAINT ck_graph_edge_condition CHECK
                (condition_state is null or
                 condition_state in ('absent','unevaluated','unsupported')),
            CONSTRAINT ck_graph_edge_digest CHECK
                (source_digest ~ '^sha256:[0-9a-f]{64}$')
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_graph_edges_source ON foundry.graph_edges "
            "(snapshot_id, source_key, kind)"
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_graph_edges_target ON foundry.graph_edges (snapshot_id, target_key)"
        )
    )
    op.execute(
        sa.text("""
        CREATE TABLE foundry.edge_policy_evidence (
            snapshot_id varchar(80) NOT NULL,
            relation_id varchar(36) NOT NULL,
            evidence_ordinal integer NOT NULL,
            evidence_role varchar(16) NOT NULL,
            policy_key varchar(36),
            identity_statement_key varchar(35),
            trust_statement_key varchar(35),
            PRIMARY KEY (snapshot_id, relation_id, evidence_ordinal),
            CONSTRAINT fk_edge_evidence_edge FOREIGN KEY (snapshot_id, relation_id)
                REFERENCES foundry.graph_edges(snapshot_id, relation_id),
            CONSTRAINT fk_edge_evidence_policy FOREIGN KEY (snapshot_id, policy_key)
                REFERENCES foundry.iam_policies(snapshot_id, policy_key),
            CONSTRAINT fk_edge_evidence_identity FOREIGN KEY
                (snapshot_id, identity_statement_key)
                REFERENCES foundry.iam_identity_statements(snapshot_id, statement_key),
            CONSTRAINT fk_edge_evidence_trust FOREIGN KEY
                (snapshot_id, trust_statement_key)
                REFERENCES foundry.iam_trust_statements(snapshot_id, statement_key),
            CONSTRAINT ck_edge_evidence_ordinal CHECK
                (evidence_ordinal between 0 and 99),
            CONSTRAINT ck_edge_evidence_role CHECK
                (evidence_role in ('anchors','supports','contradicts','limits')),
            CONSTRAINT ck_edge_evidence_one_source CHECK
                ((policy_key is not null)::integer +
                 (identity_statement_key is not null)::integer +
                 (trust_statement_key is not null)::integer = 1)
        )
    """)
    )
    op.execute(
        sa.text(
            "CREATE INDEX ix_edge_evidence_policy ON foundry.edge_policy_evidence "
            "(snapshot_id, policy_key) WHERE policy_key IS NOT NULL"
        )
    )
    tables = ", ".join(f"foundry.{name}" for name in _TABLES)
    op.execute(sa.text(f"REVOKE ALL ON {tables} FROM PUBLIC"))
    bind = op.get_bind()
    for role in ("anon", "authenticated"):
        exists = bind.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
            {"role": role},
        ).scalar_one()
        if exists:
            op.execute(sa.text(f"REVOKE ALL ON {tables} FROM {role}"))
    for table in _TABLES:
        op.execute(sa.text(f"ALTER TABLE foundry.{table} ENABLE ROW LEVEL SECURITY"))


def downgrade() -> None:
    raise RuntimeError("Graph evidence is archival; use a reviewed forward migration")
