"""Proposed private storage for observed-only graph projections.

These tables are not an authorization evaluator. The separate metadata also
keeps historical Engine 1 ``create_all`` migrations from creating them early.
"""

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    text,
)

metadata = MetaData(schema="foundry")

graph_projections = Table(
    "graph_projections",
    metadata,
    Column(
        "snapshot_id",
        String(80),
        ForeignKey("foundry.account_snapshots.snapshot_id"),
        primary_key=True,
    ),
    Column("inventory_digest", String(71), nullable=False),
    Column("handoff_digest", String(71), nullable=False),
    Column("projection_digest", String(71), nullable=False),
    Column("resolver_version", String(80), nullable=False),
    Column("generated_at", DateTime(timezone=True), nullable=False),
    Column("source_coverage_complete", Boolean, nullable=False),
    Column("incomplete_reason_codes", ARRAY(String(80)), nullable=False),
    Column("authorization_evaluated", Boolean, nullable=False, server_default="false"),
    CheckConstraint(
        "inventory_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_graph_projection_inventory_digest"
    ),
    CheckConstraint(
        "handoff_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_graph_projection_handoff_digest"
    ),
    CheckConstraint(
        "projection_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_graph_projection_digest"
    ),
    CheckConstraint(
        "resolver_version ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$'",
        name="ck_graph_projection_version",
    ),
    CheckConstraint(
        "authorization_evaluated = false", name="ck_graph_projection_not_authorization"
    ),
    CheckConstraint(
        "source_coverage_complete = (cardinality(incomplete_reason_codes) = 0) "
        "and cardinality(incomplete_reason_codes) <= 32",
        name="ck_graph_projection_coverage_reasons",
    ),
)

graph_nodes = Table(
    "graph_nodes",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("node_key", String(36), primary_key=True),
    Column("principal_key", String(34)),
    Column("policy_key", String(36)),
    Column("kind", String(16), nullable=False),
    Column("display_alias", String(32)),
    Column("source_digest", String(71), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id"],
        ["foundry.graph_projections.snapshot_id"],
        name="fk_graph_node_projection",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "principal_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_graph_node_principal",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "policy_key"],
        ["foundry.iam_policies.snapshot_id", "foundry.iam_policies.policy_key"],
        name="fk_graph_node_policy",
    ),
    CheckConstraint("node_key ~ '^(p_|pol_|svc_)[0-9a-f]{32}$'", name="ck_graph_node_key"),
    CheckConstraint(
        "kind in ('iam_user','iam_role','iam_group','policy','service')",
        name="ck_graph_node_kind",
    ),
    CheckConstraint(
        "(kind in ('iam_user','iam_role','iam_group') and principal_key is not null "
        "and principal_key = node_key and policy_key is null) or "
        "(kind = 'policy' and policy_key is not null and policy_key = node_key "
        "and principal_key is null) or "
        "(kind = 'service' and node_key ~ '^svc_' and principal_key is null "
        "and policy_key is null)",
        name="ck_graph_node_key_kind",
    ),
    CheckConstraint(
        "(kind = 'iam_user' and display_alias is not null and "
        "display_alias ~ '^user-[0-9a-f]{8}$') or "
        "(kind = 'iam_role' and display_alias is not null and "
        "display_alias ~ '^role-[0-9a-f]{8}$') or "
        "(kind = 'iam_group' and display_alias is not null and "
        "display_alias ~ '^group-[0-9a-f]{8}$') or "
        "(kind in ('policy','service') and display_alias is null)",
        name="ck_graph_node_alias",
    ),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_graph_node_digest"),
    Index("ix_graph_nodes_kind", "snapshot_id", "kind"),
)

graph_edges = Table(
    "graph_edges",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("relation_id", String(36), primary_key=True),
    Column("kind", String(40), nullable=False),
    Column("source_key", String(36), nullable=False),
    Column("target_key", String(36), nullable=False),
    Column("source_digest", String(71), nullable=False),
    Column("effect", String(8)),
    Column("condition_state", String(16)),
    Column("derivation", String(32), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id"],
        ["foundry.graph_projections.snapshot_id"],
        name="fk_graph_edge_projection",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "source_key"],
        ["foundry.graph_nodes.snapshot_id", "foundry.graph_nodes.node_key"],
        name="fk_graph_edge_source",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "target_key"],
        ["foundry.graph_nodes.snapshot_id", "foundry.graph_nodes.node_key"],
        name="fk_graph_edge_target",
    ),
    CheckConstraint("relation_id ~ '^rel_[0-9a-f]{32}$'", name="ck_graph_edge_key"),
    CheckConstraint(
        "kind in ('policy_attachment','permissions_boundary_attachment',"
        "'group_membership','role_trust_policy','trust_selector_reference')",
        name="ck_graph_edge_kind",
    ),
    CheckConstraint("derivation = 'observed_configuration'", name="ck_graph_edge_derivation"),
    CheckConstraint("effect is null or effect in ('allow','deny')", name="ck_graph_edge_effect"),
    CheckConstraint(
        "condition_state is null or condition_state in ('absent','unevaluated','unsupported')",
        name="ck_graph_edge_condition",
    ),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_graph_edge_digest"),
    Index("ix_graph_edges_source", "snapshot_id", "source_key", "kind"),
    Index("ix_graph_edges_target", "snapshot_id", "target_key"),
)

edge_policy_evidence = Table(
    "edge_policy_evidence",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("relation_id", String(36), primary_key=True),
    Column("evidence_ordinal", Integer, primary_key=True),
    Column("evidence_role", String(16), nullable=False),
    Column("policy_key", String(36)),
    Column("identity_statement_key", String(35)),
    Column("trust_statement_key", String(35)),
    ForeignKeyConstraint(
        ["snapshot_id", "relation_id"],
        ["foundry.graph_edges.snapshot_id", "foundry.graph_edges.relation_id"],
        name="fk_edge_evidence_edge",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "policy_key"],
        ["foundry.iam_policies.snapshot_id", "foundry.iam_policies.policy_key"],
        name="fk_edge_evidence_policy",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "identity_statement_key"],
        [
            "foundry.iam_identity_statements.snapshot_id",
            "foundry.iam_identity_statements.statement_key",
        ],
        name="fk_edge_evidence_identity",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "trust_statement_key"],
        ["foundry.iam_trust_statements.snapshot_id", "foundry.iam_trust_statements.statement_key"],
        name="fk_edge_evidence_trust",
    ),
    CheckConstraint("evidence_ordinal between 0 and 99", name="ck_edge_evidence_ordinal"),
    CheckConstraint(
        "evidence_role in ('anchors','supports','contradicts','limits')",
        name="ck_edge_evidence_role",
    ),
    CheckConstraint(
        "(policy_key is not null)::integer + "
        "(identity_statement_key is not null)::integer + "
        "(trust_statement_key is not null)::integer = 1",
        name="ck_edge_evidence_one_source",
    ),
    Index(
        "ix_edge_evidence_policy",
        "snapshot_id",
        "policy_key",
        postgresql_where=text("policy_key IS NOT NULL"),
    ),
)
