"""Proposed Engine 2 storage shell; no AWS credentials or policy bodies.

Separate metadata prevents historical migration 0002's evolving Engine 1
``create_all`` call from creating Engine 2 tables before migration 0009.
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
    UniqueConstraint,
)

metadata = MetaData(schema="foundry")

account_connections = Table(
    "account_connections",
    metadata,
    Column("connection_id", String(80), primary_key=True),
    Column("project_key", String(32), nullable=False),
    Column("account_alias", String(80), nullable=False),
    Column("account_fingerprint", String(76), nullable=False),
    Column("provider", String(16), nullable=False),
    Column("credential_mode", String(32), nullable=False),
    Column("profile_alias", String(64), nullable=False),
    Column("selected_region", String(32), nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    UniqueConstraint(
        "project_key", "account_fingerprint", name="uq_account_connection_fingerprint"
    ),
    CheckConstraint("project_key = 'fyp'", name="ck_account_connection_project"),
    CheckConstraint("provider = 'aws'", name="ck_account_connection_provider"),
    CheckConstraint(
        "credential_mode in ('external_profile','synthetic_fixture')",
        name="ck_account_connection_credential_mode",
    ),
    CheckConstraint(
        "account_fingerprint ~ '^hmac-sha256:[0-9a-f]{64}$'",
        name="ck_account_connection_fingerprint",
    ),
    CheckConstraint(
        "profile_alias ~ '^[A-Za-z0-9_.-]{1,64}$'", name="ck_account_connection_profile"
    ),
    CheckConstraint("account_alias ~ '^[a-z][a-z0-9-]{0,79}$'", name="ck_account_connection_alias"),
    CheckConstraint(
        "selected_region ~ '^[a-z]{2}-[a-z]+-[0-9]$'",
        name="ck_account_connection_region",
    ),
    Index("ix_account_connections_enabled", "enabled"),
)

collection_runs = Table(
    "collection_runs",
    metadata,
    Column("collection_run_id", String(80), primary_key=True),
    Column(
        "connection_id",
        String(80),
        ForeignKey("foundry.account_connections.connection_id"),
        nullable=False,
    ),
    Column("retry_of", String(80)),
    Column("request_id", String(80), nullable=False, unique=True),
    Column("status", String(16), nullable=False),
    Column("attempt", Integer, nullable=False),
    Column("collector_version", String(80), nullable=False),
    Column("started_at", DateTime(timezone=True)),
    Column("finished_at", DateTime(timezone=True)),
    Column("error_code", String(64)),
    UniqueConstraint("collection_run_id", "connection_id", name="uq_collection_run_connection"),
    ForeignKeyConstraint(
        ["retry_of", "connection_id"],
        ["foundry.collection_runs.collection_run_id", "foundry.collection_runs.connection_id"],
        name="fk_collection_run_retry_connection",
    ),
    CheckConstraint(
        "status in ('queued','running','succeeded','partial','failed','cancelled')",
        name="ck_collection_run_status",
    ),
    CheckConstraint("attempt between 1 and 10", name="ck_collection_run_attempt"),
    CheckConstraint(
        "collector_version ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$'",
        name="ck_collection_run_collector_version",
    ),
    CheckConstraint(
        "(status = 'queued' and started_at is null and finished_at is null) or "
        "(status = 'running' and started_at is not null and finished_at is null) or "
        "(status in ('succeeded','partial','failed','cancelled') and "
        "started_at is not null and finished_at >= started_at)",
        name="ck_collection_run_timestamps",
    ),
    CheckConstraint(
        "error_code is null or error_code ~ '^[a-z][a-z0-9_]{0,63}$'",
        name="ck_collection_run_error_code",
    ),
    CheckConstraint(
        "(status in ('queued','running','succeeded') and error_code is null) or "
        "(status in ('partial','failed','cancelled') and error_code is not null)",
        name="ck_collection_run_error_state",
    ),
    Index("ix_collection_runs_connection_started", "connection_id", "started_at"),
)

collection_tasks = Table(
    "collection_tasks",
    metadata,
    Column("task_id", String(80), primary_key=True),
    Column(
        "collection_run_id",
        String(80),
        ForeignKey("foundry.collection_runs.collection_run_id"),
        nullable=False,
    ),
    Column("api_name", String(80), nullable=False),
    Column("scope_key", String(76), nullable=False),
    Column("sequence_no", Integer, nullable=False),
    Column("attempt", Integer, nullable=False),
    Column("status", String(16), nullable=False),
    Column("page_count", Integer, nullable=False),
    Column("item_count", Integer, nullable=False),
    Column("pagination_complete", Boolean, nullable=False),
    Column("response_digest", String(71)),
    Column("error_code", String(64)),
    UniqueConstraint(
        "collection_run_id", "api_name", "scope_key", "attempt", name="uq_collection_task_attempt"
    ),
    UniqueConstraint("collection_run_id", "sequence_no", name="uq_collection_task_sequence"),
    UniqueConstraint("task_id", "collection_run_id", name="uq_collection_task_run"),
    CheckConstraint(
        "api_name ~ '^(iam|organizations):(Get|List|Describe)[A-Za-z0-9]{1,64}$'",
        name="ck_collection_task_api_name",
    ),
    CheckConstraint(
        "scope_key = 'account' or scope_key ~ '^hmac-sha256:[0-9a-f]{64}$'",
        name="ck_collection_task_scope",
    ),
    CheckConstraint("attempt between 1 and 10", name="ck_collection_task_attempt"),
    CheckConstraint("sequence_no between 0 and 999", name="ck_collection_task_sequence"),
    CheckConstraint("page_count >= 0 and item_count >= 0", name="ck_collection_task_counts"),
    CheckConstraint(
        "status in ('succeeded','partial','denied','throttled','failed')",
        name="ck_collection_task_status",
    ),
    CheckConstraint(
        "(status = 'succeeded' and pagination_complete and error_code is null "
        "and response_digest is not null) or "
        "(status <> 'succeeded' and error_code is not null)",
        name="ck_collection_task_outcome",
    ),
    CheckConstraint(
        "response_digest is null or response_digest ~ '^sha256:[0-9a-f]{64}$'",
        name="ck_collection_task_response_digest",
    ),
    CheckConstraint(
        "error_code is null or error_code ~ '^[a-z][a-z0-9_]{0,63}$'",
        name="ck_collection_task_error_code",
    ),
    Index("ix_collection_tasks_run_status", "collection_run_id", "status"),
    Index("ix_collection_tasks_run_scope_api", "collection_run_id", "scope_key", "api_name"),
)

account_snapshots = Table(
    "account_snapshots",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("connection_id", String(80), nullable=False),
    Column("collection_run_id", String(80), nullable=False, unique=True),
    Column("data_kind", String(32), nullable=False),
    Column("seal_status", String(16), nullable=False),
    Column("content_hash", String(71), nullable=False),
    Column("handoff_hash", String(71), nullable=False),
    Column("contract_version", String(32), nullable=False),
    Column("sealed_at", DateTime(timezone=True), nullable=False),
    Column("retention_expires_at", DateTime(timezone=True), nullable=False),
    ForeignKeyConstraint(
        ["collection_run_id", "connection_id"],
        ["foundry.collection_runs.collection_run_id", "foundry.collection_runs.connection_id"],
        name="fk_account_snapshot_run_connection",
    ),
    UniqueConstraint("snapshot_id", "collection_run_id", name="uq_account_snapshot_run"),
    CheckConstraint(
        "data_kind in ('synthetic','real_account_observed')", name="ck_account_snapshot_data_kind"
    ),
    CheckConstraint("seal_status in ('complete','partial')", name="ck_account_snapshot_seal"),
    CheckConstraint("content_hash ~ '^sha256:[0-9a-f]{64}$'", name="ck_account_snapshot_digest"),
    CheckConstraint("handoff_hash ~ '^sha256:[0-9a-f]{64}$'", name="ck_account_snapshot_handoff"),
    CheckConstraint(
        "retention_expires_at > sealed_at and ("
        "(data_kind = 'real_account_observed' and "
        "retention_expires_at <= sealed_at + interval '90 days') or "
        "(data_kind = 'synthetic' and "
        "retention_expires_at <= sealed_at + interval '2 years'))",
        name="ck_account_snapshot_retention",
    ),
    Index("ix_account_snapshots_connection_sealed", "connection_id", "sealed_at"),
    Index("ix_account_snapshots_connection_content", "connection_id", "content_hash"),
)

collection_layer_coverage = Table(
    "collection_layer_coverage",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("collection_run_id", String(80), nullable=False),
    Column("layer", String(32), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("state", String(16), nullable=False),
    Column("object_count", Integer),
    Column("reason_code", String(64)),
    Column("authorization_evaluated", Boolean, nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id", "collection_run_id"],
        ["foundry.account_snapshots.snapshot_id", "foundry.account_snapshots.collection_run_id"],
        name="fk_layer_coverage_snapshot_run",
    ),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_layer_coverage_sequence"),
    CheckConstraint("sequence_no between 0 and 6", name="ck_layer_coverage_sequence"),
    CheckConstraint(
        "layer in ('identity_policy','trust_policy','permissions_boundary',"
        "'service_control_policy','resource_control_policy','session_policy',"
        "'resource_policy')",
        name="ck_layer_coverage_layer",
    ),
    CheckConstraint(
        "(state = 'absent' and object_count = 0) or "
        "(state = 'collected' and object_count >= 0) or "
        "(state = 'partial' and (object_count is null or object_count >= 0) "
        "and reason_code is not null) or "
        "(state in ('not_collected','unavailable') and object_count is null "
        "and reason_code is not null)",
        name="ck_layer_coverage_state",
    ),
    CheckConstraint("authorization_evaluated = false", name="ck_layer_coverage_unevaluated"),
    CheckConstraint(
        "reason_code is null or reason_code ~ '^[a-z][a-z0-9_]{0,63}$'",
        name="ck_layer_coverage_reason",
    ),
    Index("ix_layer_coverage_snapshot_state", "snapshot_id", "state"),
)

coverage_gaps = Table(
    "coverage_gaps",
    metadata,
    Column("gap_id", String(80), primary_key=True),
    Column("snapshot_id", String(80), nullable=False),
    Column("collection_run_id", String(80), nullable=False),
    Column("task_id", String(80)),
    Column("layer", String(32), nullable=False),
    Column("scope_key", String(76), nullable=False),
    Column("coverage_state", String(16), nullable=False),
    Column("reason_code", String(64), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id", "collection_run_id"],
        ["foundry.account_snapshots.snapshot_id", "foundry.account_snapshots.collection_run_id"],
        name="fk_coverage_gap_snapshot_run",
    ),
    ForeignKeyConstraint(
        ["task_id", "collection_run_id"],
        ["foundry.collection_tasks.task_id", "foundry.collection_tasks.collection_run_id"],
        name="fk_coverage_gap_task_run",
    ),
    UniqueConstraint(
        "snapshot_id", "layer", "scope_key", "reason_code", name="uq_coverage_gap_reason"
    ),
    CheckConstraint(
        "layer in ('identity_policy','trust_policy','permissions_boundary',"
        "'service_control_policy','resource_control_policy','session_policy',"
        "'resource_policy')",
        name="ck_coverage_gap_layer",
    ),
    CheckConstraint(
        "coverage_state in ('partial','not_collected','unavailable')",
        name="ck_coverage_gap_state",
    ),
    CheckConstraint(
        "scope_key = 'account' or scope_key ~ '^hmac-sha256:[0-9a-f]{64}$'",
        name="ck_coverage_gap_scope",
    ),
    CheckConstraint("reason_code ~ '^[a-z][a-z0-9_]{0,63}$'", name="ck_coverage_gap_reason"),
    Index("ix_coverage_gaps_snapshot_reason", "snapshot_id", "reason_code"),
)

# Proposed 0010 normalized, redacted inventory. Stable semantics are columns
# and snapshot-scoped FKs; bounded action/condition lists are typed SQL arrays.
iam_principals = Table(
    "iam_principals",
    metadata,
    Column(
        "snapshot_id",
        String(80),
        ForeignKey("foundry.account_snapshots.snapshot_id"),
        primary_key=True,
    ),
    Column("principal_key", String(34), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("principal_fingerprint", String(76), nullable=False),
    Column("kind", String(16), nullable=False),
    Column("display_alias", String(32), nullable=False),
    Column("source_digest", String(71), nullable=False),
    UniqueConstraint("snapshot_id", "principal_fingerprint", name="uq_iam_principal_fingerprint"),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_iam_principal_sequence"),
    CheckConstraint("sequence_no between 0 and 499", name="ck_iam_principal_sequence"),
    CheckConstraint("principal_key ~ '^p_[0-9a-f]{32}$'", name="ck_iam_principal_key"),
    CheckConstraint(
        "principal_fingerprint ~ '^hmac-sha256:[0-9a-f]{64}$'", name="ck_iam_principal_fingerprint"
    ),
    CheckConstraint("kind in ('iam_user','iam_role','iam_group')", name="ck_iam_principal_kind"),
    CheckConstraint(
        "display_alias ~ '^(user|role|group)-[0-9a-f]{8}$'", name="ck_iam_principal_alias"
    ),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_iam_principal_digest"),
    Index("ix_iam_principals_snapshot_kind", "snapshot_id", "kind"),
)

iam_policies = Table(
    "iam_policies",
    metadata,
    Column(
        "snapshot_id",
        String(80),
        ForeignKey("foundry.account_snapshots.snapshot_id"),
        primary_key=True,
    ),
    Column("policy_key", String(36), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("kind", String(16), nullable=False),
    Column("version_label", String(8)),
    Column("is_default", Boolean, nullable=False),
    Column("parse_state", String(16), nullable=False),
    Column("source_digest", String(71), nullable=False),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_iam_policy_sequence"),
    CheckConstraint("sequence_no between 0 and 999", name="ck_iam_policy_sequence"),
    CheckConstraint("policy_key ~ '^pol_[0-9a-f]{32}$'", name="ck_iam_policy_key"),
    CheckConstraint("kind in ('managed','inline','trust')", name="ck_iam_policy_kind"),
    CheckConstraint(
        "parse_state in ('parsed','partial','unsupported')", name="ck_iam_policy_parse"
    ),
    CheckConstraint(
        "(kind = 'managed' and version_label ~ '^v[1-9][0-9]{0,4}$') or "
        "(kind in ('inline','trust') and version_label is null and not is_default)",
        name="ck_iam_policy_version",
    ),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_iam_policy_digest"),
    Index("ix_iam_policies_snapshot_kind", "snapshot_id", "kind"),
)

iam_identity_statements = Table(
    "iam_identity_statements",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("statement_key", String(35), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("policy_key", String(36), nullable=False),
    Column("effect", String(8), nullable=False),
    Column("action_mode", String(16), nullable=False),
    Column("action_patterns", ARRAY(String(128)), nullable=False),
    Column("resource_mode", String(24), nullable=False),
    Column("condition_state", String(16), nullable=False),
    Column("condition_keys", ARRAY(String(128)), nullable=False),
    Column("source_digest", String(71), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id", "policy_key"],
        ["foundry.iam_policies.snapshot_id", "foundry.iam_policies.policy_key"],
        name="fk_iam_statement_policy",
    ),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_iam_statement_sequence"),
    CheckConstraint("sequence_no between 0 and 4999", name="ck_iam_statement_sequence"),
    CheckConstraint("statement_key ~ '^st_[0-9a-f]{32}$'", name="ck_iam_statement_key"),
    CheckConstraint("effect in ('allow','deny')", name="ck_iam_statement_effect"),
    CheckConstraint(
        "action_mode in ('action','not_action','unsupported')", name="ck_iam_statement_action_mode"
    ),
    CheckConstraint(
        "resource_mode in ('all','linked_principals','unresolved','not_resource')",
        name="ck_iam_statement_resource_mode",
    ),
    CheckConstraint(
        "condition_state in ('absent','unevaluated','unsupported')",
        name="ck_iam_statement_condition",
    ),
    CheckConstraint(
        "cardinality(action_patterns) <= 100 and "
        "((action_mode = 'unsupported') = (cardinality(action_patterns) = 0))",
        name="ck_iam_statement_actions",
    ),
    CheckConstraint(
        "cardinality(condition_keys) <= 50 and "
        "((condition_state = 'absent' and cardinality(condition_keys) = 0) or "
        "(condition_state = 'unevaluated' and cardinality(condition_keys) > 0) or "
        "condition_state = 'unsupported')",
        name="ck_iam_statement_conditions",
    ),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_iam_statement_digest"),
    Index("ix_iam_statements_policy", "snapshot_id", "policy_key"),
)

iam_statement_resource_refs = Table(
    "iam_statement_resource_refs",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("statement_key", String(35), primary_key=True),
    Column("principal_key", String(34), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    UniqueConstraint(
        "snapshot_id", "statement_key", "sequence_no", name="uq_iam_resource_ref_sequence"
    ),
    CheckConstraint("sequence_no between 0 and 99", name="ck_iam_resource_ref_sequence"),
    ForeignKeyConstraint(
        ["snapshot_id", "statement_key"],
        [
            "foundry.iam_identity_statements.snapshot_id",
            "foundry.iam_identity_statements.statement_key",
        ],
        name="fk_iam_resource_statement",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "principal_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_iam_resource_principal",
    ),
    Index("ix_iam_resource_principal", "snapshot_id", "principal_key"),
)

iam_attachments = Table(
    "iam_attachments",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("principal_key", String(34), primary_key=True),
    Column("policy_key", String(36), primary_key=True),
    Column("kind", String(24), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("source_digest", String(71), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id", "principal_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_iam_attachment_principal",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "policy_key"],
        ["foundry.iam_policies.snapshot_id", "foundry.iam_policies.policy_key"],
        name="fk_iam_attachment_policy",
    ),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_iam_attachment_sequence"),
    CheckConstraint("sequence_no between 0 and 4999", name="ck_iam_attachment_sequence"),
    CheckConstraint(
        "kind in ('managed','inline','permissions_boundary')", name="ck_iam_attachment_kind"
    ),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_iam_attachment_digest"),
    Index("ix_iam_attachments_policy", "snapshot_id", "policy_key"),
)

iam_memberships = Table(
    "iam_memberships",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("user_key", String(34), primary_key=True),
    Column("group_key", String(34), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("source_digest", String(71), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id", "user_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_iam_membership_user",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "group_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_iam_membership_group",
    ),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_iam_membership_sequence"),
    CheckConstraint("sequence_no between 0 and 4999", name="ck_iam_membership_sequence"),
    CheckConstraint("user_key <> group_key", name="ck_iam_membership_distinct"),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_iam_membership_digest"),
    Index("ix_iam_memberships_group", "snapshot_id", "group_key"),
)

iam_group_traversals = Table(
    "iam_group_traversals",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("collection_run_id", String(80), nullable=False),
    Column("user_key", String(34), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("task_id", String(80)),
    Column("state", String(16), nullable=False),
    Column("membership_count", Integer),
    Column("evidence_digest", String(71)),
    Column("reason_code", String(64)),
    ForeignKeyConstraint(
        ["snapshot_id", "collection_run_id"],
        ["foundry.account_snapshots.snapshot_id", "foundry.account_snapshots.collection_run_id"],
        name="fk_iam_traversal_snapshot_run",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "user_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_iam_traversal_user",
    ),
    ForeignKeyConstraint(
        ["task_id", "collection_run_id"],
        ["foundry.collection_tasks.task_id", "foundry.collection_tasks.collection_run_id"],
        name="fk_iam_traversal_task_run",
    ),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_iam_traversal_sequence"),
    CheckConstraint("sequence_no between 0 and 499", name="ck_iam_traversal_sequence"),
    CheckConstraint(
        "state in ('complete','partial','not_collected','unavailable')",
        name="ck_iam_traversal_state",
    ),
    CheckConstraint(
        "(state = 'complete' and task_id is not null and membership_count between 0 and 5000 "
        "and evidence_digest is not null and reason_code is null) or "
        "(state = 'partial' and reason_code is not null and "
        "(membership_count is null or membership_count between 0 and 5000)) or "
        "(state in ('not_collected','unavailable') and membership_count is null "
        "and evidence_digest is null and reason_code is not null)",
        name="ck_iam_traversal_outcome",
    ),
    CheckConstraint(
        "evidence_digest is null or evidence_digest ~ '^sha256:[0-9a-f]{64}$'",
        name="ck_iam_traversal_digest",
    ),
    CheckConstraint(
        "reason_code is null or reason_code ~ '^[a-z][a-z0-9_]{0,63}$'",
        name="ck_iam_traversal_reason",
    ),
)

iam_trust_statements = Table(
    "iam_trust_statements",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("statement_key", String(35), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    Column("policy_key", String(36), nullable=False),
    Column("role_key", String(34), nullable=False),
    Column("effect", String(8), nullable=False),
    Column("action_mode", String(16), nullable=False),
    Column("action_patterns", ARRAY(String(128)), nullable=False),
    Column("selector_state", String(16), nullable=False),
    Column("service_principals", ARRAY(String(128)), nullable=False),
    Column("condition_state", String(16), nullable=False),
    Column("condition_keys", ARRAY(String(128)), nullable=False),
    Column("source_digest", String(71), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id", "policy_key"],
        ["foundry.iam_policies.snapshot_id", "foundry.iam_policies.policy_key"],
        name="fk_iam_trust_policy",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "role_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_iam_trust_role",
    ),
    UniqueConstraint("snapshot_id", "sequence_no", name="uq_iam_trust_sequence"),
    CheckConstraint("sequence_no between 0 and 1999", name="ck_iam_trust_sequence"),
    CheckConstraint("statement_key ~ '^st_[0-9a-f]{32}$'", name="ck_iam_trust_key"),
    CheckConstraint("effect in ('allow','deny')", name="ck_iam_trust_effect"),
    CheckConstraint(
        "action_mode in ('action','not_action','unsupported')", name="ck_iam_trust_action_mode"
    ),
    CheckConstraint("selector_state in ('linked','unresolved')", name="ck_iam_trust_selector"),
    CheckConstraint(
        "condition_state in ('absent','unevaluated','unsupported')", name="ck_iam_trust_condition"
    ),
    CheckConstraint(
        "cardinality(action_patterns) <= 50 and "
        "((action_mode = 'unsupported') = (cardinality(action_patterns) = 0))",
        name="ck_iam_trust_actions",
    ),
    CheckConstraint(
        "cardinality(service_principals) <= 50 and cardinality(condition_keys) <= 50",
        name="ck_iam_trust_array_bounds",
    ),
    CheckConstraint(
        "(condition_state = 'absent' and cardinality(condition_keys) = 0) or "
        "(condition_state = 'unevaluated' and cardinality(condition_keys) > 0) or "
        "condition_state = 'unsupported'",
        name="ck_iam_trust_condition_keys",
    ),
    CheckConstraint("source_digest ~ '^sha256:[0-9a-f]{64}$'", name="ck_iam_trust_digest"),
    Index("ix_iam_trust_role", "snapshot_id", "role_key"),
)

iam_trust_principal_refs = Table(
    "iam_trust_principal_refs",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("statement_key", String(35), primary_key=True),
    Column("principal_key", String(34), primary_key=True),
    Column("sequence_no", Integer, nullable=False),
    UniqueConstraint(
        "snapshot_id", "statement_key", "sequence_no", name="uq_iam_trust_ref_sequence"
    ),
    CheckConstraint("sequence_no between 0 and 99", name="ck_iam_trust_ref_sequence"),
    ForeignKeyConstraint(
        ["snapshot_id", "statement_key"],
        ["foundry.iam_trust_statements.snapshot_id", "foundry.iam_trust_statements.statement_key"],
        name="fk_iam_trust_ref_statement",
    ),
    ForeignKeyConstraint(
        ["snapshot_id", "principal_key"],
        ["foundry.iam_principals.snapshot_id", "foundry.iam_principals.principal_key"],
        name="fk_iam_trust_ref_principal",
    ),
    Index("ix_iam_trust_ref_principal", "snapshot_id", "principal_key"),
)

snapshot_purge_tombstones = Table(
    "snapshot_purge_tombstones",
    metadata,
    Column("snapshot_id", String(80), primary_key=True),
    Column("content_hash", String(71), nullable=False),
    Column("handoff_hash", String(71), nullable=False),
    Column("data_kind", String(32), nullable=False),
    Column("sealed_at", DateTime(timezone=True), nullable=False),
    Column("retention_expires_at", DateTime(timezone=True), nullable=False),
    Column("purged_at", DateTime(timezone=True), nullable=False),
    Column("purge_reason", String(64), nullable=False),
    ForeignKeyConstraint(
        ["snapshot_id"],
        ["foundry.account_snapshots.snapshot_id"],
        name="fk_snapshot_purge_snapshot",
    ),
    CheckConstraint(
        "data_kind in ('synthetic','real_account_observed')",
        name="ck_snapshot_purge_data_kind",
    ),
    CheckConstraint("content_hash ~ '^sha256:[0-9a-f]{64}$'", name="ck_snapshot_purge_content"),
    CheckConstraint("handoff_hash ~ '^sha256:[0-9a-f]{64}$'", name="ck_snapshot_purge_handoff"),
    CheckConstraint(
        "purge_reason in ('retention_elapsed','operator_purge')",
        name="ck_snapshot_purge_reason",
    ),
    CheckConstraint("purged_at >= sealed_at", name="ck_snapshot_purge_after_seal"),
    CheckConstraint(
        "retention_expires_at > sealed_at",
        name="ck_snapshot_purge_retention",
    ),
)
