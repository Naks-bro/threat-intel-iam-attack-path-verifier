"""Add redacted, snapshot-scoped IAM inventory tables (local draft only).

Frozen DDL generated from the proposed Engine 2 metadata at authoring time.
No collector, backfill, account data, or managed database operation occurs.
Do not apply to Supabase until schema, privacy and migration gates are reviewed.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261009_0010"
down_revision: str | None = "20261009_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Static SQL: historical migrations must not import mutable current metadata.
_STATEMENTS: tuple[str, ...] = (
    (
        "CREATE TABLE foundry.iam_policies (\n\tsnapshot_id VARCHAR(80) NOT NUL"
        "L, \n\tpolicy_key VARCHAR(36) NOT NULL, \n\tsequence_no INTEGER NOT NULL"
        ", \n\tkind VARCHAR(16) NOT NULL, \n\tversion_label VARCHAR(8), \n\tis_defa"
        "ult BOOLEAN NOT NULL, \n\tparse_state VARCHAR(16) NOT NULL, \n\tsource_d"
        "igest VARCHAR(71) NOT NULL, \n\tPRIMARY KEY (snapshot_id, policy_key),"
        " \n\tCONSTRAINT uq_iam_policy_sequence UNIQUE (snapshot_id, sequence_n"
        "o), \n\tCONSTRAINT ck_iam_policy_sequence CHECK (sequence_no between 0"
        " and 999), \n\tCONSTRAINT ck_iam_policy_key CHECK (policy_key ~ '^pol_"
        "[0-9a-f]{32}$'), \n\tCONSTRAINT ck_iam_policy_kind CHECK (kind in ('ma"
        "naged','inline','trust')), \n\tCONSTRAINT ck_iam_policy_parse CHECK (p"
        "arse_state in ('parsed','partial','unsupported')), \n\tCONSTRAINT ck_i"
        "am_policy_version CHECK ((kind = 'managed' and version_label ~ '^v[1"
        "-9][0-9]{0,4}$') or (kind in ('inline','trust') and version_label is"
        " null and not is_default)), \n\tCONSTRAINT ck_iam_policy_digest CHECK "
        "(source_digest ~ '^sha256:[0-9a-f]{64}$'), \n\tFOREIGN KEY(snapshot_id"
        ") REFERENCES foundry.account_snapshots (snapshot_id)\n)"
    ),
    (
        "CREATE TABLE foundry.iam_principals (\n\tsnapshot_id VARCHAR(80) NOT N"
        "ULL, \n\tprincipal_key VARCHAR(34) NOT NULL, \n\tsequence_no INTEGER NOT"
        " NULL, \n\tprincipal_fingerprint VARCHAR(76) NOT NULL, \n\tkind VARCHAR("
        "16) NOT NULL, \n\tdisplay_alias VARCHAR(32) NOT NULL, \n\tsource_digest "
        "VARCHAR(71) NOT NULL, \n\tPRIMARY KEY (snapshot_id, principal_key), \n\t"
        "CONSTRAINT uq_iam_principal_fingerprint UNIQUE (snapshot_id, princip"
        "al_fingerprint), \n\tCONSTRAINT uq_iam_principal_sequence UNIQUE (snap"
        "shot_id, sequence_no), \n\tCONSTRAINT ck_iam_principal_sequence CHECK "
        "(sequence_no between 0 and 499), \n\tCONSTRAINT ck_iam_principal_key C"
        "HECK (principal_key ~ '^p_[0-9a-f]{32}$'), \n\tCONSTRAINT ck_iam_princ"
        "ipal_fingerprint CHECK (principal_fingerprint ~ '^hmac-sha256:[0-9a-"
        "f]{64}$'), \n\tCONSTRAINT ck_iam_principal_kind CHECK (kind in ('iam_u"
        "ser','iam_role','iam_group')), \n\tCONSTRAINT ck_iam_principal_alias C"
        "HECK (display_alias ~ '^(user|role|group)-[0-9a-f]{8}$'), \n\tCONSTRAI"
        "NT ck_iam_principal_digest CHECK (source_digest ~ '^sha256:[0-9a-f]{"
        "64}$'), \n\tFOREIGN KEY(snapshot_id) REFERENCES foundry.account_snapsh"
        "ots (snapshot_id)\n)"
    ),
    (
        "CREATE TABLE foundry.iam_attachments (\n\tsnapshot_id VARCHAR(80) NOT "
        "NULL, \n\tprincipal_key VARCHAR(34) NOT NULL, \n\tpolicy_key VARCHAR(36)"
        " NOT NULL, \n\tkind VARCHAR(24) NOT NULL, \n\tsequence_no INTEGER NOT NU"
        "LL, \n\tsource_digest VARCHAR(71) NOT NULL, \n\tPRIMARY KEY (snapshot_id"
        ", principal_key, policy_key, kind), \n\tCONSTRAINT fk_iam_attachment_p"
        "rincipal FOREIGN KEY(snapshot_id, principal_key) REFERENCES foundry."
        "iam_principals (snapshot_id, principal_key), \n\tCONSTRAINT fk_iam_att"
        "achment_policy FOREIGN KEY(snapshot_id, policy_key) REFERENCES found"
        "ry.iam_policies (snapshot_id, policy_key), \n\tCONSTRAINT uq_iam_attac"
        "hment_sequence UNIQUE (snapshot_id, sequence_no), \n\tCONSTRAINT ck_ia"
        "m_attachment_sequence CHECK (sequence_no between 0 and 4999), \n\tCONS"
        "TRAINT ck_iam_attachment_kind CHECK (kind in ('managed','inline','pe"
        "rmissions_boundary')), \n\tCONSTRAINT ck_iam_attachment_digest CHECK ("
        "source_digest ~ '^sha256:[0-9a-f]{64}$')\n)"
    ),
    (
        "CREATE TABLE foundry.iam_group_traversals (\n\tsnapshot_id VARCHAR(80)"
        " NOT NULL, \n\tcollection_run_id VARCHAR(80) NOT NULL, \n\tuser_key VARC"
        "HAR(34) NOT NULL, \n\tsequence_no INTEGER NOT NULL, \n\ttask_id VARCHAR("
        "80), \n\tstate VARCHAR(16) NOT NULL, \n\tmembership_count INTEGER, \n\tevi"
        "dence_digest VARCHAR(71), \n\treason_code VARCHAR(64), \n\tPRIMARY KEY ("
        "snapshot_id, user_key), \n\tCONSTRAINT fk_iam_traversal_snapshot_run F"
        "OREIGN KEY(snapshot_id, collection_run_id) REFERENCES foundry.accoun"
        "t_snapshots (snapshot_id, collection_run_id), \n\tCONSTRAINT fk_iam_tr"
        "aversal_user FOREIGN KEY(snapshot_id, user_key) REFERENCES foundry.i"
        "am_principals (snapshot_id, principal_key), \n\tCONSTRAINT fk_iam_trav"
        "ersal_task_run FOREIGN KEY(task_id, collection_run_id) REFERENCES fo"
        "undry.collection_tasks (task_id, collection_run_id), \n\tCONSTRAINT uq"
        "_iam_traversal_sequence UNIQUE (snapshot_id, sequence_no), \n\tCONSTRA"
        "INT ck_iam_traversal_sequence CHECK (sequence_no between 0 and 499),"
        " \n\tCONSTRAINT ck_iam_traversal_state CHECK (state in ('complete','pa"
        "rtial','not_collected','unavailable')), \n\tCONSTRAINT ck_iam_traversa"
        "l_outcome CHECK ((state = 'complete' and task_id is not null and mem"
        "bership_count between 0 and 5000 and evidence_digest is not null and"
        " reason_code is null) or (state = 'partial' and reason_code is not n"
        "ull and (membership_count is null or membership_count between 0 and "
        "5000)) or (state in ('not_collected','unavailable') and membership_c"
        "ount is null and evidence_digest is null and reason_code is not null"
        ")), \n\tCONSTRAINT ck_iam_traversal_digest CHECK (evidence_digest is n"
        "ull or evidence_digest ~ '^sha256:[0-9a-f]{64}$'), \n\tCONSTRAINT ck_i"
        "am_traversal_reason CHECK (reason_code is null or reason_code ~ '^[a"
        "-z][a-z0-9_]{0,63}$')\n)"
    ),
    (
        "CREATE TABLE foundry.iam_identity_statements (\n\tsnapshot_id VARCHAR("
        "80) NOT NULL, \n\tstatement_key VARCHAR(35) NOT NULL, \n\tsequence_no IN"
        "TEGER NOT NULL, \n\tpolicy_key VARCHAR(36) NOT NULL, \n\teffect VARCHAR("
        "8) NOT NULL, \n\taction_mode VARCHAR(16) NOT NULL, \n\taction_patterns V"
        "ARCHAR(128)[] NOT NULL, \n\tresource_mode VARCHAR(24) NOT NULL, \n\tcond"
        "ition_state VARCHAR(16) NOT NULL, \n\tcondition_keys VARCHAR(128)[] NO"
        "T NULL, \n\tsource_digest VARCHAR(71) NOT NULL, \n\tPRIMARY KEY (snapsho"
        "t_id, statement_key), \n\tCONSTRAINT fk_iam_statement_policy FOREIGN K"
        "EY(snapshot_id, policy_key) REFERENCES foundry.iam_policies (snapsho"
        "t_id, policy_key), \n\tCONSTRAINT uq_iam_statement_sequence UNIQUE (sn"
        "apshot_id, sequence_no), \n\tCONSTRAINT ck_iam_statement_sequence CHEC"
        "K (sequence_no between 0 and 4999), \n\tCONSTRAINT ck_iam_statement_ke"
        "y CHECK (statement_key ~ '^st_[0-9a-f]{32}$'), \n\tCONSTRAINT ck_iam_s"
        "tatement_effect CHECK (effect in ('allow','deny')), \n\tCONSTRAINT ck_"
        "iam_statement_action_mode CHECK (action_mode in ('action','not_actio"
        "n','unsupported')), \n\tCONSTRAINT ck_iam_statement_resource_mode CHEC"
        "K (resource_mode in ('all','linked_principals','unresolved','not_res"
        "ource')), \n\tCONSTRAINT ck_iam_statement_condition CHECK (condition_s"
        "tate in ('absent','unevaluated','unsupported')), \n\tCONSTRAINT ck_iam"
        "_statement_actions CHECK (cardinality(action_patterns) <= 100 and (("
        "action_mode = 'unsupported') = (cardinality(action_patterns) = 0))),"
        " \n\tCONSTRAINT ck_iam_statement_conditions CHECK (cardinality(conditi"
        "on_keys) <= 50 and ((condition_state = 'absent' and cardinality(cond"
        "ition_keys) = 0) or (condition_state = 'unevaluated' and cardinality"
        "(condition_keys) > 0) or condition_state = 'unsupported')), \n\tCONSTR"
        "AINT ck_iam_statement_digest CHECK (source_digest ~ '^sha256:[0-9a-f"
        "]{64}$')\n)"
    ),
    (
        "CREATE TABLE foundry.iam_memberships (\n\tsnapshot_id VARCHAR(80) NOT "
        "NULL, \n\tuser_key VARCHAR(34) NOT NULL, \n\tgroup_key VARCHAR(34) NOT N"
        "ULL, \n\tsequence_no INTEGER NOT NULL, \n\tsource_digest VARCHAR(71) NOT"
        " NULL, \n\tPRIMARY KEY (snapshot_id, user_key, group_key), \n\tCONSTRAIN"
        "T fk_iam_membership_user FOREIGN KEY(snapshot_id, user_key) REFERENC"
        "ES foundry.iam_principals (snapshot_id, principal_key), \n\tCONSTRAINT"
        " fk_iam_membership_group FOREIGN KEY(snapshot_id, group_key) REFEREN"
        "CES foundry.iam_principals (snapshot_id, principal_key), \n\tCONSTRAIN"
        "T uq_iam_membership_sequence UNIQUE (snapshot_id, sequence_no), \n\tCO"
        "NSTRAINT ck_iam_membership_sequence CHECK (sequence_no between 0 and"
        " 4999), \n\tCONSTRAINT ck_iam_membership_distinct CHECK (user_key <> g"
        "roup_key), \n\tCONSTRAINT ck_iam_membership_digest CHECK (source_diges"
        "t ~ '^sha256:[0-9a-f]{64}$')\n)"
    ),
    (
        "CREATE TABLE foundry.iam_trust_statements (\n\tsnapshot_id VARCHAR(80)"
        " NOT NULL, \n\tstatement_key VARCHAR(35) NOT NULL, \n\tsequence_no INTEG"
        "ER NOT NULL, \n\tpolicy_key VARCHAR(36) NOT NULL, \n\trole_key VARCHAR(3"
        "4) NOT NULL, \n\teffect VARCHAR(8) NOT NULL, \n\taction_mode VARCHAR(16)"
        " NOT NULL, \n\taction_patterns VARCHAR(128)[] NOT NULL, \n\tselector_sta"
        "te VARCHAR(16) NOT NULL, \n\tservice_principals VARCHAR(128)[] NOT NUL"
        "L, \n\tcondition_state VARCHAR(16) NOT NULL, \n\tcondition_keys VARCHAR("
        "128)[] NOT NULL, \n\tsource_digest VARCHAR(71) NOT NULL, \n\tPRIMARY KEY"
        " (snapshot_id, statement_key), \n\tCONSTRAINT fk_iam_trust_policy FORE"
        "IGN KEY(snapshot_id, policy_key) REFERENCES foundry.iam_policies (sn"
        "apshot_id, policy_key), \n\tCONSTRAINT fk_iam_trust_role FOREIGN KEY(s"
        "napshot_id, role_key) REFERENCES foundry.iam_principals (snapshot_id"
        ", principal_key), \n\tCONSTRAINT uq_iam_trust_sequence UNIQUE (snapsho"
        "t_id, sequence_no), \n\tCONSTRAINT ck_iam_trust_sequence CHECK (sequen"
        "ce_no between 0 and 1999), \n\tCONSTRAINT ck_iam_trust_key CHECK (stat"
        "ement_key ~ '^st_[0-9a-f]{32}$'), \n\tCONSTRAINT ck_iam_trust_effect C"
        "HECK (effect in ('allow','deny')), \n\tCONSTRAINT ck_iam_trust_action_"
        "mode CHECK (action_mode in ('action','not_action','unsupported')), \n"
        "\tCONSTRAINT ck_iam_trust_selector CHECK (selector_state in ('linked'"
        ",'unresolved')), \n\tCONSTRAINT ck_iam_trust_condition CHECK (conditio"
        "n_state in ('absent','unevaluated','unsupported')), \n\tCONSTRAINT ck_"
        "iam_trust_actions CHECK (cardinality(action_patterns) <= 50 and ((ac"
        "tion_mode = 'unsupported') = (cardinality(action_patterns) = 0))), \n"
        "\tCONSTRAINT ck_iam_trust_array_bounds CHECK (cardinality(service_pri"
        "ncipals) <= 50 and cardinality(condition_keys) <= 50), \n\tCONSTRAINT "
        "ck_iam_trust_condition_keys CHECK ((condition_state = 'absent' and c"
        "ardinality(condition_keys) = 0) or (condition_state = 'unevaluated' "
        "and cardinality(condition_keys) > 0) or condition_state = 'unsupport"
        "ed'), \n\tCONSTRAINT ck_iam_trust_digest CHECK (source_digest ~ '^sha2"
        "56:[0-9a-f]{64}$')\n)"
    ),
    (
        "CREATE TABLE foundry.iam_statement_resource_refs (\n\tsnapshot_id VARC"
        "HAR(80) NOT NULL, \n\tstatement_key VARCHAR(35) NOT NULL, \n\tprincipal_"
        "key VARCHAR(34) NOT NULL, \n\tsequence_no INTEGER NOT NULL, \n\tPRIMARY "
        "KEY (snapshot_id, statement_key, principal_key), \n\tCONSTRAINT uq_iam"
        "_resource_ref_sequence UNIQUE (snapshot_id, statement_key, sequence_"
        "no), \n\tCONSTRAINT ck_iam_resource_ref_sequence CHECK (sequence_no be"
        "tween 0 and 99), \n\tCONSTRAINT fk_iam_resource_statement FOREIGN KEY("
        "snapshot_id, statement_key) REFERENCES foundry.iam_identity_statemen"
        "ts (snapshot_id, statement_key), \n\tCONSTRAINT fk_iam_resource_princi"
        "pal FOREIGN KEY(snapshot_id, principal_key) REFERENCES foundry.iam_p"
        "rincipals (snapshot_id, principal_key)\n)"
    ),
    (
        "CREATE TABLE foundry.iam_trust_principal_refs (\n\tsnapshot_id VARCHAR"
        "(80) NOT NULL, \n\tstatement_key VARCHAR(35) NOT NULL, \n\tprincipal_key"
        " VARCHAR(34) NOT NULL, \n\tsequence_no INTEGER NOT NULL, \n\tPRIMARY KEY"
        " (snapshot_id, statement_key, principal_key), \n\tCONSTRAINT uq_iam_tr"
        "ust_ref_sequence UNIQUE (snapshot_id, statement_key, sequence_no), \n"
        "\tCONSTRAINT ck_iam_trust_ref_sequence CHECK (sequence_no between 0 a"
        "nd 99), \n\tCONSTRAINT fk_iam_trust_ref_statement FOREIGN KEY(snapshot"
        "_id, statement_key) REFERENCES foundry.iam_trust_statements (snapsho"
        "t_id, statement_key), \n\tCONSTRAINT fk_iam_trust_ref_principal FOREIG"
        "N KEY(snapshot_id, principal_key) REFERENCES foundry.iam_principals "
        "(snapshot_id, principal_key)\n)"
    ),
    ("CREATE INDEX ix_iam_policies_snapshot_kind ON foundry.iam_policies (snapshot_id, kind)"),
    ("CREATE INDEX ix_iam_principals_snapshot_kind ON foundry.iam_principals (snapshot_id, kind)"),
    ("CREATE INDEX ix_iam_attachments_policy ON foundry.iam_attachments (snapshot_id, policy_key)"),
    (
        "CREATE INDEX ix_iam_statements_policy ON foundry.iam_identity_statem"
        "ents (snapshot_id, policy_key)"
    ),
    ("CREATE INDEX ix_iam_memberships_group ON foundry.iam_memberships (snapshot_id, group_key)"),
    ("CREATE INDEX ix_iam_trust_role ON foundry.iam_trust_statements (snapshot_id, role_key)"),
    (
        "CREATE INDEX ix_iam_resource_principal ON foundry.iam_statement_reso"
        "urce_refs (snapshot_id, principal_key)"
    ),
    (
        "CREATE INDEX ix_iam_trust_ref_principal ON foundry.iam_trust_princip"
        "al_refs (snapshot_id, principal_key)"
    ),
)

_TABLES = (
    "iam_policies",
    "iam_principals",
    "iam_attachments",
    "iam_group_traversals",
    "iam_identity_statements",
    "iam_memberships",
    "iam_trust_statements",
    "iam_statement_resource_refs",
    "iam_trust_principal_refs",
)


def upgrade() -> None:
    for statement in _STATEMENTS:
        op.execute(sa.text(statement))
    table_list = ", ".join(f"foundry.{name}" for name in _TABLES)
    op.execute(sa.text(f"REVOKE ALL ON {table_list} FROM PUBLIC"))
    connection = op.get_bind()
    for role in ("anon", "authenticated"):
        exists: bool = connection.execute(
            sa.text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
            {"role": role},
        ).scalar_one()
        if exists:
            op.execute(sa.text(f"REVOKE ALL ON {table_list} FROM {role}"))
    for table in _TABLES:
        op.execute(sa.text(f"ALTER TABLE foundry.{table} ENABLE ROW LEVEL SECURITY"))


def downgrade() -> None:
    raise RuntimeError("Snapshot evidence is archival; use a reviewed forward migration")
