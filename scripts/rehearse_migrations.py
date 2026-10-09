"""Compare fresh and staged Alembic installs on a newly owned loopback cluster.

Never uses a project .env or an existing database. The stopped cluster is retained
under a new temporary directory for diagnosis; the one-time password file is
removed. This is not a rehearsal against a copy of the managed Supabase schema.
"""

import argparse
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

import psycopg
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from fyp_iam.contracts.collection import PolicyLayer
from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
from fyp_iam.engine2.graph_schema import metadata as graph_metadata
from fyp_iam.engine2.observed_graph import project_observed_inventory
from fyp_iam.engine2.schema import metadata as inventory_metadata
from fyp_iam.engine2.shell_import import prepare_shell_import
from fyp_iam.engine2.synthetic_store import (
    SyntheticImportRejected,
    load_synthetic_handoff,
    load_synthetic_observed_graph,
    persist_synthetic_handoff,
)
from fyp_iam.persistence.schema_audit import _catalog
from fyp_iam.persistence.test_guard import database_test_gate

REPO = Path(__file__).resolve().parents[1]
PYTHON = REPO / ".venv" / "Scripts" / "python.exe"
BASE_REVISION = "20261003_0004"
LATER_TABLES = (
    "stable_releases",
    "scoped_reviews",
    "verifier_packets",
    "quality_observations",
    "quality_reports",
)


def _run(command: list[str], environment: dict[str, str], *, quiet: bool = False) -> None:
    result = subprocess.run(
        command,
        cwd=REPO,
        env=environment,
        stdout=subprocess.DEVNULL if quiet else subprocess.PIPE,
        stderr=subprocess.DEVNULL if quiet else subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        phase = " ".join(command[1:5]) if "alembic" in command else "setup"
        match = re.search(r"psycopg\.errors\.([A-Za-z]+): ([^\r\n]+)", result.stderr or "")
        database_error = f":{match.group(1)}:{match.group(2)[:120]}" if match else ""
        tail = (result.stderr or "").splitlines()[-1:] or [""]
        if not database_error and not any(
            token in tail[0].lower() for token in ("password", "://", "@")
        ):
            database_error = f":{tail[0][:120]}"
        raise RuntimeError(
            f"rehearsal_command_failed:{Path(command[0]).name}:{phase}:exit_{result.returncode}{database_error}"
        )


def _port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _child_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("FYP_DATABASE")
        and key not in {"FYP_TEST_DATABASE_URL", "FYP_MIGRATION_DATABASE_URL"}
        and not key.startswith("PG")
    }
    environment["FYP_DATABASE_SSLROOTCERT"] = ""
    environment["FYP_ALLOW_DISPOSABLE_DATABASE_TESTS"] = "1"
    return environment


def _catalog_at(url: str) -> tuple[str | None, dict[str, Any]]:
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            return _catalog(connection)
    finally:
        engine.dispose()


def _empty_engine2_shell(url: str, catalog: dict[str, Any]) -> int:
    """Prove proposed 0009–0011 DDL is private, empty and model-aligned."""

    database_tables = {table["name"]: table for table in catalog["tables"]}
    expected = {
        table.name: table
        for table in [*inventory_metadata.tables.values(), *graph_metadata.tables.values()]
    }
    if set(expected) - set(database_tables):
        raise RuntimeError("engine2_shell_missing")
    for name, model in expected.items():
        actual = {column["name"]: column for column in database_tables[name]["columns"]}
        model_columns = {column.name: column for column in model.columns}
        if actual.keys() != model_columns.keys() or any(
            actual[column]["nullable"] is not model_columns[column].nullable
            for column in model_columns
        ):
            raise RuntimeError("engine2_shell_column_drift")
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            rows = connection.execute(
                text("""
                    SELECT c.relname, c.relrowsecurity
                    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = 'foundry' AND c.relkind = 'r'
                """)
            ).all()
            security = {row[0]: row[1] for row in rows}
            if any(security.get(name) is not True for name in expected):
                raise RuntimeError("engine2_shell_rls_missing")
            for name in expected:
                if connection.execute(text(f"SELECT count(*) FROM foundry.{name}")).scalar_one():
                    raise RuntimeError("engine2_shell_not_empty")
    finally:
        engine.dispose()
    return len(expected)


def _probe_engine2_constraints(url: str) -> None:
    """Exercise synthetic 0009 invariants, then roll every test row back."""

    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    text("""
                        INSERT INTO foundry.account_connections
                        (connection_id, project_key, account_alias, account_fingerprint,
                         provider, credential_mode, profile_alias, selected_region,
                         enabled, created_at)
                        VALUES ('rehearsal_connection','fyp','synthetic-lab',:fingerprint,
                                'aws','synthetic_fixture','fixture','ap-southeast-2',false,
                                '2026-10-09 00:00:00+00')
                    """),
                    {"fingerprint": "hmac-sha256:" + "a" * 64},
                )
                for run_id in ("rehearsal_run_1", "rehearsal_run_2", "rehearsal_run_3"):
                    connection.execute(
                        text("""
                            INSERT INTO foundry.collection_runs
                            (collection_run_id, connection_id, request_id, status,
                             attempt, collector_version, started_at, finished_at)
                            VALUES (:run_id,'rehearsal_connection',:run_id,'succeeded',
                                    1,'rehearsal-1','2026-10-09 00:00:00+00',
                                    '2026-10-09 00:00:01+00')
                        """),
                        {"run_id": run_id},
                    )
                for suffix in ("1", "2"):
                    connection.execute(
                        text("""
                            INSERT INTO foundry.account_snapshots
                            (snapshot_id, connection_id, collection_run_id, data_kind,
                             seal_status, content_hash, handoff_hash,
                             contract_version, sealed_at,
                             retention_expires_at)
                            VALUES (:snapshot,'rehearsal_connection',:run_id,'synthetic',
                                    'complete',:digest,:digest,'0.1','2026-10-09 00:00:01+00',
                                    '2027-06-01 00:00:00+00')
                        """),
                        {
                            "snapshot": f"rehearsal_snapshot_{suffix}",
                            "run_id": f"rehearsal_run_{suffix}",
                            "digest": "sha256:" + "b" * 64,
                        },
                    )
                # Identical content from a later collection is allowed; runs
                # remain distinct and idempotency is keyed by request ID.
                savepoint = connection.begin_nested()
                try:
                    connection.execute(
                        text("""
                            INSERT INTO foundry.account_snapshots
                            (snapshot_id, connection_id, collection_run_id, data_kind,
                             seal_status, content_hash, handoff_hash,
                             contract_version, sealed_at,
                             retention_expires_at)
                            VALUES ('rehearsal_real','rehearsal_connection',
                                    'rehearsal_run_3','real_account_observed','partial',
                                    :digest,:digest,'0.1','2026-10-09 00:00:01+00',
                                    '2027-02-01 00:00:00+00')
                        """),
                        {"digest": "sha256:" + "c" * 64},
                    )
                except IntegrityError:
                    savepoint.rollback()
                else:
                    savepoint.rollback()
                    raise RuntimeError("real_snapshot_retention_not_enforced")

                connection.execute(
                    text("""
                        INSERT INTO foundry.collection_tasks
                        (task_id, collection_run_id, api_name, scope_key, sequence_no, attempt,
                         status, page_count, item_count, pagination_complete,
                         response_digest)
                        VALUES ('rehearsal_task_1','rehearsal_run_1',
                                'iam:ListGroupsForUser','account',0,1,'succeeded',1,0,
                                true,:digest)
                    """),
                    {"digest": "sha256:" + "d" * 64},
                )
                savepoint = connection.begin_nested()
                try:
                    connection.execute(
                        text("""
                            INSERT INTO foundry.coverage_gaps
                            (gap_id, snapshot_id, collection_run_id, task_id, layer,
                             scope_key, coverage_state, reason_code)
                            VALUES ('rehearsal_gap','rehearsal_snapshot_2',
                                    'rehearsal_run_2','rehearsal_task_1',
                                    'identity_policy','account','unavailable','read_denied')
                        """)
                    )
                except IntegrityError:
                    savepoint.rollback()
                else:
                    savepoint.rollback()
                    raise RuntimeError("cross_run_gap_not_rejected")

                savepoint = connection.begin_nested()
                try:
                    connection.execute(
                        text("""
                            INSERT INTO foundry.collection_layer_coverage
                            (snapshot_id, collection_run_id, layer, sequence_no, state,
                             object_count, authorization_evaluated)
                            VALUES ('rehearsal_snapshot_1','rehearsal_run_1',
                                    'identity_policy',0,'absent',0,true)
                        """)
                    )
                except IntegrityError:
                    savepoint.rollback()
                else:
                    savepoint.rollback()
                    raise RuntimeError("evaluated_coverage_not_rejected")

                savepoint = connection.begin_nested()
                try:
                    connection.execute(
                        text("""
                            INSERT INTO foundry.collection_tasks
                            (task_id, collection_run_id, api_name, scope_key, sequence_no,
                             attempt, status, page_count, item_count,
                             pagination_complete, response_digest)
                            VALUES ('rehearsal_task_duplicate','rehearsal_run_1',
                                    'iam:ListRoles','account',0,1,'succeeded',1,0,
                                    true,:digest)
                        """),
                        {"digest": "sha256:" + "d" * 64},
                    )
                except IntegrityError:
                    savepoint.rollback()
                else:
                    savepoint.rollback()
                    raise RuntimeError("duplicate_task_sequence_not_rejected")
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def _sample_handoff() -> CollectionHandoff:
    """Redacted synthetic records covering every 0010 inventory table, not AWS data."""

    principal_key = "p_" + "a" * 32
    role_key = "p_" + "1" * 32
    group_key = "p_" + "2" * 32
    policy_key = "pol_" + "b" * 32
    trust_policy_key = "pol_" + "3" * 32
    digest = "sha256:" + "d" * 64
    inventory = InventorySnapshot.model_validate(
        {
            "snapshot_id": "rehearsal_shell_snapshot",
            "principals": [
                {
                    "principal_key": principal_key,
                    "principal_fingerprint": "hmac-sha256:" + "c" * 64,
                    "kind": "iam_user",
                    "display_alias": "user-00000001",
                    "source_digest": "sha256:" + "d" * 64,
                },
                {
                    "principal_key": role_key,
                    "principal_fingerprint": "hmac-sha256:" + "1" * 64,
                    "kind": "iam_role",
                    "display_alias": "role-00000002",
                    "source_digest": digest,
                },
                {
                    "principal_key": group_key,
                    "principal_fingerprint": "hmac-sha256:" + "2" * 64,
                    "kind": "iam_group",
                    "display_alias": "group-00000003",
                    "source_digest": digest,
                },
            ],
            "policies": [
                {
                    "policy_key": policy_key,
                    "kind": "managed",
                    "version_label": "v1",
                    "is_default": True,
                    "parse_state": "parsed",
                    "source_digest": "sha256:" + "d" * 64,
                },
                {
                    "policy_key": trust_policy_key,
                    "kind": "trust",
                    "parse_state": "parsed",
                    "source_digest": digest,
                },
            ],
            "statements": [
                {
                    "statement_key": "st_" + "e" * 32,
                    "policy_key": policy_key,
                    "effect": "allow",
                    "action_mode": "action",
                    "action_patterns": ["iam:CreateAccessKey"],
                    "resource_mode": "linked_principals",
                    "resource_principal_keys": [role_key],
                    "condition_state": "absent",
                    "source_digest": "sha256:" + "d" * 64,
                }
            ],
            "attachments": [
                {
                    "principal_key": principal_key,
                    "policy_key": policy_key,
                    "kind": "managed",
                    "source_digest": "sha256:" + "d" * 64,
                }
            ],
            "memberships": [
                {"user_key": principal_key, "group_key": group_key, "source_digest": digest}
            ],
            "group_traversals": [
                {
                    "user_key": principal_key,
                    "state": "complete",
                    "membership_count": 1,
                    "evidence_digest": digest,
                }
            ],
            "trust_statements": [
                {
                    "statement_key": "st_" + "4" * 32,
                    "policy_key": trust_policy_key,
                    "role_key": role_key,
                    "effect": "allow",
                    "action_mode": "action",
                    "action_patterns": ["sts:AssumeRole"],
                    "trusted_principal_keys": [principal_key],
                    "selector_state": "linked",
                    "condition_state": "absent",
                    "source_digest": digest,
                }
            ],
        }
    )
    fingerprint = "hmac-sha256:" + "e" * 64
    return CollectionHandoff.model_validate(
        {
            "manifest": {
                "data_kind": "synthetic",
                "run_id": "rehearsal_shell_run",
                "snapshot_id": inventory.snapshot_id,
                "account_alias": "rehearsal-shell",
                "account_fingerprint": fingerprint,
                "collector_version": "rehearsal-1",
                "started_at": "2026-10-09T00:00:00Z",
                "sealed_at": "2026-10-09T00:00:01Z",
                "outcome": "succeeded",
                "snapshot_digest": inventory.content_digest(),
                "tasks": [
                    {
                        "operation": "iam:ListUsers",
                        "attempt": 1,
                        "outcome": "succeeded",
                        "page_count": 1,
                        "item_count": 1,
                        "pagination_complete": True,
                        "response_digest": "sha256:" + "f" * 64,
                    },
                    {
                        "operation": "iam:ListGroupsForUser",
                        "subject_principal_key": principal_key,
                        "attempt": 1,
                        "outcome": "succeeded",
                        "page_count": 1,
                        "item_count": 1,
                        "pagination_complete": True,
                        "response_digest": digest,
                    },
                ],
                "coverage": [
                    {"layer": layer, "state": "not_collected", "reason_code": "outside_scope"}
                    for layer in PolicyLayer
                ],
            },
            "inventory": inventory.model_dump(mode="json"),
        }
    )


def _probe_shell_plan(url: str) -> None:
    """Insert the pure synthetic handoff shell plan, then roll it back."""

    handoff = _sample_handoff()
    fingerprint = handoff.manifest.account_fingerprint
    plan = prepare_shell_import(
        handoff,
        connection_id="rehearsal_shell_connection",
        expected_account_fingerprint=fingerprint,
        request_id="rehearsal_shell_request",
    )
    tables = {table.name: table for table in inventory_metadata.tables.values()}
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    tables["account_connections"].insert(),
                    {
                        "connection_id": "rehearsal_shell_connection",
                        "project_key": "fyp",
                        "account_alias": "rehearsal-shell",
                        "account_fingerprint": fingerprint,
                        "provider": "aws",
                        "credential_mode": "synthetic_fixture",
                        "profile_alias": "fixture",
                        "selected_region": "ap-southeast-2",
                        "enabled": False,
                        "created_at": plan.run["started_at"],
                    },
                )
                connection.execute(tables["collection_runs"].insert(), plan.run)
                connection.execute(tables["collection_tasks"].insert(), list(plan.tasks))
                connection.execute(tables["account_snapshots"].insert(), plan.snapshot)
                connection.execute(
                    tables["collection_layer_coverage"].insert(), list(plan.coverage)
                )
                connection.execute(tables["coverage_gaps"].insert(), list(plan.gaps))
                persisted: str = connection.execute(
                    text("""
                        SELECT handoff_hash FROM foundry.account_snapshots
                        WHERE snapshot_id = :id
                    """),
                    {"id": plan.snapshot["snapshot_id"]},
                ).scalar_one()
                if persisted != handoff.content_digest():
                    raise RuntimeError("shell_plan_handoff_hash_mismatch")
                if connection.execute(
                    text(
                        "SELECT count(*) FROM foundry.collection_layer_coverage "
                        "WHERE snapshot_id = :id"
                    ),
                    {"id": plan.snapshot["snapshot_id"]},
                ).scalar_one() != len(PolicyLayer):
                    raise RuntimeError("shell_plan_layer_count_mismatch")
                if connection.execute(
                    text("SELECT count(*) FROM foundry.coverage_gaps WHERE snapshot_id = :id"),
                    {"id": plan.snapshot["snapshot_id"]},
                ).scalar_one() != len(plan.gaps):
                    raise RuntimeError("shell_plan_gap_count_mismatch")
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def _probe_synthetic_writer(url: str) -> None:
    """Commit and read back one synthetic handoff on the owned fresh DB."""

    handoff = _sample_handoff()
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    tables = {table.name: table for table in inventory_metadata.tables.values()}
    try:
        with engine.begin() as connection:
            connection.execute(
                tables["account_connections"].insert(),
                {
                    "connection_id": "rehearsal_writer_connection",
                    "project_key": "fyp",
                    "account_alias": handoff.manifest.account_alias,
                    "account_fingerprint": handoff.manifest.account_fingerprint,
                    "provider": "aws",
                    "credential_mode": "synthetic_fixture",
                    "profile_alias": "fixture",
                    "selected_region": "ap-southeast-2",
                    "enabled": True,
                    "created_at": handoff.manifest.started_at,
                },
            )
        result = persist_synthetic_handoff(
            engine,
            handoff,
            connection_id="rehearsal_writer_connection",
            request_id="rehearsal_writer_request",
            allow_disposable=True,
            include_observed_graph=True,
        )
        if result.handoff_hash != handoff.content_digest():
            raise RuntimeError("synthetic_writer_digest_mismatch")
        rebuilt = load_synthetic_handoff(
            engine, handoff.inventory.snapshot_id, allow_disposable=True
        )
        if rebuilt.model_dump(mode="json") != handoff.model_dump(mode="json"):
            raise RuntimeError("synthetic_writer_roundtrip_mismatch")
        observed = project_observed_inventory(rebuilt)
        stored_graph = load_synthetic_observed_graph(
            engine, handoff.inventory.snapshot_id, allow_disposable=True
        )
        if (
            observed != project_observed_inventory(handoff)
            or stored_graph != observed
            or observed.source_coverage_complete
            or observed.authorization_evaluated
            or len(observed.relations) < 4
        ):
            raise RuntimeError("synthetic_writer_graph_projection_mismatch")
        if any(
            result.row_counts[name] != expected
            for name, expected in {
                "iam_principals": 3,
                "iam_policies": 2,
                "iam_identity_statements": 1,
                "iam_statement_resource_refs": 1,
                "iam_attachments": 1,
                "iam_memberships": 1,
                "iam_group_traversals": 1,
                "iam_trust_statements": 1,
                "iam_trust_principal_refs": 1,
                "graph_projections": 1,
                "graph_nodes": len(observed.nodes),
                "graph_edges": len(observed.relations),
            }.items()
        ):
            raise RuntimeError("synthetic_writer_inventory_missing")
        with engine.connect() as connection:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            stored_hash: str = connection.execute(
                text("SELECT handoff_hash FROM foundry.account_snapshots WHERE snapshot_id = :id"),
                {"id": handoff.inventory.snapshot_id},
            ).scalar_one()
            if stored_hash != handoff.content_digest():
                raise RuntimeError("synthetic_writer_readback_mismatch")
        try:
            persist_synthetic_handoff(
                engine,
                handoff,
                connection_id="rehearsal_writer_connection",
                request_id="rehearsal_writer_request",
                allow_disposable=True,
            )
        except SyntheticImportRejected as exc:
            if str(exc) != "request_id_exists":
                raise RuntimeError("synthetic_writer_retry_unexpected") from None
        else:
            raise RuntimeError("synthetic_writer_duplicate_accepted")
        with engine.begin() as connection:
            connection.execute(
                graph_metadata.tables["foundry.graph_edges"]
                .update()
                .where(
                    graph_metadata.tables["foundry.graph_edges"].c.snapshot_id
                    == handoff.inventory.snapshot_id
                )
                .values(source_digest="sha256:" + "e" * 64)
            )
        try:
            load_synthetic_observed_graph(
                engine, handoff.inventory.snapshot_id, allow_disposable=True
            )
        except SyntheticImportRejected as exc:
            if str(exc) != "stored_graph_row_mismatch":
                raise RuntimeError("synthetic_graph_tamper_unexpected") from None
        else:
            raise RuntimeError("synthetic_graph_tamper_accepted")
        with engine.begin() as connection:
            connection.execute(
                tables["iam_identity_statements"]
                .update()
                .where(
                    tables["iam_identity_statements"].c.snapshot_id == handoff.inventory.snapshot_id
                )
                .values(source_digest="sha256:" + "f" * 64)
            )
        try:
            load_synthetic_handoff(engine, handoff.inventory.snapshot_id, allow_disposable=True)
        except SyntheticImportRejected as exc:
            if str(exc) != "stored_handoff_invalid":
                raise RuntimeError("synthetic_writer_tamper_unexpected") from None
        else:
            raise RuntimeError("synthetic_writer_tamper_accepted")
    finally:
        engine.dispose()


def _probe_inventory_snapshot_fks(url: str) -> None:
    """Prove 0010 refuses policy/resource links across sealed snapshots."""

    tables = {table.name: table for table in inventory_metadata.tables.values()}
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    tables["account_connections"].insert(),
                    {
                        "connection_id": "inventory_fk_connection",
                        "project_key": "fyp",
                        "account_alias": "inventory-fk-lab",
                        "account_fingerprint": "hmac-sha256:" + "a" * 64,
                        "provider": "aws",
                        "credential_mode": "synthetic_fixture",
                        "profile_alias": "fixture",
                        "selected_region": "ap-southeast-2",
                        "enabled": False,
                        "created_at": "2026-10-09T00:00:00+00:00",
                    },
                )
                for suffix in ("a", "b"):
                    run_id = f"inventory_fk_run_{suffix}"
                    snapshot_id = f"inventory_fk_snapshot_{suffix}"
                    connection.execute(
                        tables["collection_runs"].insert(),
                        {
                            "collection_run_id": run_id,
                            "connection_id": "inventory_fk_connection",
                            "retry_of": None,
                            "request_id": run_id,
                            "status": "succeeded",
                            "attempt": 1,
                            "collector_version": "rehearsal-1",
                            "started_at": "2026-10-09T00:00:00+00:00",
                            "finished_at": "2026-10-09T00:00:01+00:00",
                            "error_code": None,
                        },
                    )
                    connection.execute(
                        tables["account_snapshots"].insert(),
                        {
                            "snapshot_id": snapshot_id,
                            "connection_id": "inventory_fk_connection",
                            "collection_run_id": run_id,
                            "data_kind": "synthetic",
                            "seal_status": "partial",
                            "content_hash": "sha256:" + "b" * 64,
                            "handoff_hash": "sha256:" + "c" * 64,
                            "contract_version": "0.1",
                            "sealed_at": "2026-10-09T00:00:01+00:00",
                            "retention_expires_at": "2027-01-01T00:00:00+00:00",
                        },
                    )
                principal_key = "p_" + "d" * 32
                policy_key = "pol_" + "e" * 32
                connection.execute(
                    tables["iam_principals"].insert(),
                    {
                        "snapshot_id": "inventory_fk_snapshot_a",
                        "sequence_no": 0,
                        "principal_key": principal_key,
                        "principal_fingerprint": "hmac-sha256:" + "f" * 64,
                        "kind": "iam_user",
                        "display_alias": "user-00000001",
                        "source_digest": "sha256:" + "1" * 64,
                    },
                )
                connection.execute(
                    tables["iam_policies"].insert(),
                    {
                        "snapshot_id": "inventory_fk_snapshot_b",
                        "sequence_no": 0,
                        "policy_key": policy_key,
                        "kind": "managed",
                        "version_label": "v1",
                        "is_default": True,
                        "parse_state": "parsed",
                        "source_digest": "sha256:" + "2" * 64,
                    },
                )
                savepoint = connection.begin_nested()
                try:
                    connection.execute(
                        tables["iam_attachments"].insert(),
                        {
                            "snapshot_id": "inventory_fk_snapshot_a",
                            "principal_key": principal_key,
                            "policy_key": policy_key,
                            "kind": "managed",
                            "source_digest": "sha256:" + "3" * 64,
                        },
                    )
                except IntegrityError:
                    savepoint.rollback()
                else:
                    savepoint.rollback()
                    raise RuntimeError("cross_snapshot_attachment_not_rejected")

                statement_key = "st_" + "4" * 32
                connection.execute(
                    tables["iam_identity_statements"].insert(),
                    {
                        "snapshot_id": "inventory_fk_snapshot_b",
                        "sequence_no": 0,
                        "statement_key": statement_key,
                        "policy_key": policy_key,
                        "effect": "allow",
                        "action_mode": "action",
                        "action_patterns": ["iam:CreateAccessKey"],
                        "resource_mode": "linked_principals",
                        "condition_state": "absent",
                        "condition_keys": [],
                        "source_digest": "sha256:" + "5" * 64,
                    },
                )
                savepoint = connection.begin_nested()
                try:
                    connection.execute(
                        tables["iam_statement_resource_refs"].insert(),
                        {
                            "snapshot_id": "inventory_fk_snapshot_b",
                            "statement_key": statement_key,
                            "principal_key": principal_key,
                        },
                    )
                except IntegrityError:
                    savepoint.rollback()
                else:
                    savepoint.rollback()
                    raise RuntimeError("cross_snapshot_resource_not_rejected")
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def _probe_observed_graph_fks(url: str) -> None:
    """Refuse cross-snapshot graph links and capability claims on 0011."""

    inventory = {table.name: table for table in inventory_metadata.tables.values()}
    graph = {table.name: table for table in graph_metadata.tables.values()}
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    digest = "sha256:" + "a" * 64
    principal_a = "p_" + "1" * 32
    principal_b = "p_" + "2" * 32
    policy_b = "pol_" + "3" * 32
    relation = "rel_" + "4" * 32
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.execute(
                    inventory["account_connections"].insert(),
                    {
                        "connection_id": "graph_fk_connection",
                        "project_key": "fyp",
                        "account_alias": "graph-fk-lab",
                        "account_fingerprint": "hmac-sha256:" + "a" * 64,
                        "provider": "aws",
                        "credential_mode": "synthetic_fixture",
                        "profile_alias": "fixture",
                        "selected_region": "ap-southeast-2",
                        "enabled": False,
                        "created_at": "2026-10-09T00:00:00+00:00",
                    },
                )
                for suffix, principal_key in (("a", principal_a), ("b", principal_b)):
                    run_id = f"graph_fk_run_{suffix}"
                    snapshot_id = f"graph_fk_snapshot_{suffix}"
                    connection.execute(
                        inventory["collection_runs"].insert(),
                        {
                            "collection_run_id": run_id,
                            "connection_id": "graph_fk_connection",
                            "request_id": run_id,
                            "status": "succeeded",
                            "attempt": 1,
                            "collector_version": "rehearsal-1",
                            "started_at": "2026-10-09T00:00:00+00:00",
                            "finished_at": "2026-10-09T00:00:01+00:00",
                        },
                    )
                    connection.execute(
                        inventory["account_snapshots"].insert(),
                        {
                            "snapshot_id": snapshot_id,
                            "connection_id": "graph_fk_connection",
                            "collection_run_id": run_id,
                            "data_kind": "synthetic",
                            "seal_status": "partial",
                            "content_hash": digest,
                            "handoff_hash": digest,
                            "contract_version": "0.1",
                            "sealed_at": "2026-10-09T00:00:01+00:00",
                            "retention_expires_at": "2027-01-01T00:00:00+00:00",
                        },
                    )
                    connection.execute(
                        graph["graph_projections"].insert(),
                        {
                            "snapshot_id": snapshot_id,
                            "inventory_digest": digest,
                            "handoff_digest": digest,
                            "projection_digest": digest,
                            "resolver_version": "observed-0.1",
                            "generated_at": "2026-10-09T00:00:02+00:00",
                            "source_coverage_complete": False,
                            "incomplete_reason_codes": ["fixture_coverage_incomplete"],
                            "authorization_evaluated": False,
                        },
                    )
                    connection.execute(
                        inventory["iam_principals"].insert(),
                        {
                            "snapshot_id": snapshot_id,
                            "principal_key": principal_key,
                            "sequence_no": 0,
                            "principal_fingerprint": "hmac-sha256:" + suffix * 64,
                            "kind": "iam_user",
                            "display_alias": f"user-{suffix * 8}",
                            "source_digest": digest,
                        },
                    )
                    connection.execute(
                        graph["graph_nodes"].insert(),
                        {
                            "snapshot_id": snapshot_id,
                            "node_key": principal_key,
                            "principal_key": principal_key,
                            "kind": "iam_user",
                            "display_alias": f"user-{suffix * 8}",
                            "source_digest": digest,
                        },
                    )
                connection.execute(
                    inventory["iam_policies"].insert(),
                    {
                        "snapshot_id": "graph_fk_snapshot_b",
                        "policy_key": policy_b,
                        "sequence_no": 0,
                        "kind": "managed",
                        "version_label": "v1",
                        "is_default": True,
                        "parse_state": "parsed",
                        "source_digest": digest,
                    },
                )

                def rejected(table_name: str, row: dict[str, Any], code: str) -> None:
                    savepoint = connection.begin_nested()
                    try:
                        connection.execute(graph[table_name].insert(), row)
                    except IntegrityError:
                        savepoint.rollback()
                    else:
                        savepoint.rollback()
                        raise RuntimeError(code)

                missing_principal = "p_" + "5" * 32
                rejected(
                    "graph_nodes",
                    {
                        "snapshot_id": "graph_fk_snapshot_a",
                        "node_key": missing_principal,
                        "principal_key": missing_principal,
                        "kind": "iam_user",
                        "display_alias": "user-55555555",
                        "source_digest": digest,
                    },
                    "phantom_graph_node_accepted",
                )
                rejected(
                    "graph_edges",
                    {
                        "snapshot_id": "graph_fk_snapshot_a",
                        "relation_id": relation,
                        "kind": "group_membership",
                        "source_key": principal_a,
                        "target_key": principal_b,
                        "source_digest": digest,
                        "derivation": "observed_configuration",
                    },
                    "cross_snapshot_graph_edge_accepted",
                )
                rejected(
                    "graph_edges",
                    {
                        "snapshot_id": "graph_fk_snapshot_a",
                        "relation_id": relation,
                        "kind": "CAN_ASSUME",
                        "source_key": principal_a,
                        "target_key": principal_a,
                        "source_digest": digest,
                        "derivation": "observed_configuration",
                    },
                    "capability_edge_accepted",
                )
                connection.execute(
                    graph["graph_edges"].insert(),
                    {
                        "snapshot_id": "graph_fk_snapshot_a",
                        "relation_id": relation,
                        "kind": "group_membership",
                        "source_key": principal_a,
                        "target_key": principal_a,
                        "source_digest": digest,
                        "derivation": "observed_configuration",
                    },
                )
                rejected(
                    "edge_policy_evidence",
                    {
                        "snapshot_id": "graph_fk_snapshot_a",
                        "relation_id": relation,
                        "evidence_ordinal": 0,
                        "evidence_role": "anchors",
                        "policy_key": policy_b,
                    },
                    "cross_snapshot_graph_evidence_accepted",
                )
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def _reconstruct_observed_0004(url: str) -> None:
    """Undo only empty tables that evolving migration 0002 created too early.

    These five absences and the NOT NULL duration were observed read-only on
    the managed 0004 database; this function operates only on the newly owned
    disposable staged database created by ``rehearse``.
    """
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.begin() as connection:
            revision: str = connection.execute(
                text("SELECT version_num FROM foundry.alembic_version")
            ).scalar_one()
            if revision != BASE_REVISION:
                raise RuntimeError("unexpected_reconstruction_revision")
            for name in LATER_TABLES:
                count: int = connection.execute(
                    text(f"SELECT count(*) FROM foundry.{name}")
                ).scalar_one()
                if count != 0:
                    raise RuntimeError("reconstruction_table_not_empty")
                connection.execute(text(f"DROP TABLE foundry.{name}"))
            connection.execute(
                text("ALTER TABLE foundry.validation_runs ALTER COLUMN duration_ms SET NOT NULL")
            )
    finally:
        engine.dispose()


def _seed_legacy_rows(url: str) -> None:
    """Populate only the newly owned staged database with synthetic legacy rows."""
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.begin() as connection:
            connection.execute(
                text("""
                    INSERT INTO foundry.rule_candidates
                    (candidate_id, lifecycle, generator_name, template_version)
                    VALUES ('rehearsal_candidate', 'experimental', 'rehearsal', 'test-1')
                """)
            )
            connection.execute(
                text("""
                    INSERT INTO foundry.rule_versions
                    (version_id, candidate_id, rule_version, rule_json, semantic_hash,
                     parent_version_id, generator_version)
                    VALUES ('rehearsal_version', 'rehearsal_candidate', 1, '{}',
                            'synthetic-rehearsal-hash', NULL, 'test-1')
                """)
            )
            connection.execute(
                text("""
                    INSERT INTO foundry.validation_runs
                    (validation_id, rule_version_id, validator_name, validator_version,
                     result, findings_json, corpus_version, executed_at, duration_ms)
                    VALUES ('rehearsal_validation', 'rehearsal_version', 'rehearsal',
                            'test-1', 'pass', '{}', 'test-1',
                            '2026-10-09 00:00:00+00', 9)
                """)
            )
            connection.execute(
                text("""
                    INSERT INTO foundry.review_decisions
                    (decision_id, rule_version_id, reviewer_alias, decision, comment, decided_at)
                    VALUES ('rehearsal_review', 'rehearsal_version', 'test-alias',
                            'approved', 'synthetic legacy review', '2026-10-09 00:00:00+00')
                """)
            )
            connection.execute(
                text("""
                    INSERT INTO foundry.publications
                    (publication_id, rule_version_id, evidence_snapshot_hash, channel, published_at)
                    VALUES ('rehearsal_publication', 'rehearsal_version',
                            'synthetic-rehearsal-hash', 'experimental',
                            '2026-10-09 00:00:00+00')
                """)
            )
    finally:
        engine.dispose()


def _legacy_rows(url: str) -> tuple[str, ...]:
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            return tuple(
                connection.execute(
                    text(
                        f"SELECT row_to_json(t)::text FROM foundry.{table} AS t WHERE {key} = :id"
                    ),
                    {"id": row_id},
                ).scalar_one()
                for table, key, row_id in (
                    ("rule_candidates", "candidate_id", "rehearsal_candidate"),
                    ("rule_versions", "version_id", "rehearsal_version"),
                    ("validation_runs", "validation_id", "rehearsal_validation"),
                    ("review_decisions", "decision_id", "rehearsal_review"),
                    ("publications", "publication_id", "rehearsal_publication"),
                )
            )
    finally:
        engine.dispose()


def rehearse(postgres_bin: Path) -> dict[str, object]:
    if not PYTHON.is_file() or not all(
        (postgres_bin / executable).is_file() for executable in ("initdb.exe", "pg_ctl.exe")
    ):
        raise RuntimeError("rehearsal_runtime_missing")
    owned = Path(tempfile.mkdtemp(prefix="fyp-schema-rehearsal-"))
    cluster = owned / "cluster"
    password_file = owned / "init-password"
    log = owned / "postgres.log"
    password = secrets.token_urlsafe(36)
    port = _port()
    environment = _child_environment()
    started = False
    try:
        password_file.write_text(password + "\n", encoding="ascii")
        _run(
            [
                str(postgres_bin / "initdb.exe"),
                "-D",
                str(cluster),
                "-U",
                "fyp",
                "-E",
                "UTF8",
                "--locale=C",
                "--auth=scram-sha-256",
                "--pwfile",
                str(password_file),
                "-c",
                "listen_addresses=127.0.0.1",
                "-c",
                f"port={port}",
                "-c",
                "shared_buffers=32MB",
                "-c",
                "max_connections=30",
            ],
            environment,
        )
        password_file.unlink()
        _run(
            [
                str(postgres_bin / "pg_ctl.exe"),
                "-D",
                str(cluster),
                "-w",
                "-t",
                "30",
                "-l",
                str(log),
                "start",
            ],
            environment,
            quiet=True,
        )
        started = True
        with psycopg.connect(
            host="127.0.0.1",
            port=port,
            dbname="postgres",
            user="fyp",
            password=password,
            autocommit=True,
        ) as connection:
            connection.execute("CREATE DATABASE fyp_iam")
            connection.execute("CREATE DATABASE fyp_iam_staged")

        def url(database: str) -> str:
            return f"postgresql+psycopg://fyp:{quote(password)}@127.0.0.1:{port}/{database}"

        fresh_url = url("fyp_iam")
        gate_environment = dict(environment, FYP_DATABASE_URL=fresh_url)
        if database_test_gate(gate_environment) is not None:
            raise RuntimeError("disposable_target_gate_failed")

        def upgrade(database_url: str, revision: str) -> None:
            migration_environment = dict(
                environment,
                FYP_DATABASE_URL=database_url,
                FYP_MIGRATION_DATABASE_URL=database_url,
                FYP_DATABASE_DIRECT_URL=database_url,
                FYP_DATABASE_SESSION_URL=database_url,
                FYP_TEST_DATABASE_URL=database_url,
            )
            _run([str(PYTHON), "-m", "alembic", "upgrade", revision], migration_environment)

        upgrade(fresh_url, "head")
        fresh_revision, fresh_catalog = _catalog_at(fresh_url)
        shell_tables = _empty_engine2_shell(fresh_url, fresh_catalog)
        _probe_engine2_constraints(fresh_url)
        _probe_shell_plan(fresh_url)
        _probe_inventory_snapshot_fks(fresh_url)
        _probe_observed_graph_fks(fresh_url)
        _probe_synthetic_writer(fresh_url)
        staged_url = url("fyp_iam_staged")
        upgrade(staged_url, BASE_REVISION)
        staged_base_revision, _ = _catalog_at(staged_url)
        _reconstruct_observed_0004(staged_url)
        reconstructed_revision, reconstructed_catalog = _catalog_at(staged_url)
        if reconstructed_revision != BASE_REVISION or len(reconstructed_catalog["tables"]) != 22:
            raise RuntimeError("reconstructed_boundary_mismatch")
        _seed_legacy_rows(staged_url)
        legacy_before = _legacy_rows(staged_url)
        upgrade(staged_url, "head")
        staged_revision, staged_catalog = _catalog_at(staged_url)
        if _empty_engine2_shell(staged_url, staged_catalog) != shell_tables:
            raise RuntimeError("engine2_shell_mismatch")
        _probe_engine2_constraints(staged_url)
        _probe_shell_plan(staged_url)
        _probe_inventory_snapshot_fks(staged_url)
        _probe_observed_graph_fks(staged_url)
        if _legacy_rows(staged_url) != legacy_before:
            raise RuntimeError("legacy_rows_changed")
        engine = create_engine(staged_url, connect_args={"connect_timeout": 5})
        try:
            with engine.connect() as catalog_connection:
                catalog_connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                inferred_review_count: int = catalog_connection.execute(
                    text("SELECT count(*) FROM foundry.scoped_reviews")
                ).scalar_one()
                inferred_release_count: int = catalog_connection.execute(
                    text("SELECT count(*) FROM foundry.stable_releases")
                ).scalar_one()
                if inferred_review_count or inferred_release_count:
                    raise RuntimeError("legacy_approval_inferred")
        finally:
            engine.dispose()
        return {
            "status": "matched" if fresh_catalog == staged_catalog else "catalog_mismatch",
            "fresh_revision": fresh_revision,
            "staged_base_revision": staged_base_revision,
            "reconstructed_revision": reconstructed_revision,
            "reconstructed_table_count": len(reconstructed_catalog["tables"]),
            "staged_revision": staged_revision,
            "fresh_table_count": len(fresh_catalog["tables"]),
            "staged_table_count": len(staged_catalog["tables"]),
            "synthetic_legacy_rows_preserved": len(legacy_before),
            "empty_rls_engine2_tables": shell_tables,
            "legacy_stable_releases_inferred": inferred_release_count,
            "owned_cluster": str(owned),
            "scope": "fresh_vs_reconstructed_0004_with_synthetic_legacy_rows",
        }
    finally:
        password_file.unlink(missing_ok=True)
        if started:
            _run(
                [
                    str(postgres_bin / "pg_ctl.exe"),
                    "-D",
                    str(cluster),
                    "-w",
                    "-t",
                    "30",
                    "-m",
                    "fast",
                    "stop",
                ],
                environment,
                quiet=True,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = rehearse(args.postgres_bin.resolve())
    except Exception as exc:
        detail = (
            str(exc)
            if isinstance(exc, RuntimeError) and str(exc).startswith("rehearsal_command_failed:")
            else type(exc).__name__
        )
        if isinstance(exc, IntegrityError):
            detail += f":sqlstate_{getattr(exc.orig, 'sqlstate', 'unknown')}"
            detail += f":constraint_{getattr(exc.orig.diag, 'constraint_name', 'unknown')}"
        print(f"rehearsal_failed:{detail}; owned temporary cluster retained for local diagnosis")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "matched" else 1


if __name__ == "__main__":
    sys.exit(main())
