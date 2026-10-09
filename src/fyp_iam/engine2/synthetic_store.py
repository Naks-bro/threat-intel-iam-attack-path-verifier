"""Atomic synthetic handoff import on an explicitly supplied PostgreSQL engine.

No URL resolution, AWS call, real-account import, API route, or auto-migration.
This is a disposable-test path while privacy, auth and purge gates are open.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.engine2.graph_import import GraphImportRejected, prepare_graph_import
from fyp_iam.engine2.graph_schema import metadata as graph_metadata
from fyp_iam.engine2.inventory_import import prepare_inventory_import
from fyp_iam.engine2.observed_graph import ObservedInventoryGraph
from fyp_iam.engine2.schema import metadata
from fyp_iam.engine2.shell_import import ShellImportRejected, prepare_shell_import
from fyp_iam.engine2.snapshot_retention import (
    SnapshotRetentionRejected,
    assert_snapshot_usable,
    plan_purge,
)


class SyntheticImportRejected(ValueError):
    """Fixed, non-sensitive failure code for a disabled or invalid import."""


@dataclass(frozen=True)
class SyntheticImportResult:
    snapshot_id: str
    handoff_hash: str
    row_counts: dict[str, int]


def persist_synthetic_handoff(
    engine: Engine,
    handoff: CollectionHandoff,
    *,
    connection_id: str,
    request_id: str,
    allow_disposable: bool,
    include_observed_graph: bool = False,
) -> SyntheticImportResult:
    """Store one synthetic handoff and verify its rows before commit.

    The caller owns ``engine`` and must point it at a disposable, migrated
    PostgreSQL database. The function cannot authorize managed database use.
    Real-account input is rejected before opening a transaction.
    """

    if not (
        allow_disposable
        and engine.url.drivername == "postgresql+psycopg"
        and engine.url.host in {"127.0.0.1", "localhost", "::1"}
        and engine.url.database == "fyp_iam"
        and not engine.url.query
    ):
        raise SyntheticImportRejected("disposable_target_required")
    if handoff.manifest.data_kind != "synthetic":
        raise SyntheticImportRejected("real_account_import_disabled")

    tables = {
        table.name: table for table in (*metadata.tables.values(), *graph_metadata.tables.values())
    }
    try:
        with engine.begin() as connection:
            registered = (
                connection.execute(
                    select(tables["account_connections"]).where(
                        tables["account_connections"].c.connection_id == connection_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if registered is None or not (
                registered["project_key"] == "fyp"
                and registered["provider"] == "aws"
                and registered["credential_mode"] == "synthetic_fixture"
                and registered["enabled"] is True
            ):
                raise SyntheticImportRejected("synthetic_connection_not_enabled")
            if registered["account_fingerprint"] != handoff.manifest.account_fingerprint:
                raise SyntheticImportRejected("account_fingerprint_mismatch")
            if registered["account_alias"] != handoff.manifest.account_alias:
                raise SyntheticImportRejected("account_alias_mismatch")

            shell = prepare_shell_import(
                handoff,
                connection_id=connection_id,
                expected_account_fingerprint=registered["account_fingerprint"],
                request_id=request_id,
            )
            inventory = prepare_inventory_import(handoff, shell)
            graph_plan = (
                prepare_graph_import(
                    handoff,
                    resolver_version="observed_0.1",
                    generated_at=datetime.now(UTC),
                )
                if include_observed_graph
                else None
            )
            if (
                connection.execute(
                    select(tables["collection_runs"].c.collection_run_id).where(
                        tables["collection_runs"].c.request_id == request_id
                    )
                ).first()
                is not None
            ):
                raise SyntheticImportRejected("request_id_exists")

            rows: tuple[tuple[str, tuple[dict[str, Any], ...]], ...] = (
                ("collection_runs", (shell.run,)),
                ("collection_tasks", shell.tasks),
                ("account_snapshots", (shell.snapshot,)),
                ("collection_layer_coverage", shell.coverage),
                ("coverage_gaps", shell.gaps),
                ("iam_principals", inventory.principals),
                ("iam_policies", inventory.policies),
                ("iam_identity_statements", inventory.identity_statements),
                ("iam_statement_resource_refs", inventory.statement_resource_refs),
                ("iam_attachments", inventory.attachments),
                ("iam_memberships", inventory.memberships),
                ("iam_group_traversals", inventory.group_traversals),
                ("iam_trust_statements", inventory.trust_statements),
                ("iam_trust_principal_refs", inventory.trust_principal_refs),
            )
            if graph_plan is not None:
                rows += (
                    ("graph_projections", (graph_plan.projection,)),
                    ("graph_nodes", graph_plan.nodes),
                    ("graph_edges", graph_plan.edges),
                    ("edge_policy_evidence", graph_plan.evidence),
                )
            for name, records in rows:
                if records:
                    connection.execute(tables[name].insert(), list(records))

            if graph_plan is not None:
                _verify_graph_rows(connection, tables, graph_plan)

            counts: dict[str, int] = {}
            for name, records in rows:
                key = "collection_run_id" if name == "collection_tasks" else "snapshot_id"
                if name == "collection_runs":
                    key = "collection_run_id"
                value = (
                    shell.run["collection_run_id"]
                    if key == "collection_run_id"
                    else shell.snapshot["snapshot_id"]
                )
                actual: int = connection.execute(
                    select(func.count())
                    .select_from(tables[name])
                    .where(tables[name].c[key] == value)
                ).scalar_one()
                if actual != len(records):
                    raise SyntheticImportRejected("row_count_mismatch")
                counts[name] = actual

            stored_hash: str = connection.execute(
                select(tables["account_snapshots"].c.handoff_hash).where(
                    tables["account_snapshots"].c.snapshot_id == shell.snapshot["snapshot_id"]
                )
            ).scalar_one()
            if stored_hash != handoff.content_digest():
                raise SyntheticImportRejected("handoff_digest_mismatch")
            return SyntheticImportResult(shell.snapshot["snapshot_id"], stored_hash, counts)
    except ShellImportRejected as exc:
        raise SyntheticImportRejected(str(exc)) from None
    except GraphImportRejected as exc:
        raise SyntheticImportRejected(str(exc)) from None
    except IntegrityError:
        raise SyntheticImportRejected("schema_constraint_failed") from None


def load_synthetic_handoff(
    engine: Engine,
    snapshot_id: str,
    *,
    allow_disposable: bool,
    as_of: datetime | None = None,
) -> CollectionHandoff:
    """Rebuild and verify a synthetic handoff from ordered disposable DB rows."""

    if not (
        allow_disposable
        and engine.url.drivername == "postgresql+psycopg"
        and engine.url.host in {"127.0.0.1", "localhost", "::1"}
        and engine.url.database == "fyp_iam"
        and not engine.url.query
    ):
        raise SyntheticImportRejected("disposable_target_required")
    tables = {table.name: table for table in metadata.tables.values()}

    def fields(row: dict[str, Any], *names: str) -> dict[str, Any]:
        return {name: row[name] for name in names}

    with engine.connect() as connection:
        connection.exec_driver_sql("SET TRANSACTION READ ONLY")
        snapshot = (
            connection.execute(
                select(tables["account_snapshots"]).where(
                    tables["account_snapshots"].c.snapshot_id == snapshot_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if snapshot is None or snapshot["data_kind"] != "synthetic":
            raise SyntheticImportRejected("synthetic_snapshot_not_found")
        tombstone = (
            connection.execute(
                select(tables["snapshot_purge_tombstones"]).where(
                    tables["snapshot_purge_tombstones"].c.snapshot_id == snapshot_id
                )
            )
            .mappings()
            .one_or_none()
        )
        try:
            assert_snapshot_usable(
                sealed_at=snapshot["sealed_at"],
                retention_expires_at=snapshot["retention_expires_at"],
                data_kind=snapshot["data_kind"],
                as_of=as_of or datetime.now(UTC),
                purged_at=None if tombstone is None else tombstone["purged_at"],
            )
        except SnapshotRetentionRejected as exc:
            raise SyntheticImportRejected(str(exc)) from None

        def ordered(name: str, key: str = "snapshot_id") -> list[dict[str, Any]]:
            table = tables[name]
            bound = snapshot["collection_run_id"] if key == "collection_run_id" else snapshot_id
            rows = connection.execute(
                select(table).where(table.c[key] == bound).order_by(table.c.sequence_no)
            ).mappings()
            result = [dict(row) for row in rows]
            if [row["sequence_no"] for row in result] != list(range(len(result))):
                raise SyntheticImportRejected("stored_sequence_incomplete")
            return result

        account = (
            connection.execute(
                select(tables["account_connections"]).where(
                    tables["account_connections"].c.connection_id == snapshot["connection_id"]
                )
            )
            .mappings()
            .one()
        )
        run = (
            connection.execute(
                select(tables["collection_runs"]).where(
                    tables["collection_runs"].c.collection_run_id == snapshot["collection_run_id"]
                )
            )
            .mappings()
            .one()
        )
        principals = ordered("iam_principals")
        fingerprints = {row["principal_fingerprint"]: row["principal_key"] for row in principals}
        tasks = []
        for row in ordered("collection_tasks", "collection_run_id"):
            scope = row["scope_key"]
            policy_scope = (
                scope not in fingerprints
                and scope != "account"
                and row["api_name"] in {"iam:GetPolicy", "iam:GetPolicyVersion"}
            )
            if scope != "account" and scope not in fingerprints and not policy_scope:
                raise SyntheticImportRejected("stored_task_subject_unknown")
            tasks.append(
                {
                    "operation": row["api_name"],
                    "subject_principal_key": fingerprints.get(scope),
                    "subject_policy_fingerprint": scope if policy_scope else None,
                    "attempt": row["attempt"],
                    "outcome": row["status"],
                    "page_count": row["page_count"],
                    "item_count": row["item_count"],
                    "pagination_complete": row["pagination_complete"],
                    "response_digest": row["response_digest"],
                    "error_code": row["error_code"],
                }
            )
        coverage = [
            fields(
                row,
                "layer",
                "state",
                "authorization_evaluated",
                "object_count",
                "reason_code",
            )
            for row in ordered("collection_layer_coverage")
        ]

        def refs(name: str) -> dict[str, list[str]]:
            table = tables[name]
            rows = connection.execute(
                select(table)
                .where(table.c.snapshot_id == snapshot_id)
                .order_by(table.c.statement_key, table.c.sequence_no)
            ).mappings()
            result: dict[str, list[str]] = {}
            for row in rows:
                keys = result.setdefault(row["statement_key"], [])
                if row["sequence_no"] != len(keys):
                    raise SyntheticImportRejected("stored_ref_sequence_incomplete")
                keys.append(row["principal_key"])
            return result

        resource_refs = refs("iam_statement_resource_refs")
        trust_refs = refs("iam_trust_principal_refs")
        statements = [
            {
                **fields(
                    row,
                    "statement_key",
                    "policy_key",
                    "effect",
                    "action_mode",
                    "action_patterns",
                    "resource_mode",
                    "condition_state",
                    "condition_keys",
                    "source_digest",
                ),
                "resource_principal_keys": resource_refs.pop(row["statement_key"], []),
            }
            for row in ordered("iam_identity_statements")
        ]
        trusts = [
            {
                **fields(
                    row,
                    "statement_key",
                    "policy_key",
                    "role_key",
                    "effect",
                    "action_mode",
                    "action_patterns",
                    "selector_state",
                    "service_principals",
                    "condition_state",
                    "condition_keys",
                    "source_digest",
                ),
                "trusted_principal_keys": trust_refs.pop(row["statement_key"], []),
            }
            for row in ordered("iam_trust_statements")
        ]
        if resource_refs or trust_refs:
            raise SyntheticImportRejected("stored_orphan_refs")
        inventory = {
            "schema_version": snapshot["contract_version"],
            "snapshot_id": snapshot_id,
            "principals": [
                fields(
                    row,
                    "principal_key",
                    "principal_fingerprint",
                    "kind",
                    "display_alias",
                    "source_digest",
                )
                for row in principals
            ],
            "policies": [
                fields(
                    row,
                    "policy_key",
                    "kind",
                    "version_label",
                    "is_default",
                    "parse_state",
                    "source_digest",
                )
                for row in ordered("iam_policies")
            ],
            "statements": statements,
            "attachments": [
                fields(row, "principal_key", "policy_key", "kind", "source_digest")
                for row in ordered("iam_attachments")
            ],
            "memberships": [
                fields(row, "user_key", "group_key", "source_digest")
                for row in ordered("iam_memberships")
            ],
            "group_traversals": [
                fields(
                    row, "user_key", "state", "membership_count", "evidence_digest", "reason_code"
                )
                for row in ordered("iam_group_traversals")
            ],
            "trust_statements": trusts,
        }
        manifest = {
            "schema_version": snapshot["contract_version"],
            "data_kind": snapshot["data_kind"],
            "run_id": run["collection_run_id"],
            "snapshot_id": snapshot_id,
            "account_alias": account["account_alias"],
            "account_fingerprint": account["account_fingerprint"],
            "collector_version": run["collector_version"],
            "started_at": run["started_at"],
            "sealed_at": snapshot["sealed_at"],
            "outcome": run["status"],
            "snapshot_digest": snapshot["content_hash"],
            "tasks": tasks,
            "coverage": coverage,
        }
        try:
            rebuilt = CollectionHandoff.model_validate(
                {"manifest": manifest, "inventory": inventory}
            )
        except ValueError:
            raise SyntheticImportRejected("stored_handoff_invalid") from None
        if rebuilt.content_digest() != snapshot["handoff_hash"]:
            raise SyntheticImportRejected("stored_handoff_digest_mismatch")
        return rebuilt


def _verify_graph_rows(connection: Any, tables: dict[str, Any], plan: Any) -> None:
    """Compare every stored projection row with the deterministic row plan."""

    order_columns = {
        "graph_projections": ("snapshot_id",),
        "graph_nodes": ("node_key",),
        "graph_edges": ("relation_id",),
        "edge_policy_evidence": ("relation_id", "evidence_ordinal"),
    }
    for name, expected in (
        ("graph_projections", (plan.projection,)),
        ("graph_nodes", plan.nodes),
        ("graph_edges", plan.edges),
        ("edge_policy_evidence", plan.evidence),
    ):
        table = tables[name]
        stored = [
            dict(row)
            for row in connection.execute(
                select(table)
                .where(table.c.snapshot_id == plan.graph.snapshot_id)
                .order_by(*(table.c[column] for column in order_columns[name]))
            ).mappings()
        ]
        if stored != list(expected):
            raise SyntheticImportRejected("stored_graph_row_mismatch")


def load_synthetic_observed_graph(
    engine: Engine, snapshot_id: str, *, allow_disposable: bool
) -> ObservedInventoryGraph:
    """Rebuild the graph from the exact stored synthetic handoff and compare all rows."""

    handoff = load_synthetic_handoff(engine, snapshot_id, allow_disposable=allow_disposable)
    tables = {table.name: table for table in graph_metadata.tables.values()}
    with engine.connect() as connection:
        connection.exec_driver_sql("SET TRANSACTION READ ONLY")
        projection = (
            connection.execute(
                select(tables["graph_projections"]).where(
                    tables["graph_projections"].c.snapshot_id == snapshot_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if projection is None:
            raise SyntheticImportRejected("stored_graph_not_found")
        try:
            plan = prepare_graph_import(
                handoff,
                resolver_version=projection["resolver_version"],
                generated_at=projection["generated_at"],
            )
        except GraphImportRejected:
            raise SyntheticImportRejected("stored_graph_input_invalid") from None
        _verify_graph_rows(connection, tables, plan)
        return plan.graph


def purge_synthetic_snapshot(
    engine: Engine,
    snapshot_id: str,
    *,
    allow_disposable: bool,
    purged_at: datetime,
    reason: str = "operator_purge",
) -> dict[str, object]:
    """Delete redacted synthetic bodies and leave an explicit hash tombstone.

    Real-account rows are refused. This does not run on a managed database and
    does not authorize retention of a live AWS snapshot.
    """

    if not (
        allow_disposable
        and engine.url.drivername == "postgresql+psycopg"
        and engine.url.host in {"127.0.0.1", "localhost", "::1"}
        and engine.url.database == "fyp_iam"
        and not engine.url.query
    ):
        raise SyntheticImportRejected("disposable_target_required")
    tables = {
        table.name: table for table in (*metadata.tables.values(), *graph_metadata.tables.values())
    }
    try:
        with engine.begin() as connection:
            snapshot = (
                connection.execute(
                    select(tables["account_snapshots"]).where(
                        tables["account_snapshots"].c.snapshot_id == snapshot_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if snapshot is None or snapshot["data_kind"] != "synthetic":
                raise SyntheticImportRejected("synthetic_snapshot_not_found")
            existing = connection.execute(
                select(tables["snapshot_purge_tombstones"].c.snapshot_id).where(
                    tables["snapshot_purge_tombstones"].c.snapshot_id == snapshot_id
                )
            ).first()
            if existing is not None:
                raise SyntheticImportRejected("snapshot_already_purged")
            plan = plan_purge(
                snapshot_id=snapshot_id,
                content_hash=snapshot["content_hash"],
                handoff_hash=snapshot["handoff_hash"],
                data_kind=snapshot["data_kind"],
                sealed_at=snapshot["sealed_at"],
                retention_expires_at=snapshot["retention_expires_at"],
                purged_at=purged_at,
                reason=reason,
            )
            connection.execute(tables["snapshot_purge_tombstones"].insert(), plan.tombstone)
            for name in plan.delete_tables:
                table = tables[name]
                connection.execute(table.delete().where(table.c.snapshot_id == snapshot_id))
                remaining = connection.execute(
                    select(func.count())
                    .select_from(table)
                    .where(table.c.snapshot_id == snapshot_id)
                ).scalar_one()
                if remaining != 0:
                    raise SyntheticImportRejected("purge_incomplete")
            return plan.tombstone
    except SnapshotRetentionRejected as exc:
        raise SyntheticImportRejected(str(exc)) from None
    except IntegrityError:
        raise SyntheticImportRejected("schema_constraint_failed") from None
