"""Opt-in storage for one redacted real-account handoff.

The caller must supply a disposable loopback ``fyp_iam`` engine and both opt-in
flags. Credentials, raw policy bodies, and ``authorization_evaluated=true`` are
rejected before a transaction opens. This module does not call AWS, migrate a
managed database, or schedule a purge.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import reject_sensitive_text
from fyp_iam.engine2.graph_import import GraphImportRejected, prepare_graph_import
from fyp_iam.engine2.graph_schema import metadata as graph_metadata
from fyp_iam.engine2.inventory_import import prepare_inventory_import
from fyp_iam.engine2.schema import metadata
from fyp_iam.engine2.shell_import import ShellImportRejected, prepare_shell_import

_POLICY_KEYS = frozenset({"Statement", "PolicyDocument", "policy_document", "policy_body"})
_POLICY_TEXT = re.compile(r'"Statement"|\'Statement\'|PolicyDocument|2012-10-17')


class RealAccountImportRejected(ValueError):
    """Fixed, non-sensitive failure code for a refused real-account write."""


@dataclass(frozen=True)
class RealAccountImportResult:
    snapshot_id: str
    snapshot_digest: str
    handoff_hash: str
    row_counts: dict[str, int]


def persist_real_account_handoff(
    engine: Engine,
    handoff: CollectionHandoff,
    *,
    connection_id: str,
    request_id: str,
    allow_disposable: bool,
    allow_real_account: bool,
    include_observed_graph: bool = True,
) -> RealAccountImportResult:
    """Store one redacted real-account handoff and verify its rows before commit.

    ``allow_disposable`` and ``allow_real_account`` must both be true. The engine
    must already point at loopback ``fyp_iam``. The registered connection must
    use ``external_profile``. No credential or raw policy body is written.
    """

    _require_disposable(engine, allow_disposable)
    if not allow_real_account:
        raise RealAccountImportRejected("real_account_opt_in_required")
    _reject_unsafe_content(handoff)
    kind = _data_kind(handoff)
    if kind is None:
        raise RealAccountImportRejected("handoff_invalid")
    if kind != "real_account_observed":
        raise RealAccountImportRejected("real_account_data_kind_required")
    sealed = _seal(handoff)
    try:
        shell = prepare_shell_import(
            sealed,
            connection_id=connection_id,
            expected_account_fingerprint=sealed.manifest.account_fingerprint,
            request_id=request_id,
        )
        inventory = prepare_inventory_import(sealed, shell)
        graph_plan = (
            prepare_graph_import(
                sealed,
                resolver_version="observed_0.1",
                generated_at=sealed.manifest.sealed_at,
            )
            if include_observed_graph
            else None
        )
    except ShellImportRejected as exc:
        raise RealAccountImportRejected(str(exc)) from None
    except GraphImportRejected as exc:
        raise RealAccountImportRejected(str(exc)) from None

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
                and registered["credential_mode"] == "external_profile"
                and registered["enabled"] is True
            ):
                raise RealAccountImportRejected("real_account_connection_not_enabled")
            if registered["account_fingerprint"] != sealed.manifest.account_fingerprint:
                raise RealAccountImportRejected("account_fingerprint_mismatch")
            if registered["account_alias"] != sealed.manifest.account_alias:
                raise RealAccountImportRejected("account_alias_mismatch")
            if (
                connection.execute(
                    select(tables["collection_runs"].c.collection_run_id).where(
                        tables["collection_runs"].c.request_id == request_id
                    )
                ).first()
                is not None
            ):
                raise RealAccountImportRejected("request_id_exists")

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
                    raise RealAccountImportRejected("row_count_mismatch")
                counts[name] = actual

            stored_hash: str = connection.execute(
                select(tables["account_snapshots"].c.handoff_hash).where(
                    tables["account_snapshots"].c.snapshot_id == shell.snapshot["snapshot_id"]
                )
            ).scalar_one()
            stored_snapshot: str = connection.execute(
                select(tables["account_snapshots"].c.content_hash).where(
                    tables["account_snapshots"].c.snapshot_id == shell.snapshot["snapshot_id"]
                )
            ).scalar_one()
            if stored_hash != sealed.content_digest():
                raise RealAccountImportRejected("handoff_digest_mismatch")
            if stored_snapshot != sealed.manifest.snapshot_digest:
                raise RealAccountImportRejected("stored_snapshot_digest_mismatch")
            return RealAccountImportResult(
                shell.snapshot["snapshot_id"], stored_snapshot, stored_hash, counts
            )
    except IntegrityError:
        raise RealAccountImportRejected("schema_constraint_failed") from None


def load_real_account_handoff(
    engine: Engine,
    snapshot_id: str,
    *,
    allow_disposable: bool,
    allow_real_account: bool,
) -> CollectionHandoff:
    """Rebuild a real-account handoff and require the same snapshot digest."""

    _require_disposable(engine, allow_disposable)
    if not allow_real_account:
        raise RealAccountImportRejected("real_account_opt_in_required")
    tables = {table.name: table for table in metadata.tables.values()}

    def fields(row: Mapping[str, Any], *names: str) -> dict[str, Any]:
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
        if snapshot is None or snapshot["data_kind"] != "real_account_observed":
            raise RealAccountImportRejected("real_account_snapshot_not_found")

        def ordered(name: str, key: str = "snapshot_id") -> list[dict[str, Any]]:
            table = tables[name]
            bound = snapshot["collection_run_id"] if key == "collection_run_id" else snapshot_id
            rows = connection.execute(
                select(table).where(table.c[key] == bound).order_by(table.c.sequence_no)
            ).mappings()
            result = [dict(row) for row in rows]
            if [row["sequence_no"] for row in result] != list(range(len(result))):
                raise RealAccountImportRejected("stored_sequence_incomplete")
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
                raise RealAccountImportRejected("stored_task_subject_unknown")
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
                    raise RealAccountImportRejected("stored_ref_sequence_incomplete")
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
            raise RealAccountImportRejected("stored_orphan_refs")
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
            raise RealAccountImportRejected("stored_handoff_invalid") from None
        if rebuilt.inventory.content_digest() != snapshot["content_hash"]:
            raise RealAccountImportRejected("stored_snapshot_digest_mismatch")
        if rebuilt.manifest.snapshot_digest != snapshot["content_hash"]:
            raise RealAccountImportRejected("stored_snapshot_digest_mismatch")
        if rebuilt.content_digest() != snapshot["handoff_hash"]:
            raise RealAccountImportRejected("stored_handoff_digest_mismatch")
        return rebuilt


def _require_disposable(engine: Engine, allow_disposable: bool) -> None:
    if not (
        allow_disposable
        and engine.url.drivername == "postgresql+psycopg"
        and engine.url.host in {"127.0.0.1", "localhost", "::1"}
        and engine.url.database == "fyp_iam"
        and not engine.url.query
    ):
        raise RealAccountImportRejected("disposable_target_required")


def _data_kind(handoff: object) -> str | None:
    manifest: object
    if isinstance(handoff, Mapping):
        manifest = cast(Mapping[str, object], handoff).get("manifest")
    else:
        manifest = getattr(handoff, "manifest", None)
    kind: object
    if isinstance(manifest, Mapping):
        kind = cast(Mapping[str, object], manifest).get("data_kind")
    else:
        kind = getattr(manifest, "data_kind", None)
    return kind if isinstance(kind, str) else None


def _seal(handoff: object) -> CollectionHandoff:
    try:
        raw = handoff.model_dump(mode="json") if isinstance(handoff, CollectionHandoff) else handoff
        sealed = CollectionHandoff.model_validate(raw)
    except (ValueError, TypeError):
        raise RealAccountImportRejected("handoff_invalid") from None
    _reject_unsafe_content(sealed.model_dump(mode="json"))
    if sealed.manifest.data_kind != "real_account_observed":
        raise RealAccountImportRejected("real_account_data_kind_required")
    return sealed


def _reject_unsafe_content(value: object) -> None:
    """Reject credentials, raw policy bodies, and evaluated authorization."""

    credentials = False
    policy = False
    evaluated = False
    seen: set[int] = set()

    def walk(item: object, key: str | None) -> None:
        nonlocal credentials, policy, evaluated
        if key in _POLICY_KEYS:
            policy = True
        if key == "authorization_evaluated" and item is True:
            evaluated = True
        if isinstance(item, str):
            if _sensitive(item) or (key is not None and _sensitive(key)):
                credentials = True
            if _POLICY_TEXT.search(item):
                policy = True
            return
        if key is not None and _sensitive(key):
            credentials = True
        marker = id(item)
        if marker in seen:
            return
        seen.add(marker)
        if isinstance(item, Mapping):
            mapping = cast(Mapping[object, object], item)
            for child_key, child in mapping.items():
                walk(child, child_key if isinstance(child_key, str) else None)
            return
        if isinstance(item, (list, tuple)):
            for child in item:
                walk(child, None)
            return
        dump = getattr(item, "model_dump", None)
        if callable(dump):
            try:
                dumped = dump(mode="json")
            except (TypeError, ValueError):
                dumped = None
            if dumped is not None:
                walk(dumped, None)
                return
        data = getattr(item, "__dict__", None)
        if isinstance(data, dict):
            walk(
                {name: child for name, child in data.items() if not str(name).startswith("_")},
                None,
            )

    walk(value, None)
    if credentials:
        raise RealAccountImportRejected("credential_rejected")
    if policy:
        raise RealAccountImportRejected("raw_policy_body_rejected")
    if evaluated:
        raise RealAccountImportRejected("authorization_evaluated_rejected")


def _sensitive(value: str) -> bool:
    try:
        reject_sensitive_text(value)
    except ValueError:
        return True
    return False


def _verify_graph_rows(connection: Any, tables: dict[str, Any], plan: Any) -> None:
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
            raise RealAccountImportRejected("stored_graph_row_mismatch")
