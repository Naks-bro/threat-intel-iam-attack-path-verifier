"""Read-only, redacted PostgreSQL schema inventory for migration planning.

Run with ``python -m fyp_iam.persistence.schema_audit``. This never migrates,
seeds, or reads application rows. Output contains schema metadata only.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

from sqlalchemy import Connection, create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError

from fyp_iam.engine1.foundry.models import Base
from fyp_iam.engine2.graph_schema import metadata as graph_metadata
from fyp_iam.engine2.schema import metadata as inventory_metadata
from fyp_iam.persistence.status import _head_revision
from fyp_iam.persistence.urls import application_database_url, prepare_url

AuditStatus = Literal["not_configured", "unavailable", "migration_required", "available"]


@dataclass(frozen=True)
class SchemaAudit:
    status: AuditStatus
    code: str
    revision: str | None = None
    repository_head: str | None = None
    table_count: int | None = None
    fingerprint_sha256: str | None = None
    rls_enabled_tables: int | None = None
    anon_select_tables: int | None = None
    authenticated_select_tables: int | None = None
    missing_model_tables: tuple[str, ...] = ()
    extra_database_tables: tuple[str, ...] = ()
    missing_model_columns: tuple[str, ...] = ()
    extra_database_columns: tuple[str, ...] = ()
    nullability_mismatches: tuple[str, ...] = ()


def _declared_tables() -> dict[str, Any]:
    """Include both migration-owned schemas without invoking create_all."""

    tables = [
        *Base.metadata.tables.values(),
        *inventory_metadata.tables.values(),
        *graph_metadata.tables.values(),
    ]
    return {table.name: table for table in tables}


def _catalog(connection: Connection) -> tuple[str | None, dict[str, Any]]:
    """Reflect only ``foundry`` DDL, within a read-only transaction."""

    connection.exec_driver_sql("SET TRANSACTION READ ONLY")
    inspector = inspect(connection)
    table_names = sorted(inspector.get_table_names(schema="foundry"))
    revision = None
    if "alembic_version" in table_names:
        revision = connection.execute(
            text("SELECT version_num FROM foundry.alembic_version")
        ).scalar()
    security_row = connection.execute(
        text(
            "SELECT count(*) FILTER (WHERE c.relrowsecurity) AS rls_enabled, "
            "count(*) FILTER (WHERE has_table_privilege(to_regrole('anon'), c.oid, 'SELECT')) "
            "AS anon_select, "
            "count(*) FILTER (WHERE has_table_privilege(to_regrole('authenticated'), c.oid, "
            "'SELECT')) "
            "AS authenticated_select "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'foundry' AND c.relkind = 'r'"
        )
    ).one()
    tables: list[dict[str, Any]] = []
    for name in table_names:
        columns = sorted(
            (
                {
                    "name": column["name"],
                    "type": str(column["type"]),
                    "nullable": bool(column["nullable"]),
                }
                for column in inspector.get_columns(name, schema="foundry")
            ),
            key=lambda item: str(item["name"]),
        )
        pk = inspector.get_pk_constraint(name, schema="foundry")
        foreign_keys = sorted(
            (
                {
                    "columns": fk["constrained_columns"],
                    "schema": fk.get("referred_schema") or "foundry",
                    "table": fk["referred_table"],
                    "referred_columns": fk["referred_columns"],
                }
                for fk in inspector.get_foreign_keys(name, schema="foundry")
            ),
            key=lambda item: (item["columns"], item["table"]),
        )
        unique = sorted(
            (
                sorted(item["column_names"])
                for item in inspector.get_unique_constraints(name, schema="foundry")
            ),
        )
        checks = sorted(
            str(item["sqltext"]) for item in inspector.get_check_constraints(name, schema="foundry")
        )
        indexes = sorted(
            (
                {"columns": item["column_names"], "unique": bool(item["unique"])}
                for item in inspector.get_indexes(name, schema="foundry")
            ),
            key=lambda item: (str(item["columns"]), item["unique"]),
        )
        tables.append(
            {
                "name": name,
                "columns": columns,
                "primary_key": pk.get("constrained_columns") or [],
                "foreign_keys": foreign_keys,
                "unique": unique,
                "checks": checks,
                "indexes": indexes,
            }
        )
    return revision, {
        "schema": "foundry",
        "tables": tables,
        "security": {
            "rls_enabled": int(security_row.rls_enabled),
            "anon_select": int(security_row.anon_select),
            "authenticated_select": int(security_row.authenticated_select),
        },
    }


def audit_schema(url: str | None) -> SchemaAudit:
    """Return fixed status codes and metadata digest, never a URL or DB row."""

    if not url:
        return SchemaAudit(status="not_configured", code="not_configured")
    prepared, error = prepare_url(url)
    if error:
        return SchemaAudit(status="unavailable", code=error)
    engine = None
    try:
        engine = create_engine(prepared, connect_args={"connect_timeout": 5})
        with engine.connect() as connection:
            revision, catalog = _catalog(connection)
        names = {table["name"] for table in catalog["tables"]} - {"alembic_version"}
        model_tables = _declared_tables()
        model_names = set(model_tables)
        database_tables = {table["name"]: table for table in catalog["tables"]}
        missing_columns: list[str] = []
        extra_columns: list[str] = []
        nullability_mismatches: list[str] = []
        for name in sorted(names & model_names):
            model_columns = {column.name: column for column in model_tables[name].columns}
            database_columns = {
                column["name"]: column for column in database_tables[name]["columns"]
            }
            missing_columns.extend(
                f"{name}.{column}"
                for column in sorted(model_columns.keys() - database_columns.keys())
            )
            extra_columns.extend(
                f"{name}.{column}"
                for column in sorted(database_columns.keys() - model_columns.keys())
            )
            nullability_mismatches.extend(
                f"{name}.{column}"
                for column in sorted(model_columns.keys() & database_columns.keys())
                if database_columns[column].get("nullable") is not model_columns[column].nullable
            )
        canonical = json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
        head = _head_revision()
        missing = tuple(sorted(model_names - names))
        extra = tuple(sorted(names - model_names))
        if revision is None:
            status: AuditStatus = "migration_required"
            code = "schema_missing"
        elif (
            head is None
            or revision != head
            or missing
            or extra
            or missing_columns
            or extra_columns
            or nullability_mismatches
        ):
            status = "migration_required"
            code = "behind_or_drifted"
        else:
            status = "available"
            code = "current_table_inventory"
        return SchemaAudit(
            status=status,
            code=code,
            revision=revision,
            repository_head=head,
            table_count=len(names),
            fingerprint_sha256=hashlib.sha256(canonical).hexdigest(),
            rls_enabled_tables=catalog.get("security", {}).get("rls_enabled"),
            anon_select_tables=catalog.get("security", {}).get("anon_select"),
            authenticated_select_tables=catalog.get("security", {}).get("authenticated_select"),
            missing_model_tables=missing,
            extra_database_tables=extra,
            missing_model_columns=tuple(missing_columns),
            extra_database_columns=tuple(extra_columns),
            nullability_mismatches=tuple(nullability_mismatches),
        )
    except (SQLAlchemyError, OSError, ValueError):
        return SchemaAudit(status="unavailable", code="unreachable")
    finally:
        if engine is not None:
            engine.dispose()


def main() -> None:
    print(json.dumps(asdict(audit_schema(application_database_url())), sort_keys=True))


if __name__ == "__main__":
    main()
