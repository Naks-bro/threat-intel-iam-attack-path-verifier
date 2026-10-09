"""The schema audit must never migrate, read domain rows, or reveal a URL."""

import json
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from fyp_iam.persistence import schema_audit


def test_missing_or_bad_url_returns_fixed_code() -> None:
    assert schema_audit.audit_schema(None).code == "not_configured"
    result = schema_audit.audit_schema("sqlite:///private.db")
    assert (result.status, result.code) == ("unavailable", "sqlite_rejected")


def test_catalog_reads_only_foundry_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    statements: list[str] = []

    class Connection:
        def exec_driver_sql(self, sql: str) -> None:
            statements.append(sql)

        def execute(self, sql: Any) -> Any:
            statements.append(str(sql))
            if "alembic_version" in str(sql):
                return SimpleNamespace(scalar=lambda: "20261003_0004")
            return SimpleNamespace(
                one=lambda: SimpleNamespace(rls_enabled=0, anon_select=0, authenticated_select=0)
            )

    class Inspector:
        def get_table_names(self, *, schema: str) -> list[str]:
            assert schema == "foundry"
            return ["alembic_version"]

        def get_columns(self, name: str, *, schema: str) -> list[dict[str, Any]]:
            return [{"name": "version_num", "type": "VARCHAR(32)", "nullable": False}]

        def get_pk_constraint(self, name: str, *, schema: str) -> dict[str, Any]:
            return {"constrained_columns": ["version_num"]}

        def get_foreign_keys(self, name: str, *, schema: str) -> list[Any]:
            return []

        def get_unique_constraints(self, name: str, *, schema: str) -> list[Any]:
            return []

        def get_check_constraints(self, name: str, *, schema: str) -> list[Any]:
            return []

        def get_indexes(self, name: str, *, schema: str) -> list[Any]:
            return []

    monkeypatch.setattr(schema_audit, "inspect", lambda _connection: Inspector())
    revision, catalog = schema_audit._catalog(Connection())  # type: ignore[arg-type]
    assert revision == "20261003_0004"
    assert catalog["tables"][0]["name"] == "alembic_version"
    assert catalog["security"] == {
        "rls_enabled": 0,
        "anon_select": 0,
        "authenticated_select": 0,
    }
    assert statements[:2] == [
        "SET TRANSACTION READ ONLY",
        "SELECT version_num FROM foundry.alembic_version",
    ]
    assert "pg_class" in statements[2]
    assert "has_table_privilege" in statements[2]


def test_connection_failure_never_returns_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_url = "postgresql+psycopg://user:secret@127.0.0.1:1/fyp_iam"

    def fail_connect(_url: str, **_kwargs: Any) -> Any:
        raise OperationalError("connect", {}, Exception(secret_url))

    monkeypatch.setattr(schema_audit, "create_engine", fail_connect)
    result = schema_audit.audit_schema(secret_url)
    output = json.dumps(result.__dict__)
    assert (result.status, result.code) == ("unavailable", "unreachable")
    assert "secret" not in output
    assert "127.0.0.1" not in output


@pytest.mark.parametrize(
    ("revision", "expected_status", "expected_missing"),
    [
        ("20261003_0004", "migration_required", ("stable_releases",)),
        ("20261009_0009", "migration_required", ()),
        ("20261009_0010", "migration_required", ()),
        ("20261009_0011", "available", ()),
    ],
)
def test_revision_and_missing_tables_are_reported_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    revision: str,
    expected_status: str,
    expected_missing: tuple[str, ...],
) -> None:
    class Engine:
        def connect(self) -> Any:
            class Context:
                def __enter__(self) -> object:
                    return object()

                def __exit__(self, *_args: object) -> None:
                    pass

            return Context()

        def dispose(self) -> None:
            pass

    model_tables = schema_audit._declared_tables()
    names = set(model_tables)
    if revision == "20261003_0004":
        names.remove("stable_releases")
    monkeypatch.setattr(schema_audit, "create_engine", lambda *_args, **_kwargs: Engine())
    monkeypatch.setattr(schema_audit, "_head_revision", lambda: "20261009_0011")
    monkeypatch.setattr(
        schema_audit,
        "_catalog",
        lambda _connection: (
            revision,
            {
                "schema": "foundry",
                "security": {
                    "rls_enabled": 15,
                    "anon_select": 0,
                    "authenticated_select": 0,
                },
                "tables": [
                    {
                        "name": name,
                        "columns": [
                            {"name": column.name, "nullable": column.nullable}
                            for column in model_tables[name].columns
                        ],
                    }
                    for name in sorted(names)
                ],
            },
        ),
    )
    result = schema_audit.audit_schema("postgresql+psycopg://user:secret@localhost/db")
    assert result.status == expected_status
    assert result.missing_model_tables == expected_missing
    assert result.repository_head == "20261009_0011"
    assert result.fingerprint_sha256 is not None
    assert result.rls_enabled_tables == 15
    assert result.anon_select_tables == 0
    assert result.authenticated_select_tables == 0


@pytest.mark.parametrize(
    ("change", "expected_missing", "expected_extra"),
    [
        ("missing", ("sources.source_key",), ()),
        ("extra", (), ("sources.unexpected_column",)),
    ],
)
def test_current_revision_with_column_drift_is_not_available(
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    expected_missing: tuple[str, ...],
    expected_extra: tuple[str, ...],
) -> None:
    class Engine:
        def connect(self) -> Any:
            class Context:
                def __enter__(self) -> object:
                    return object()

                def __exit__(self, *_args: object) -> None:
                    pass

            return Context()

        def dispose(self) -> None:
            pass

    tables = [
        {
            "name": table.name,
            "columns": [
                {"name": column.name, "nullable": column.nullable} for column in table.columns
            ],
        }
        for table in schema_audit._declared_tables().values()
    ]
    source = next(table for table in tables if table["name"] == "sources")
    if change == "missing":
        source["columns"] = [item for item in source["columns"] if item["name"] != "source_key"]
    else:
        source["columns"].append({"name": "unexpected_column"})
    monkeypatch.setattr(schema_audit, "create_engine", lambda *_args, **_kwargs: Engine())
    monkeypatch.setattr(schema_audit, "_head_revision", lambda: "20261009_0011")
    monkeypatch.setattr(
        schema_audit,
        "_catalog",
        lambda _connection: ("20261009_0011", {"schema": "foundry", "tables": tables}),
    )

    result = schema_audit.audit_schema("postgresql+psycopg://user:secret@localhost/db")
    assert (result.status, result.code) == ("migration_required", "behind_or_drifted")
    assert result.missing_model_columns == expected_missing
    assert result.extra_database_columns == expected_extra


def test_current_revision_with_nullability_drift_is_not_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Engine:
        def connect(self) -> Any:
            class Context:
                def __enter__(self) -> object:
                    return object()

                def __exit__(self, *_args: object) -> None:
                    pass

            return Context()

        def dispose(self) -> None:
            pass

    tables = [
        {
            "name": table.name,
            "columns": [
                {"name": column.name, "nullable": column.nullable} for column in table.columns
            ],
        }
        for table in schema_audit._declared_tables().values()
    ]
    validation = next(table for table in tables if table["name"] == "validation_runs")
    duration = next(column for column in validation["columns"] if column["name"] == "duration_ms")
    duration["nullable"] = not duration["nullable"]
    monkeypatch.setattr(schema_audit, "create_engine", lambda *_args, **_kwargs: Engine())
    monkeypatch.setattr(schema_audit, "_head_revision", lambda: "20261009_0011")
    monkeypatch.setattr(
        schema_audit,
        "_catalog",
        lambda _connection: ("20261009_0011", {"schema": "foundry", "tables": tables}),
    )

    result = schema_audit.audit_schema("postgresql+psycopg://user:secret@localhost/db")
    assert (result.status, result.code) == ("migration_required", "behind_or_drifted")
    assert result.nullability_mismatches == ("validation_runs.duration_ms",)
