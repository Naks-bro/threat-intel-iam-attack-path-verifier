"""Report whether PostgreSQL can serve the foundry. Details never include a URL."""

import threading
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from fyp_iam.persistence.urls import prepare_url

_PROBE = threading.Lock()


def database_status(url: str | None, *, probe: bool = True) -> tuple[str, str]:
    """Return one of the health states and a fixed detail code."""

    if not url:
        return "not_configured", "not_configured"
    prepared, error = prepare_url(url)
    if error:
        return "unavailable", error
    if not probe:
        return "connecting", "not_probed"
    if not _PROBE.acquire(blocking=False):
        return "connecting", "in_progress"
    try:
        return _probe(prepared)
    finally:
        _PROBE.release()


def _probe(url: str) -> tuple[str, str]:
    engine = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            return _revision(connection)
    except SQLAlchemyError:
        return "unavailable", "unreachable"
    finally:
        engine.dispose()


def _revision(connection: object) -> tuple[str, str]:
    execute = getattr(connection, "execute", None)
    if execute is None:
        return "unavailable", "unreachable"
    head = _head_revision()
    if head is None:
        return "migration_required", "revision_unknown"
    present = execute(text("SELECT to_regclass('foundry.alembic_version')")).scalar()
    if present is None:
        return "migration_required", "schema_missing"
    current = execute(text("SELECT version_num FROM foundry.alembic_version")).scalar()
    if current != head:
        return "migration_required", "behind"
    return "available", "current"


def alembic_ini_path() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "alembic.ini"
        if candidate.is_file():
            return candidate
    return None


def _head_revision() -> str | None:
    ini = alembic_ini_path()
    if ini is None:
        return None
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(Config(str(ini)))
    return script.get_current_head()
