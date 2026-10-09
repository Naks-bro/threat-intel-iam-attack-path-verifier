"""Database commands. They print status codes, never connection strings."""

import json
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence

from fyp_iam.persistence.redact import install_redaction, redact
from fyp_iam.persistence.status import alembic_ini_path, database_status
from fyp_iam.persistence.urls import (
    application_database_url,
    migration_database_url,
    prepare_url,
)

_API = "http://127.0.0.1:8766"


def main(argv: Sequence[str] | None = None) -> int:
    install_redaction()
    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0] if args else ""
    if command == "check":
        return _check()
    if command == "migrate":
        return _migrate()
    if command == "seed":
        return _seed()
    if command == "verify-restart":
        return _verify_restart()
    print("usage: python -m fyp_iam.persistence check|migrate|seed|verify-restart")
    return 2


def _check() -> int:
    state, detail = database_status(application_database_url())
    print(f"{state} {detail}")
    if state == "available":
        return 0
    if state == "not_configured":
        return 3
    if state == "migration_required":
        return 2
    return 1


def _migrate() -> int:
    url = migration_database_url()
    if not url:
        print("not_configured")
        return 3
    _prepared, error = prepare_url(url)
    if error:
        print(error)
        return 1
    from alembic import command
    from alembic.config import Config

    ini = alembic_ini_path()
    if ini is None:
        print("revision_unknown")
        return 1
    try:
        command.upgrade(Config(str(ini)), "head")
    except Exception as exc:
        print(redact(str(exc)).splitlines()[0][:160] or "migration_failed")
        return 1
    print("migrated")
    return 0


def _seed() -> int:
    url = application_database_url()
    state, _detail = database_status(url)
    if state != "available" or url is None:
        print(state)
        return 3 if state == "not_configured" else 1
    from fyp_iam.engine1.foundry.store import persist_foundry

    overview = persist_foundry(url)
    candidate = overview.get("candidate")
    if not isinstance(candidate, dict):
        print("no_candidate")
        return 1
    print(candidate["rule_id"])
    print(candidate["version_id"])
    return 0


def _verify_restart() -> int:
    url = application_database_url()
    state, _detail = database_status(url)
    if state != "available" or url is None:
        print(state)
        return 3 if state == "not_configured" else 1
    from fyp_iam.engine1.foundry.store import persist_foundry, read_rule

    overview = persist_foundry(url)
    candidate = overview.get("candidate")
    if not isinstance(candidate, dict):
        print("no_candidate")
        return 1
    version_id = str(candidate["version_id"])
    rule_id = str(candidate["rule_id"])
    stored = read_rule(url, version_id)
    if stored is None or stored.get("rule_id") != rule_id:
        print("not_visible")
        return 1
    first = _api_rule(version_id)
    second = _api_rule(version_id)
    if first != rule_id or second != rule_id:
        print("not_visible")
        return 1
    print(rule_id)
    print(version_id)
    print("persisted")
    return 0


def _api_rule(version_id: str) -> str | None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "fyp_iam.api.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8766",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(20):
            try:
                with urllib.request.urlopen(f"{_API}/health", timeout=15) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError):
                process.poll()
                if process.returncode is not None:
                    return None
        with urllib.request.urlopen(
            f"{_API}/v1/foundry/rules/{version_id}",
            timeout=30,
        ) as response:
            body = json.loads(response.read().decode("utf-8"))
        rule_id = body.get("rule_id") if isinstance(body, dict) else None
        if isinstance(rule_id, str):
            return rule_id
        return None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
