"""Connection selection stays provider-neutral and does not leak URLs."""

import logging
import os
from pathlib import Path

import pytest

from fyp_iam.engine1.foundry.models import SourceVersionRow
from fyp_iam.persistence.dotenv import load_local_env
from fyp_iam.persistence.redact import RedactingFilter, redact
from fyp_iam.persistence.status import database_status
from fyp_iam.persistence.urls import application_database_url, prepare_url

_DIRECT = "postgresql+psycopg://user:secret@db.example.supabase.co:5432/postgres"
_SESSION = "postgresql+psycopg://user.example:secret@aws-0-region.pooler.supabase.com:5432/postgres"


def test_foundry_tables_use_the_foundry_schema() -> None:
    table = SourceVersionRow.__table__
    assert table.schema == "foundry"
    targets = {key.column.table.schema for key in table.foreign_keys}
    assert targets == {"foundry"}


def test_direct_endpoint_is_used_when_ipv6_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FYP_DATABASE_DIRECT_URL", _DIRECT)
    monkeypatch.setenv("FYP_DATABASE_SESSION_URL", _SESSION)
    monkeypatch.setattr("fyp_iam.persistence.urls._ipv6_reaches", lambda _url: True)
    assert application_database_url() == _DIRECT


def test_session_pooler_is_used_when_ipv6_does_not_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FYP_DATABASE_DIRECT_URL", _DIRECT)
    monkeypatch.setenv("FYP_DATABASE_SESSION_URL", _SESSION)
    monkeypatch.setattr("fyp_iam.persistence.urls._ipv6_reaches", lambda _url: False)
    assert application_database_url() == _SESSION


def test_managed_hosts_require_ssl_and_reject_transaction_mode() -> None:
    prepared, error = prepare_url(_DIRECT)
    assert error is None
    assert "sslmode=require" in prepared
    _url, rejected = prepare_url(_SESSION.replace(":5432/", ":6543/"))
    assert rejected == "transaction_pooler_rejected"
    _url, pooled = prepare_url(_SESSION + "?pool_mode=transaction")
    assert pooled == "transaction_pooler_rejected"


def test_verify_full_requires_the_configured_certificate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FYP_DATABASE_SSLROOTCERT", str(tmp_path / "missing.crt"))
    _url, missing = prepare_url(_DIRECT)
    assert missing == "ssl_certificate_missing"
    certificate = tmp_path / "ca.crt"
    certificate.write_text("placeholder-ca\n", encoding="utf-8")
    monkeypatch.setenv("FYP_DATABASE_SSLROOTCERT", str(certificate))
    prepared, ready = prepare_url(_DIRECT)
    assert ready is None
    assert "sslmode=verify-full" in prepared


def test_health_states_do_not_include_a_url() -> None:
    assert database_status(None) == ("not_configured", "not_configured")
    assert database_status("sqlite:///local.db") == ("unavailable", "sqlite_rejected")
    state, detail = database_status(_DIRECT, probe=False)
    assert (state, detail) == ("connecting", "not_probed")
    assert "secret" not in f"{state} {detail}"
    assert "supabase.co" not in detail


def test_a_busy_probe_reports_connecting() -> None:
    from fyp_iam.persistence import status as status_module

    assert status_module._PROBE.acquire(blocking=False)
    try:
        state, detail = database_status("postgresql+psycopg://user:secret@127.0.0.1:1/db")
        assert (state, detail) == ("connecting", "in_progress")
        assert "secret" not in f"{state} {detail}"
    finally:
        status_module._PROBE.release()


def test_redaction_removes_urls_from_log_records() -> None:
    message = redact(f"failed {_DIRECT}")
    assert "secret" not in message
    assert "supabase.co" not in message
    record = logging.LogRecord(
        name="sqlalchemy.engine",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="connect %s",
        args=(_DIRECT,),
        exc_info=(RuntimeError, RuntimeError(_DIRECT), None),
    )
    assert RedactingFilter().filter(record) is True
    rendered = record.getMessage()
    assert "secret" not in rendered
    assert record.exc_text is not None
    assert "secret" not in record.exc_text
    assert "supabase.co" not in record.exc_text


def test_dotenv_fills_only_missing_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        'FYP_DATABASE_URL="postgresql+psycopg://user:secret@localhost/db"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FYP_DATABASE_URL", raising=False)
    load_local_env()
    assert os.environ["FYP_DATABASE_URL"].endswith("/db")
    monkeypatch.setenv("FYP_DATABASE_URL", "already")
    load_local_env()
    assert os.environ["FYP_DATABASE_URL"] == "already"


def test_cli_check_without_a_database_is_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    from fyp_iam.persistence.cli import main

    monkeypatch.delenv("FYP_DATABASE_URL", raising=False)
    monkeypatch.delenv("FYP_DATABASE_DIRECT_URL", raising=False)
    monkeypatch.delenv("FYP_DATABASE_SESSION_URL", raising=False)
    monkeypatch.setattr("fyp_iam.persistence.urls.load_local_env", lambda: None)
    assert main(["check"]) == 3
