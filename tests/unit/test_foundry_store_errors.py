"""Database failures must not disclose connection parameters in tracebacks."""

import traceback

import pytest

import fyp_iam.engine1.foundry.store as store
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable


def test_unbound_persistence_cannot_be_selected(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Unbound run must be rejected before opening a database")

    monkeypatch.setattr(store, "create_engine", forbidden)
    with pytest.raises(DatabaseUnavailable, match="Exact verifier inputs are required"):
        store.persist_foundry("private-url", verify_inputs=False)


def test_foundry_storage_exception_suppresses_sensitive_driver_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeEngine:
        def dispose(self) -> None:
            pass

    def failing_session(_engine: object) -> None:
        raise RuntimeError("driver password=fixture_secret")

    monkeypatch.setattr(store, "create_engine", lambda *_args, **_kwargs: FakeEngine())
    monkeypatch.setattr(store, "Session", failing_session)
    connection = "postgresql+psycopg://example:fixture_secret@localhost/db"
    with pytest.raises(DatabaseUnavailable) as caught:
        store.persist_foundry(connection)
    rendered = "".join(traceback.format_exception(caught.value))
    assert "fixture_secret" not in rendered
    assert "PostgreSQL did not commit the foundry run" in rendered
