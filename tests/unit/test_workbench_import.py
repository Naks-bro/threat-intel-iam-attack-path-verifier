"""The pinned T1548 path can be prepared without PostgreSQL."""

import pytest
from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app
from fyp_iam.engine1.workbench.db import PostgresWorkbenchStore, database_status
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable
from fyp_iam.engine1.workbench.memory import MemoryWorkbenchStore
from fyp_iam.engine1.workbench.services import build_snapshot, import_snapshot


def test_t1548_snapshot_is_pending_and_deterministic() -> None:
    snapshot = build_snapshot("attack-t1548-assume-chain")
    assert snapshot.lifecycle == "needs_review"
    assert snapshot.validation_status == "passed"
    assert snapshot.rule_id == "rule_t1548_assume_chain"
    assert snapshot.rule_version == 1
    assert snapshot.aws_iam_relevant is True
    assert "No model wrote this rule." in snapshot.explanation
    store = MemoryWorkbenchStore()
    assert import_snapshot(store, snapshot) == "created"
    assert import_snapshot(store, snapshot) == "unchanged"
    stored = store.get_import(snapshot.pin_id)
    assert stored is not None
    assert stored.model_dump() == snapshot.model_dump()


def test_unmapped_pin_stays_unsupported() -> None:
    snapshot = build_snapshot("attack-t9999-unmapped")
    assert snapshot.lifecycle == "unsupported"
    assert snapshot.rule_id is None
    assert snapshot.rule_json is None
    assert snapshot.validation_status == "unsupported"


def test_sqlite_is_not_a_workbench_store() -> None:
    status, detail = database_status("sqlite:///workbench.db")
    assert status == "unavailable"
    assert detail == "sqlite_rejected"
    with pytest.raises(DatabaseUnavailable):
        PostgresWorkbenchStore("sqlite:///workbench.db")


def test_missing_database_does_not_pretend_to_save() -> None:
    status, detail = database_status(None)
    assert status == "unavailable"
    assert detail == "not_configured"
    client = TestClient(create_app(database_url=None))
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["database"] == "unavailable"
    assert health.json()["database_detail"] == "not_configured"
    preview = client.get("/v1/workbench/fixtures/attack-t1548-assume-chain")
    assert preview.status_code == 200
    body = preview.json()
    assert body["persisted"] is False
    assert body["storage"] == "not_written"
    assert body["lifecycle"] == "needs_review"
    assert body["rule_id"] == "rule_t1548_assume_chain"
    saved = client.post("/v1/workbench/imports/attack-t1548-assume-chain")
    assert saved.status_code == 503
    assert saved.json()["detail"] == "database_unavailable"
