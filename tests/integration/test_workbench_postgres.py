"""PostgreSQL persistence. Skipped unless FYP_DATABASE_URL points at a migrated database."""

import os

import pytest
from sqlalchemy import create_engine, func, select

from fyp_iam.engine1.workbench.db import (
    AuditEventRow,
    EvidenceRelationRow,
    PostgresWorkbenchStore,
    PublishedRuleRow,
    ReviewDecisionRow,
)
from fyp_iam.engine1.workbench.services import build_snapshot

pytestmark = pytest.mark.postgres


@pytest.fixture
def database_url() -> str:
    url = os.environ.get("FYP_DATABASE_URL", "").strip()
    if not url:
        pytest.skip("PostgreSQL is not configured")
    return url


def test_import_survives_a_new_connection(database_url: str) -> None:
    snapshot = build_snapshot("attack-t1548-assume-chain")
    writer = PostgresWorkbenchStore(database_url)
    try:
        assert writer.save_import(snapshot) == "created"
        assert writer.save_import(snapshot) == "unchanged"
    finally:
        writer.dispose()
    reader = PostgresWorkbenchStore(database_url)
    try:
        stored = reader.get_import("attack-t1548-assume-chain")
    finally:
        reader.dispose()
    assert stored is not None
    assert stored.lifecycle == "needs_review"
    assert stored.rule_id == "rule_t1548_assume_chain"
    assert stored.validation_status == "passed"
    assert stored.content_hash == snapshot.content_hash
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            reviews = connection.scalar(select(func.count()).select_from(ReviewDecisionRow))
            published = connection.scalar(select(func.count()).select_from(PublishedRuleRow))
            relations = connection.scalar(select(func.count()).select_from(EvidenceRelationRow))
            audits = connection.scalar(select(func.count()).select_from(AuditEventRow))
    finally:
        engine.dispose()
    assert reviews == 0
    assert published == 0
    assert relations == 0
    assert audits == 1
