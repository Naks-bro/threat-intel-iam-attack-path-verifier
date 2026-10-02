"""PostgreSQL foundry slice. Skipped unless FYP_DATABASE_URL is set."""

import os

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from fyp_iam.engine1.foundry.models import (
    EvidenceRelationRow,
    PublicationRow,
    RawArtifactRow,
    ReviewDecisionRow,
    RuleVersionRow,
)
from fyp_iam.engine1.foundry.store import experimental_publication_count, persist_foundry

pytestmark = pytest.mark.postgres


def test_experimental_rule_is_stored_once(monkeypatch: pytest.MonkeyPatch) -> None:
    url = os.environ.get("FYP_DATABASE_URL", "").strip()
    if not url:
        pytest.skip("FYP_DATABASE_URL is not set")
    monkeypatch.delenv("FYP_DATABASE_URL", raising=False)
    first = persist_foundry(url)
    second = persist_foundry(url)
    assert isinstance(first["publication"], dict)
    assert first["publication"]["channel"] == "experimental"
    run = second["run"]
    assert isinstance(run, dict)
    assert run["unchanged_count"] == 3
    assert experimental_publication_count(url) == 1
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            relations = session.scalars(select(EvidenceRelationRow)).all()
            assert relations
            assert all(row.to_entity_id for row in relations)
            reviews = session.scalar(select(func.count()).select_from(ReviewDecisionRow))
            assert reviews == 0
            payload = session.scalar(select(RawArtifactRow.byte_count).limit(1))
            assert payload is not None and payload > 0
            linked = session.execute(
                select(PublicationRow.channel, RuleVersionRow.semantic_hash).join(
                    RuleVersionRow,
                    PublicationRow.rule_version_id == RuleVersionRow.version_id,
                )
            ).one()
            assert linked[0] == "experimental"
            assert str(linked[1]).startswith("sha256:")
    finally:
        engine.dispose()
