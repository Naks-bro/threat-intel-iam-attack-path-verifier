"""PostgreSQL foundry slice. Skipped unless FYP_DATABASE_URL is set."""

import os

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from fyp_iam.engine1.foundry.models import (
    EvidenceRelationRow,
    IngestionRunRow,
    PipelineRunRow,
    PublicationRow,
    RawArtifactRow,
    ReviewDecisionRow,
    RuleVersionRow,
    SourceRow,
)
from fyp_iam.engine1.foundry.store import (
    experimental_publication_count,
    persist_foundry,
    read_registry,
    read_rule,
)

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
    assert run["status"] == "succeeded"
    assert experimental_publication_count(url) == 1
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            relations = session.scalars(select(EvidenceRelationRow)).all()
            assert relations
            assert all(row.to_entity_id for row in relations)
            reviews = session.scalar(select(func.count()).select_from(ReviewDecisionRow))
            assert reviews == 0
            latest = max(
                session.scalars(select(PipelineRunRow)).all(),
                key=lambda item: (item.started_at, item.run_id),
            )
            attempts = session.scalars(
                select(IngestionRunRow).where(IngestionRunRow.pipeline_run_id == latest.run_id)
            ).all()
            assert len(attempts) == 3
            assert all(attempt.status == "succeeded" for attempt in attempts)
            catalog = session.scalar(
                select(SourceRow).where(SourceRow.source_key == "aws-threat-technique-catalog")
            )
            assert catalog is not None and not catalog.enabled
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
            public_sources = session.scalar(text("SELECT to_regclass('public.sources')"))
            foundry_sources = session.scalar(text("SELECT to_regclass('foundry.sources')"))
            assert public_sources is None
            assert foundry_sources is not None
    finally:
        engine.dispose()
    registry = read_registry(url)
    assert registry["run"]["status"] == "succeeded"
    version_id = registry["candidates"][0]["version_id"]
    dossier = read_rule(url, version_id)
    assert dossier is not None
    assert len(dossier["scenarios"]) == 6
    assert any(item["validator_name"] == "ontology" for item in dossier["validations"])


def test_api_roles_cannot_read_foundry_tables() -> None:
    url = os.environ.get("FYP_DATABASE_URL", "").strip()
    if not url:
        pytest.skip("FYP_DATABASE_URL is not set")
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    DO $$
                    BEGIN
                        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
                            CREATE ROLE anon NOLOGIN;
                        END IF;
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'
                        ) THEN
                            CREATE ROLE authenticated NOLOGIN;
                        END IF;
                    END $$;
                    """
                )
            )
            connection.execute(text("REVOKE ALL ON SCHEMA foundry FROM anon, authenticated"))
            connection.execute(
                text("REVOKE ALL ON ALL TABLES IN SCHEMA foundry FROM anon, authenticated")
            )
        for role in ("anon", "authenticated"):
            with engine.connect() as connection:
                connection.execute(text(f"SET ROLE {role}"))
                with pytest.raises(DBAPIError) as caught:
                    connection.execute(text("SELECT source_id FROM foundry.sources"))
                assert "permission denied" in str(caught.value).lower()
                connection.rollback()
    finally:
        engine.dispose()
