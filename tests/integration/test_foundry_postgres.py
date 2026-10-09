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


def test_bound_verifier_run_retains_request_and_response() -> None:
    from fyp_iam.engine1.foundry.models import VerifierPacketRow
    from fyp_iam.engine1.foundry.verifier_store import read_latest_verifier_packet

    url = os.environ["FYP_DATABASE_URL"]
    first = persist_foundry(url, verify_inputs=True)
    second = persist_foundry(url, verify_inputs=True)
    assert first["candidate"] == second["candidate"]
    assert first["ai_verification"] == second["ai_verification"]
    assert second["run"]["unchanged_count"] == 3
    engine = create_engine(url)
    try:
        with Session(engine) as session:
            version = session.get(RuleVersionRow, first["candidate"]["version_id"])
            assert version is not None
            restored = read_latest_verifier_packet(session, version)
            assert restored is not None
            assert restored["response"] == second["ai_verification"]
            assert len(restored["request"]["evidence"]) == 3
            assert session.scalar(select(func.count()).select_from(VerifierPacketRow)) >= 2
    finally:
        engine.dispose()
    from fastapi.testclient import TestClient

    from fyp_iam.api.app import create_app

    with TestClient(create_app(database_url=url)) as client:
        response = client.get(f"/v1/foundry/rules/{first['candidate']['version_id']}")
    assert response.status_code == 200
    summary = response.json()["verifier_record"]
    assert summary["request_hash"] == first["ai_verification"]["request_hash"]
    assert summary["response_hash"] == first["ai_verification"]["response_hash"]
    assert len(summary["evidence"]) == 3
    assert all("text" not in item for item in summary["evidence"])


def test_normal_api_run_retains_binding_and_rolls_back_corrupt_inputs() -> None:
    from fastapi.testclient import TestClient

    from fyp_iam.api.app import create_app
    from fyp_iam.engine1.foundry.models import VerifierPacketRow

    url = os.environ["FYP_DATABASE_URL"]
    engine = create_engine(url)
    original = None
    artifact_id = None
    try:
        with TestClient(create_app(database_url=url)) as client:
            response = client.post("/v1/foundry/runs")
            assert response.status_code == 200
            version_id = response.json()["candidates"][0]["version_id"]
            dossier = client.get(f"/v1/foundry/rules/{version_id}")
            assert dossier.status_code == 200
            record = dossier.json()["verifier_record"]
            assert record is not None and record["provider"] == "fake"
            assert len(record["evidence"]) == 3
            with Session(engine) as session, session.begin():
                packet_count = session.scalar(select(func.count()).select_from(VerifierPacketRow))
                run_count = session.scalar(select(func.count()).select_from(PipelineRunRow))
                artifact = session.scalar(select(RawArtifactRow).limit(1))
                assert artifact is not None
                artifact_id, original = artifact.artifact_id, artifact.payload
                artifact.payload = b"corrupt verifier source"
            failed = client.post("/v1/foundry/runs")
            assert failed.status_code == 503
            assert failed.json()["detail"] == "database_unavailable"
            assert "corrupt verifier source" not in failed.text
            with Session(engine) as session:
                assert (
                    session.scalar(select(func.count()).select_from(VerifierPacketRow))
                    == packet_count
                )
                assert session.scalar(select(func.count()).select_from(PipelineRunRow)) == run_count
            retained = client.get(f"/v1/foundry/rules/{version_id}")
            assert retained.status_code == 200
            assert retained.json()["verifier_record"] == record
    finally:
        if artifact_id is not None:
            with Session(engine) as session, session.begin():
                artifact = session.get(RawArtifactRow, artifact_id)
                assert artifact is not None
                artifact.payload = original
        engine.dispose()


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
