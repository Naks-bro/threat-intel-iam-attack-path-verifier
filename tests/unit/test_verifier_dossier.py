"""Dossier metadata is typed, version bound, and contains no source text."""

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from fyp_iam.api.app import create_app
from fyp_iam.api.schemas import FoundryRuleResponse
from fyp_iam.engine1.foundry.adapters import assemble_snapshot
from fyp_iam.engine1.foundry.models import RuleVersionRow, VerifierPacketRow
from fyp_iam.engine1.foundry.preview import preview_rule
from fyp_iam.engine1.foundry.verifier_pipeline import (
    build_verifier_request,
    compile_verified_snapshot,
)
from fyp_iam.engine1.foundry.verifier_store import (
    read_latest_verifier_summary,
    write_verifier_packet,
)


def _summary():
    snapshot = assemble_snapshot()
    compiled = asyncio.run(compile_verified_snapshot(snapshot))
    request = build_verifier_request(snapshot, compiled)
    version = RuleVersionRow(
        version_id=request.candidate_version_id,
        semantic_hash=request.candidate_semantic_hash,
        rule_json=request.candidate_json,
    )
    writer = MagicMock()
    writer.get.side_effect = [version, None]
    write_verifier_packet(
        writer, request, compiled["ai_verification"], "pipeline_test", datetime.now(UTC)
    )
    params = writer.execute.call_args.args[0].compile(dialect=postgresql.dialect()).params
    reader = MagicMock()
    reader.scalar.return_value = VerifierPacketRow(**params)
    summary = read_latest_verifier_summary(reader, version)
    assert summary is not None
    return summary


def test_summary_rechecks_binding_and_excludes_source_text():
    summary = _summary()
    body = summary.model_dump(mode="json")
    assert summary.provider == "fake"
    assert len(summary.evidence) == 3
    assert "candidate_json" not in json.dumps(body)
    assert all("text" not in item for item in body["evidence"])


@pytest.mark.parametrize("field", ["rule_version_id", "rule_semantic_hash"])
def test_dossier_rejects_wrong_version_summary(field):
    summary = _summary().model_dump(mode="json")
    dossier = preview_rule(summary["rule_version_id"])
    assert dossier is not None
    summary[field] = "version_other" if field == "rule_version_id" else "sha256:" + "0" * 64
    dossier["verifier_record"] = summary
    with pytest.raises(ValidationError):
        FoundryRuleResponse.model_validate(dossier)


@pytest.mark.parametrize("present", [True, False])
def test_real_route_serializes_available_or_missing_summary(monkeypatch, present):
    summary = _summary()
    dossier = preview_rule(summary.rule_version_id)
    assert dossier is not None
    dossier["verifier_record"] = summary.model_dump(mode="json") if present else None
    monkeypatch.setattr("fyp_iam.api.app.read_rule", lambda _url, _id: dossier)
    with TestClient(
        create_app(database_url="postgresql+psycopg://test@127.0.0.1/fyp_iam")
    ) as client:
        response = client.get(f"/v1/foundry/rules/{summary.rule_version_id}")
    assert response.status_code == 200
    assert response.json()["verifier_record"] == dossier["verifier_record"]


def test_missing_history_is_not_reconstructed():
    session = MagicMock()
    session.scalar.return_value = None
    assert (
        read_latest_verifier_summary(session, RuleVersionRow(version_id="version_missing")) is None
    )


def test_generated_consumer_verifier_contract_matches_provider():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "scripts/quality_contract_types.py", "--verifier", "--check"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
