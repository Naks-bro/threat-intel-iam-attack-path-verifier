"""Exact request/result retention is distinct from publication or human approval."""

import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects import postgresql

from fyp_iam.engine1.foundry.adapters import assemble_snapshot
from fyp_iam.engine1.foundry.models import RuleVersionRow, VerifierPacketRow
from fyp_iam.engine1.foundry.snapshot_store import checked_artifact_payload
from fyp_iam.engine1.foundry.verifier_pipeline import (
    build_verifier_request,
    compile_verified_snapshot,
)
from fyp_iam.engine1.foundry.verifier_store import decode_verifier_packet, write_verifier_packet


def _inputs():
    snapshot = assemble_snapshot()
    compiled = asyncio.run(compile_verified_snapshot(snapshot))
    request = build_verifier_request(snapshot, compiled)
    version = RuleVersionRow(
        version_id=request.candidate_version_id,
        semantic_hash=request.candidate_semantic_hash,
        rule_json=request.candidate_json,
    )
    return request, compiled["ai_verification"], version


def _stored():
    request, response, version = _inputs()
    session = MagicMock()
    session.get.side_effect = [version, None]
    write_verifier_packet(session, request, response, "pipeline_test", datetime.now(UTC))
    statement = session.execute.call_args.args[0]
    params = statement.compile(dialect=postgresql.dialect()).params
    return VerifierPacketRow(**params), version, session


def test_write_retains_exact_inputs_and_result_without_commit():
    row, version, session = _stored()
    restored = decode_verifier_packet(row, version)
    assert restored["request"]["candidate_json"] == version.rule_json
    assert len(restored["request"]["evidence"]) == 3
    assert restored["response"]["request_hash"] == row.request_hash
    assert restored["response"]["response_hash"] == row.response_hash
    session.commit.assert_not_called()
    sql = str(session.execute.call_args.args[0].compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT" in sql


@pytest.mark.parametrize("field", ["request_hash", "response_hash", "rule_version_id", "packet_id"])
def test_corrupt_packet_metadata_is_rejected(field):
    row, version, _ = _stored()
    setattr(row, field, "tampered")
    with pytest.raises(ValueError, match="Stored verifier packet is invalid"):
        decode_verifier_packet(row, version)


def test_corrupt_request_content_never_returns_evidence_in_error():
    row, version, _ = _stored()
    body = json.loads(row.request_json)
    body["evidence"][0]["text"] = "private injected payload"
    row.request_json = json.dumps(body)
    with pytest.raises(ValueError, match="Stored verifier packet is invalid") as caught:
        decode_verifier_packet(row, version)
    assert "private injected payload" not in str(caught.value)


def test_wrong_rule_or_unbound_response_is_rejected_before_insert():
    request, response, version = _inputs()
    for invalid in ({**response, "request_hash": "sha256:" + "0" * 64}, {"verdict": "pass"}):
        session = MagicMock()
        session.get.return_value = version
        with pytest.raises(ValueError, match="Verifier packet binding is invalid"):
            write_verifier_packet(session, request, invalid, "pipeline_test", datetime.now(UTC))
        session.execute.assert_not_called()


@pytest.mark.parametrize("corrupt", ["bytes", "length", "hash", "missing"])
def test_artifact_metadata_cannot_hide_changed_or_missing_bytes(corrupt):
    import hashlib

    from fyp_iam.engine1.foundry.models import RawArtifactRow

    payload = b'{"public": "evidence"}'
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    row = RawArtifactRow(payload=payload, byte_count=len(payload), content_hash=digest)
    if corrupt == "bytes":
        row.payload = b"other"
    elif corrupt == "length":
        row.byte_count = 0
    elif corrupt == "hash":
        row.content_hash = "sha256:" + "0" * 64
    else:
        row.payload = None
    with pytest.raises(ValueError, match="Stored verifier evidence is invalid"):
        checked_artifact_payload(row, digest)


def test_packet_migration_is_frozen_additive_and_archival():
    import importlib.util
    from io import StringIO
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = (
        Path(__file__).resolve().parents[2] / "alembic/versions/20261003_0006_verifier_packets.py"
    )
    spec = importlib.util.spec_from_file_location("packet_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": output}
    )
    with Operations.context(context):
        migration.upgrade()
    sql = output.getvalue()
    assert "CREATE TABLE IF NOT EXISTS foundry.verifier_packets" in sql
    assert "REVOKE ALL" in sql
    assert "DROP TABLE" not in sql and "UPDATE " not in sql
    with pytest.raises(RuntimeError, match="archival"):
        migration.downgrade()
