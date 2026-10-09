"""Transactional exact verifier records; no commits, approval or provider calls."""

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from fyp_iam.contracts.models import ApprovedRule
from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.foundry.models import RuleVersionRow, VerifierPacketRow
from fyp_iam.engine1.foundry.verifier_models import (
    VerifierRecordSummary,
    VerifierRequest,
    checked_verification,
)


def _bound(
    request: VerifierRequest, response: dict[str, object], version: RuleVersionRow | None
) -> dict[str, object]:
    if (
        version is None
        or request.candidate_version_id != version.version_id
        or request.candidate_semantic_hash != version.semantic_hash
        or request.candidate_json
        != ApprovedRule.model_validate_json(version.rule_json).model_dump_json()
    ):
        raise ValueError("invalid rule binding")
    raw = {key: value for key, value in response.items() if key != "response_hash"}
    checked = checked_verification(
        raw,
        version_id=version.version_id,
        evidence_hash=request.evidence_snapshot_hash,
        evidence_ids=[item.evidence_id for item in request.evidence],
        request_hash=request.request_hash,
    )
    if checked.get("request_hash") != request.request_hash or checked.get(
        "response_hash"
    ) != response.get("response_hash"):
        raise ValueError("invalid response binding")
    return checked


def decode_verifier_packet(row: VerifierPacketRow, version: RuleVersionRow) -> dict[str, object]:
    try:
        if len(row.request_json.encode()) > 65536 or len(row.response_json.encode()) > 262144:
            raise ValueError("record too large")
        request = VerifierRequest.model_validate_json(row.request_json)
        response = json.loads(row.response_json)
        if not isinstance(response, dict):
            raise ValueError("invalid response")
        checked = _bound(request, response, version)
        if (
            row.rule_version_id != version.version_id
            or row.request_hash != request.request_hash
            or row.response_hash != checked["response_hash"]
            or row.packet_id
            != stable_id("vpacket", row.pipeline_run_id, row.request_hash, row.response_hash)
        ):
            raise ValueError("invalid packet metadata")
        return {"request": request.model_dump(mode="json"), "response": checked}
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Stored verifier packet is invalid") from None


def write_verifier_packet(
    session: Session,
    request: VerifierRequest,
    response: dict[str, object],
    pipeline_run_id: str,
    observed_at: datetime,
) -> str:
    try:
        request = VerifierRequest.model_validate_json(request.model_dump_json())
        version = session.get(RuleVersionRow, request.candidate_version_id)
        checked = _bound(request, response, version)
        response_json = json.dumps(checked, sort_keys=True)
        if len(response_json.encode()) > 262144:
            raise ValueError("record too large")
        packet_id = stable_id(
            "vpacket", pipeline_run_id, request.request_hash, str(checked["response_hash"])
        )
        existing = session.get(VerifierPacketRow, packet_id)
        if existing is not None:
            assert version is not None
            decoded = decode_verifier_packet(existing, version)
            if decoded != {"request": request.model_dump(mode="json"), "response": checked}:
                raise ValueError("packet conflict")
            return packet_id
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Verifier packet binding is invalid") from None
    session.execute(
        insert(VerifierPacketRow)
        .values(
            packet_id=packet_id,
            pipeline_run_id=pipeline_run_id,
            rule_version_id=request.candidate_version_id,
            request_hash=request.request_hash,
            response_hash=checked["response_hash"],
            request_json=request.model_dump_json(),
            response_json=response_json,
            created_at=observed_at,
        )
        .on_conflict_do_nothing(index_elements=["packet_id"])
    )
    return packet_id


def read_latest_verifier_packet(
    session: Session, version: RuleVersionRow
) -> dict[str, object] | None:
    row = session.scalar(
        select(VerifierPacketRow)
        .where(VerifierPacketRow.rule_version_id == version.version_id)
        .order_by(VerifierPacketRow.created_at.desc(), VerifierPacketRow.packet_id.desc())
        .limit(1)
    )
    return None if row is None else decode_verifier_packet(row, version)


def read_latest_verifier_summary(
    session: Session, version: RuleVersionRow
) -> VerifierRecordSummary | None:
    row = session.scalar(
        select(VerifierPacketRow)
        .where(VerifierPacketRow.rule_version_id == version.version_id)
        .order_by(VerifierPacketRow.created_at.desc(), VerifierPacketRow.packet_id.desc())
        .limit(1)
    )
    if row is None:
        return None
    decoded = decode_verifier_packet(row, version)
    request = VerifierRequest.model_validate(decoded["request"])
    response = decoded["response"]
    assert isinstance(response, dict)
    return VerifierRecordSummary.model_validate(
        {
            "packet_id": row.packet_id,
            "pipeline_run_id": row.pipeline_run_id,
            "recorded_at": row.created_at,
            "rule_version_id": version.version_id,
            "rule_semantic_hash": version.semantic_hash,
            "evidence_snapshot_hash": request.evidence_snapshot_hash,
            "request_hash": row.request_hash,
            "response_hash": row.response_hash,
            "ontology_version": request.ontology_version,
            **{
                key: response[key]
                for key in (
                    "provider",
                    "model",
                    "prompt_version",
                    "verdict",
                    "findings",
                    "citations",
                )
            },
            "evidence": [
                {key: value for key, value in item.model_dump().items() if key != "text"}
                for item in request.evidence
            ],
        }
    )
