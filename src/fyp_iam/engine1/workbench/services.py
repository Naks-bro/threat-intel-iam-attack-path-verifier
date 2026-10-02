"""Build a deterministic candidate from a pinned technique. This module does not connect."""

import json
from pathlib import Path

from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.intake import (
    explain_proposal,
    load_artifact,
    normalize_technique,
    propose_rule,
    validate_candidate,
)
from fyp_iam.engine1.workbench.domain import WorkbenchSnapshot, WorkbenchView
from fyp_iam.engine1.workbench.repositories import WorkbenchRepository

_PARSER = "allowlisted-technique-map-0.1"
_ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"


def build_snapshot(pin_id: str) -> WorkbenchSnapshot:
    """Normalize one pin. An unmapped technique stays unsupported."""

    artifact, digest = load_artifact(pin_id)
    raw = (_ARTIFACTS / f"{pin_id}.json").read_bytes()
    record = normalize_technique(artifact, digest)
    try:
        rule = propose_rule(record)
        validate_candidate(rule, record)
    except IntakeError as exc:
        if exc.code != "unsupported_technique":
            raise
        return WorkbenchSnapshot(
            pin_id=pin_id,
            source_name=artifact.source_name,
            source_version=artifact.source_version,
            official_reference=artifact.official_reference,
            retrieved_at=artifact.retrieved_at,
            content_hash=digest,
            byte_count=len(raw),
            record_id=record.record_id,
            technique_id=artifact.external_id,
            technique_name=artifact.technique_name,
            parser_version=_PARSER,
            aws_iam_relevant=False,
            lifecycle="unsupported",
            validation_status="unsupported",
            explanation="No curated IAM mapping is available.",
            limitations=["No curated IAM mapping is available."],
        )
    return WorkbenchSnapshot(
        pin_id=pin_id,
        source_name=artifact.source_name,
        source_version=artifact.source_version,
        official_reference=artifact.official_reference,
        retrieved_at=artifact.retrieved_at,
        content_hash=digest,
        byte_count=len(raw),
        record_id=record.record_id,
        technique_id=artifact.external_id,
        technique_name=artifact.technique_name,
        parser_version=_PARSER,
        aws_iam_relevant=True,
        lifecycle="needs_review",
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        rule_json=rule.model_dump_json(),
        validation_status="passed",
        explanation=explain_proposal(record, rule),
        limitations=list(rule.limitations),
    )


def import_snapshot(repository: WorkbenchRepository, snapshot: WorkbenchSnapshot) -> str:
    return repository.save_import(snapshot)


def view_from_snapshot(snapshot: WorkbenchSnapshot, *, persisted: bool) -> WorkbenchView:
    return WorkbenchView(
        schema_version="0.1",
        pin_id=snapshot.pin_id,
        technique_id=snapshot.technique_id,
        technique_name=snapshot.technique_name,
        official_reference=snapshot.official_reference,
        artifact_sha256=snapshot.content_hash,
        normalized_record_id=snapshot.record_id,
        lifecycle=snapshot.lifecycle,
        rule_id=snapshot.rule_id,
        rule_version=snapshot.rule_version,
        validation_status=snapshot.validation_status,
        explanation=snapshot.explanation,
        limitations=snapshot.limitations,
        persisted=persisted,
        storage="postgres" if persisted else "not_written",
    )


def rule_limitations(rule_json: str | None, fallback: str) -> list[str]:
    if not rule_json:
        return [fallback]
    loaded = json.loads(rule_json)
    values = loaded.get("limitations") if isinstance(loaded, dict) else None
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        return [fallback]
    return list(values)
