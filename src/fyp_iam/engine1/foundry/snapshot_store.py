"""Reconstruct only explicitly selected stored source versions; no latest fallback."""

import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from fyp_iam.engine1.foundry.compiler import (
    ClaimDraft,
    EntityDraft,
    RelationDraft,
    Snapshot,
    SourceDraft,
)
from fyp_iam.engine1.foundry.models import (
    EvidenceClaimRow,
    EvidenceRelationRow,
    NormalizedEntityRow,
    RawArtifactRow,
    SourceRow,
    SourceVersionRow,
)

_FILES = {
    "mitre-attack": "mitre-enterprise-19.2-extract.json",
    "aws-service-reference": "aws-service-reference-extract.json",
    "stratus-red-team": "stratus-iam-redacted.json",
}


def checked_artifact_payload(row: RawArtifactRow, version_hash: str) -> bytes:
    raw = row.payload
    if (
        raw is None
        or len(raw) > 4096
        or row.byte_count != len(raw)
        or row.content_hash != version_hash
        or "sha256:" + hashlib.sha256(raw).hexdigest() != version_hash
    ):
        raise ValueError("Stored verifier evidence is invalid")
    return raw


def read_version_snapshot(session: Session, version_ids: dict[str, str]) -> Snapshot:
    """Rebuild current small public pins from their exact persisted versions."""
    if set(version_ids) != set(_FILES) or len(set(version_ids.values())) != len(_FILES):
        raise ValueError("Stored verifier evidence is invalid")
    sources = []
    key_by_version = {}
    hash_by_version = {}
    for key, version_id in sorted(version_ids.items()):
        version = session.get(SourceVersionRow, version_id)
        source = session.get(SourceRow, version.source_id) if version is not None else None
        if version is None or source is None or source.source_key != key or not source.enabled:
            raise ValueError("Stored verifier evidence is invalid")
        sources.append(
            SourceDraft(
                key,
                source.authority_tier,
                source.source_type,
                source.official_url,
                version.version_label,
                version.content_hash,
                True,
            )
        )
        key_by_version[version_id] = key
        hash_by_version[version_id] = version.content_hash
    artifacts = session.scalars(
        select(RawArtifactRow).where(RawArtifactRow.source_version_id.in_(version_ids.values()))
    ).all()
    payloads = {}
    artifact_by_id = {}
    for artifact in artifacts:
        key = key_by_version[artifact.source_version_id]
        if artifact.source_native_id != key or _FILES[key] in payloads:
            raise ValueError("Stored verifier evidence is invalid")
        payloads[_FILES[key]] = checked_artifact_payload(
            artifact, hash_by_version[artifact.source_version_id]
        )
        artifact_by_id[artifact.artifact_id] = artifact
    if len(payloads) != len(_FILES):
        raise ValueError("Stored verifier evidence is invalid")
    rows = session.scalars(
        select(NormalizedEntityRow).where(
            NormalizedEntityRow.source_version_id.in_(version_ids.values())
        )
    ).all()
    native_by_id = {row.entity_id: row.native_id for row in rows}
    if len(set(native_by_id.values())) != len(rows):
        raise ValueError("Stored verifier evidence is invalid")
    entities = []
    for row in rows:
        selected_artifact = artifact_by_id.get(row.artifact_id)
        attributes = json.loads(row.attributes_json)
        if (
            selected_artifact is None
            or selected_artifact.source_version_id != row.source_version_id
            or not isinstance(attributes, dict)
        ):
            raise ValueError("Stored verifier evidence is invalid")
        entities.append(
            EntityDraft(
                row.entity_type,
                row.native_id,
                row.name,
                key_by_version[row.source_version_id],
                attributes,
            )
        )
    relations = tuple(
        RelationDraft(
            native_by_id[row.from_entity_id],
            native_by_id[row.to_entity_id],
            row.relation_type,
            row.mapping_method,
            row.mapping_confidence,
            row.review_state,
            row.rationale,
        )
        for row in session.scalars(
            select(EvidenceRelationRow).where(
                EvidenceRelationRow.from_entity_id.in_(native_by_id),
                EvidenceRelationRow.to_entity_id.in_(native_by_id),
            )
        ).all()
    )
    claims = tuple(
        ClaimDraft(
            native_by_id[row.subject_entity_id],
            row.predicate,
            row.object_value,
            native_by_id[row.object_entity_id] if row.object_entity_id else "",
            key_by_version[artifact_by_id[row.artifact_id].source_version_id],
            row.source_location,
            row.extraction_method,
            row.confidence,
        )
        for row in session.scalars(
            select(EvidenceClaimRow).where(EvidenceClaimRow.artifact_id.in_(artifact_by_id))
        ).all()
    )
    return Snapshot(tuple(sources), (), tuple(entities), claims, relations, payloads)
