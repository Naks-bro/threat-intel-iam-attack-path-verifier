"""PostgreSQL persistence for one foundry slice. SQLite is rejected."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.foundry.models import (
    AIVerificationRow,
    AttackPrimitiveRow,
    AuditEventRow,
    CandidateEntityRow,
    CandidatePrimitiveRow,
    EvidenceClaimRow,
    EvidenceRelationClaimRow,
    EvidenceRelationRow,
    IngestionRunRow,
    NormalizedEntityRow,
    PipelineRunRow,
    PrimitiveRelationRow,
    PublicationRow,
    RawArtifactRow,
    RuleCandidateRow,
    RuleVersionRow,
    SourceRow,
    SourceVersionRow,
    ValidationRunRow,
)
from fyp_iam.engine1.foundry.pins import load_pins
from fyp_iam.engine1.foundry.pipeline import PARSER, build_foundry
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable

_NOW = datetime(2026, 10, 3, tzinfo=UTC)


def persist_foundry(url: str) -> dict[str, object]:
    if not url or url.startswith("sqlite"):
        raise DatabaseUnavailable("PostgreSQL is required for foundry persistence")
    overview = build_foundry(persisted=True, storage="postgres")
    pins = load_pins()
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with Session(engine) as session, session.begin():
            version_ids = {
                _text(item["source_key"]): stable_id(
                    "sver",
                    _text(item["source_key"]),
                    _text(item["content_hash"]),
                )
                for item in _object_list(overview["sources"])
            }
            already = all(
                session.get(SourceVersionRow, version_id) is not None
                for version_id in version_ids.values()
            )
            _ensure_sources(session, overview)
            run = _object(overview["run"])
            if already:
                run["created_count"] = 0
                run["unchanged_count"] = 3
            pipeline_id = stable_id("pipeline", str(run["content_hash"]), uuid4().hex)
            session.add(
                PipelineRunRow(
                    run_id=pipeline_id,
                    status="succeeded",
                    attempt=1,
                    trigger="manual",
                    parent_run_id=None,
                    started_at=_NOW,
                    finished_at=_NOW,
                    fetched_count=_int(run["fetched_count"]),
                    created_count=_int(run["created_count"]),
                    updated_count=0,
                    unchanged_count=_int(run["unchanged_count"]),
                    rejected_count=_int(run["rejected_count"]),
                    error_json="[]",
                    content_hash=_text(run["content_hash"]),
                )
            )
            session.flush()
            _ingest(session, pipeline_id, version_ids, already)
            if not already:
                _write_graph(session, pipeline_id, version_ids, overview, pins.payloads)
            session.add(
                AuditEventRow(
                    event_id=stable_id("audit", pipeline_id, "pipeline_completed"),
                    actor="foundry-worker",
                    action="pipeline_completed",
                    object_type="pipeline_run",
                    object_id=pipeline_id,
                    correlation_id=pipeline_id,
                    before_hash=None,
                    after_hash=_text(run["content_hash"]),
                    details_json=json.dumps({"unchanged": already}),
                    recorded_at=_NOW,
                )
            )
        overview["run"] = run
        return overview
    except DatabaseUnavailable:
        raise
    except Exception as exc:
        raise DatabaseUnavailable("PostgreSQL did not commit the foundry run") from exc
    finally:
        engine.dispose()


def experimental_publication_count(url: str) -> int:
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with Session(engine) as session:
            rows = session.scalars(
                select(PublicationRow).where(PublicationRow.channel == "experimental")
            ).all()
            return len(rows)
    finally:
        engine.dispose()


def _ensure_sources(session: Session, overview: dict[str, object]) -> dict[str, str]:
    version_ids: dict[str, str] = {}
    for item in _object_list(overview["sources"]):
        key = _text(item["source_key"])
        source_id = stable_id("source", key)
        session.execute(
            insert(SourceRow)
            .values(
                source_id=source_id,
                source_key=key,
                authority_tier=_int(item["authority_tier"]),
                source_type=_text(item["source_type"]),
                official_url=_text(item["official_url"]),
                enabled=True,
                schedule_cron=None,
            )
            .on_conflict_do_nothing(index_elements=["source_key"])
        )
        version_id = stable_id("sver", key, _text(item["content_hash"]))
        session.execute(
            insert(SourceVersionRow)
            .values(
                version_id=version_id,
                source_id=source_id,
                version_label=_text(item["version_label"]),
                discovered_at=_NOW,
                effective_at=_NOW,
                content_hash=_text(item["content_hash"]),
            )
            .on_conflict_do_nothing(index_elements=["source_id", "content_hash"])
        )
        version_ids[key] = version_id
    session.flush()
    return version_ids


def _ingest(
    session: Session,
    pipeline_id: str,
    version_ids: dict[str, str],
    already: bool,
) -> None:
    for key, version_id in version_ids.items():
        source_id = stable_id("source", key)
        session.add(
            IngestionRunRow(
                ingestion_id=stable_id("ingest", pipeline_id, key),
                pipeline_run_id=pipeline_id,
                source_id=source_id,
                source_version_id=version_id,
                attempt=1,
                status="succeeded",
                started_at=_NOW,
                finished_at=_NOW,
                fetched_count=1,
                created_count=0 if already else 1,
                updated_count=0,
                unchanged_count=1 if already else 0,
                rejected_count=0,
                error_json="[]",
                retry_of=None,
                parser_version=PARSER,
            )
        )
    session.flush()


def _write_graph(
    session: Session,
    pipeline_id: str,
    version_ids: dict[str, str],
    overview: dict[str, object],
    payloads: dict[str, bytes],
) -> None:
    file_for = {
        "mitre-attack": "mitre-enterprise-19.2-extract.json",
        "aws-service-reference": "aws-service-reference-extract.json",
        "stratus-red-team": "stratus-iam-redacted.json",
    }
    artifact_ids: dict[str, str] = {}
    for key, filename in file_for.items():
        payload = payloads[filename]
        artifact_id = stable_id("artifact", key, hashlib_payload(payload))
        artifact_ids[key] = artifact_id
        session.add(
            RawArtifactRow(
                artifact_id=artifact_id,
                source_version_id=version_ids[key],
                ingestion_id=stable_id("ingest", pipeline_id, key),
                source_native_id=key,
                mime_type="application/json",
                content_hash="sha256:" + hashlib_payload(payload),
                byte_count=len(payload),
                payload=payload,
                storage_uri=None,
                retrieved_at=_NOW,
                parser_version=PARSER,
            )
        )
    session.flush()
    entities = _entities(version_ids, artifact_ids)
    for row in entities.values():
        session.add(row)
    session.flush()
    claim_ids = _claims(session, entities, artifact_ids)
    relation_ids = _relations(session, overview, entities, claim_ids)
    primitive_ids = _primitives(session, overview, relation_ids)
    _candidate(session, overview, entities, primitive_ids)


def hashlib_payload(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _entities(
    version_ids: dict[str, str],
    artifact_ids: dict[str, str],
) -> dict[str, NormalizedEntityRow]:
    pins = load_pins()
    rows: dict[str, NormalizedEntityRow] = {}
    for technique in pins.techniques.values():
        rows[technique.native_id] = _entity(
            "technique",
            technique.native_id,
            technique.name,
            version_ids["mitre-attack"],
            artifact_ids["mitre-attack"],
        )
    for action in pins.actions.values():
        rows[action.native_id] = _entity(
            "aws_action",
            action.native_id,
            action.native_id,
            version_ids["aws-service-reference"],
            artifact_ids["aws-service-reference"],
        )
        for resource in action.resources:
            native = f"aws:{resource}"
            rows[native] = _entity(
                "aws_resource",
                native,
                resource,
                version_ids["aws-service-reference"],
                artifact_ids["aws-service-reference"],
            )
    for behavior in pins.behaviors:
        rows[behavior.native_id] = _entity(
            "cloud_behavior",
            behavior.native_id,
            behavior.title,
            version_ids["stratus-red-team"],
            artifact_ids["stratus-red-team"],
        )
    return rows


def _entity(
    entity_type: str,
    native_id: str,
    name: str,
    version_id: str,
    artifact_id: str,
) -> NormalizedEntityRow:
    return NormalizedEntityRow(
        entity_id=stable_id("entity", entity_type, native_id, version_id),
        entity_type=entity_type,
        native_id=native_id,
        name=name[:200],
        source_version_id=version_id,
        artifact_id=artifact_id,
        attributes_json="{}",
    )


def _claims(
    session: Session,
    entities: dict[str, NormalizedEntityRow],
    artifact_ids: dict[str, str],
) -> dict[str, str]:
    pins = load_pins()
    claim_ids: dict[str, str] = {}
    for behavior in pins.behaviors:
        for action in behavior.actions:
            claim_id = stable_id("claim", behavior.native_id, action)
            session.add(
                EvidenceClaimRow(
                    claim_id=claim_id,
                    subject_entity_id=entities[behavior.native_id].entity_id,
                    predicate="requires_action",
                    object_value=action,
                    object_entity_id=entities[action].entity_id,
                    artifact_id=artifact_ids["stratus-red-team"],
                    source_location="techniques.actions",
                    extraction_method="redacted-field-extract-0.1",
                    confidence="0.40",
                    valid_from=None,
                    valid_to=None,
                )
            )
            claim_ids[f"{behavior.native_id}:{action}"] = claim_id
    session.flush()
    return claim_ids


def _relations(
    session: Session,
    overview: dict[str, object],
    entities: dict[str, NormalizedEntityRow],
    claim_ids: dict[str, str],
) -> dict[str, str]:
    relation_ids: dict[str, str] = {}
    pending_claims: list[tuple[str, str]] = []
    for item in _object_list(overview["relations"]):
        left = _text(item["from_native_id"])
        right = _text(item["to_native_id"])
        relation_id = stable_id("relation", left, right, _text(item["relation_type"]))
        session.add(
            EvidenceRelationRow(
                relation_id=relation_id,
                from_entity_id=entities[left].entity_id,
                to_entity_id=entities[right].entity_id,
                relation_type=_text(item["relation_type"]),
                mapping_method=_text(item["mapping_method"]),
                mapping_confidence=_text(item["mapping_confidence"]),
                review_state=_text(item["review_state"]),
                rationale=_text(item["rationale"]),
            )
        )
        relation_ids[f"{left}:{right}"] = relation_id
        claim_id = claim_ids.get(f"{left}:{right}")
        if claim_id is not None:
            pending_claims.append((relation_id, claim_id))
    session.flush()
    for relation_id, claim_id in pending_claims:
        session.add(EvidenceRelationClaimRow(relation_id=relation_id, claim_id=claim_id))
    session.flush()
    return relation_ids


def _primitives(
    session: Session,
    overview: dict[str, object],
    relation_ids: dict[str, str],
) -> dict[str, str]:
    primitive_ids: dict[str, str] = {}
    pending_links: list[tuple[str, str]] = []
    for item in _object_list(overview["primitives"]):
        key = _text(item["primitive_key"])
        primitive_id = stable_id("primitive", key, PARSER)
        session.add(
            AttackPrimitiveRow(
                primitive_id=primitive_id,
                primitive_key=key,
                outcome_category=_text(item["outcome_category"]),
                required_actions_json=json.dumps(item["required_actions"]),
                required_resources_json=json.dumps(item["required_resources"]),
                preconditions_json="[]",
                state_transition=_text(item["state_transition"]),
                resulting_capability=_text(item["resulting_capability"]),
                limitations=_text(item["limitations"]),
                mapping_confidence="0.70" if item["attack_mapping_state"] == "mapped" else "0.00",
                attack_mapping_state=_text(item["attack_mapping_state"]),
                generator_version=PARSER,
            )
        )
        primitive_ids[key] = primitive_id
        behavior = _text(item["behavior_id"])
        for rel_key, relation_id in relation_ids.items():
            if rel_key.startswith(behavior + ":"):
                pending_links.append((primitive_id, relation_id))
    session.flush()
    for primitive_id, relation_id in pending_links:
        session.add(PrimitiveRelationRow(primitive_id=primitive_id, relation_id=relation_id))
    session.flush()
    return primitive_ids


def _candidate(
    session: Session,
    overview: dict[str, object],
    entities: dict[str, NormalizedEntityRow],
    primitive_ids: dict[str, str],
) -> None:
    candidate = overview.get("candidate")
    if not isinstance(candidate, dict):
        return
    candidate_id = stable_id("candidate", _text(candidate["rule_id"]))
    session.add(
        RuleCandidateRow(
            candidate_id=candidate_id,
            lifecycle="experimental" if overview.get("publication") else "validated",
            generator_name="credential-template",
            template_version=_text(candidate["template_version"]),
        )
    )
    session.flush()
    primitive_id = primitive_ids["additional_cloud_credentials"]
    session.add(CandidatePrimitiveRow(candidate_id=candidate_id, primitive_id=primitive_id))
    session.add(
        CandidateEntityRow(
            candidate_id=candidate_id,
            entity_id=entities["iam:CreateAccessKey"].entity_id,
        )
    )
    session.add(
        CandidateEntityRow(
            candidate_id=candidate_id,
            entity_id=entities["T1098.001"].entity_id,
        )
    )
    version_id = _text(candidate["version_id"])
    session.add(
        RuleVersionRow(
            version_id=version_id,
            candidate_id=candidate_id,
            rule_version=1,
            rule_json=json.dumps(candidate["rule"]),
            semantic_hash=_text(candidate["semantic_hash"]),
            parent_version_id=None,
            generator_version=_text(candidate["template_version"]),
        )
    )
    session.flush()
    for index, item in enumerate(_object_list(overview["validations"])):
        session.add(
            ValidationRunRow(
                validation_id=stable_id("validation", version_id, _text(item["validator_name"])),
                rule_version_id=version_id,
                validator_name=_text(item["validator_name"]),
                validator_version=_text(item["validator_version"]),
                result=_text(item["result"]),
                findings_json="[]",
                corpus_version=_text(item["corpus_version"]),
                executed_at=_NOW,
                duration_ms=index,
            )
        )
    ai = _object(overview["ai_verification"])
    session.add(
        AIVerificationRow(
            verification_id=stable_id("aiverify", version_id, _text(ai["response_hash"])),
            rule_version_id=version_id,
            provider=_text(ai["provider"]),
            model=_text(ai["model"]),
            prompt_version=_text(ai["prompt_version"]),
            schema_version=_text(ai["schema_version"]),
            evidence_snapshot_hash=_text(candidate["evidence_snapshot_hash"]),
            verdict=_text(ai["verdict"]),
            findings_json=json.dumps(ai["findings"]),
            citations_json=json.dumps(ai["citations"]),
            response_hash=_text(ai["response_hash"]),
        )
    )
    publication = overview.get("publication")
    if isinstance(publication, dict):
        session.add(
            PublicationRow(
                publication_id=stable_id("pub", version_id, "experimental"),
                rule_version_id=version_id,
                evidence_snapshot_hash=_text(publication["evidence_snapshot_hash"]),
                channel="experimental",
                published_at=_NOW,
            )
        )


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("foundry object missing")
    return {str(key): item for key, item in value.items()}


def _object_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise RuntimeError("foundry list missing")
    return [_object(item) for item in value]


def _text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RuntimeError("foundry text missing")
    return value


def _int(value: object) -> int:
    if not isinstance(value, int):
        raise RuntimeError("foundry count missing")
    return value
