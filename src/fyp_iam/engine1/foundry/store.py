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
from fyp_iam.engine1.foundry.adapters import assemble_snapshot
from fyp_iam.engine1.foundry.compiler import (
    EntityDraft,
    RelationDraft,
    Snapshot,
    compile_snapshot,
)
from fyp_iam.engine1.foundry.models import (
    AISuggestionRow,
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
from fyp_iam.engine1.foundry.pipeline import PARSER, present
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable

_NOW = datetime(2026, 10, 3, tzinfo=UTC)


def persist_foundry(url: str) -> dict[str, object]:
    if not url or url.startswith("sqlite"):
        raise DatabaseUnavailable("PostgreSQL is required for foundry persistence")
    snapshot = assemble_snapshot()
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with Session(engine) as session, session.begin():
            version_ids = {
                item.source_key: stable_id("sver", item.source_key, item.content_hash)
                for item in snapshot.sources
            }
            already = all(
                session.get(SourceVersionRow, version_id) is not None
                for version_id in version_ids.values()
            )
            _ensure_sources(session, snapshot)
            _ensure_failures(session, snapshot)
            preview = compile_snapshot(snapshot)
            overview = present(snapshot, preview, persisted=True, storage="postgres")
            run = _object(overview["run"])
            if already:
                run["created_count"] = 0
                run["unchanged_count"] = len(snapshot.sources)
            pipeline_id = stable_id("pipeline", str(run["content_hash"]), uuid4().hex)
            session.add(
                PipelineRunRow(
                    run_id=pipeline_id,
                    status=_text(run["status"]),
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
            _ingest_failures(session, pipeline_id, snapshot)
            if not already:
                _write_graph(session, pipeline_id, version_ids, snapshot)
            session.flush()
            stored = _read_snapshot(session)
            compiled = compile_snapshot(stored)
            overview = present(snapshot, compiled, persisted=True, storage="postgres")
            run = _object(overview["run"])
            if already:
                run["created_count"] = 0
                run["unchanged_count"] = len(snapshot.sources)
            if not already:
                _write_compiled(session, overview)
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


def read_registry(url: str) -> dict[str, object]:
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with Session(engine) as session:
            sources = session.scalars(select(SourceRow)).all()
            versions = session.scalars(select(SourceVersionRow)).all()
            ingestions = session.scalars(select(IngestionRunRow)).all()
            runs = session.scalars(select(PipelineRunRow)).all()
            if not sources and not runs:
                return _registry_shell("ok", "reachable", "empty")
            version_by_source = {row.source_id: row for row in versions}
            latest_ingestion: dict[str, IngestionRunRow] = {}
            for row in sorted(ingestions, key=lambda item: item.ingestion_id):
                latest_ingestion[row.source_id] = row
            source_views = []
            for source in sources:
                version = version_by_source.get(source.source_id)
                ingestion = latest_ingestion.get(source.source_id)
                source_views.append(
                    {
                        "source_key": source.source_key,
                        "authority_tier": source.authority_tier,
                        "source_type": source.source_type,
                        "version_label": version.version_label if version else "unavailable",
                        "enabled": source.enabled,
                        "last_status": ingestion.status if ingestion else "queued",
                    }
                )
            latest = max(runs, key=lambda item: item.run_id) if runs else None
            entities = session.scalars(select(NormalizedEntityRow)).all()
            native_by_id = {row.entity_id: row.native_id for row in entities}
            relations = [
                {
                    "from_native_id": native_by_id[row.from_entity_id],
                    "to_native_id": native_by_id[row.to_entity_id],
                    "relation_type": row.relation_type,
                    "review_state": row.review_state,
                    "rationale": row.rationale,
                }
                for row in session.scalars(select(EvidenceRelationRow)).all()
            ]
            primitives = [
                {
                    "primitive_key": row.primitive_key,
                    "outcome_category": row.outcome_category,
                    "required_actions": json.loads(row.required_actions_json),
                    "attack_mapping_state": row.attack_mapping_state,
                    "state_transition": row.state_transition,
                }
                for row in session.scalars(select(AttackPrimitiveRow)).all()
            ]
            candidates = []
            for rule_version in session.scalars(select(RuleVersionRow)).all():
                candidate = session.get(RuleCandidateRow, rule_version.candidate_id)
                publication = session.scalar(
                    select(PublicationRow).where(
                        PublicationRow.rule_version_id == rule_version.version_id
                    )
                )
                candidates.append(
                    {
                        "rule_id": json.loads(rule_version.rule_json)["rule_id"],
                        "version_id": rule_version.version_id,
                        "semantic_hash": rule_version.semantic_hash,
                        "lifecycle": candidate.lifecycle if candidate else "generated",
                        "channel": publication.channel if publication else "unpublished",
                    }
                )
            return {
                **_registry_shell(
                    "ok",
                    "reachable",
                    "ready" if candidates or source_views else "empty",
                ),
                "sources": source_views,
                "run": None
                if latest is None
                else {
                    "status": latest.status,
                    "fetched_count": latest.fetched_count,
                    "created_count": latest.created_count,
                    "unchanged_count": latest.unchanged_count,
                    "rejected_count": latest.rejected_count,
                    "parser_version": PARSER,
                },
                "primitives": primitives,
                "relations": relations,
                "candidates": candidates,
            }
    finally:
        engine.dispose()


def read_rule(url: str, version_id: str) -> dict[str, object] | None:
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with Session(engine) as session:
            version = session.get(RuleVersionRow, version_id)
            if version is None:
                return None
            candidate = session.get(RuleCandidateRow, version.candidate_id)
            validations = session.scalars(
                select(ValidationRunRow).where(ValidationRunRow.rule_version_id == version_id)
            ).all()
            ai = session.scalar(
                select(AIVerificationRow).where(AIVerificationRow.rule_version_id == version_id)
            )
            publication = session.scalar(
                select(PublicationRow).where(PublicationRow.rule_version_id == version_id)
            )
            scenarios: list[object] = []
            for item in validations:
                if item.validator_name == "scenario_corpus":
                    parsed = json.loads(item.findings_json)
                    if isinstance(parsed, list):
                        scenarios = parsed
            rule = json.loads(version.rule_json)
            return {
                "rule_id": rule["rule_id"] if isinstance(rule, dict) else version.version_id,
                "version_id": version.version_id,
                "semantic_hash": version.semantic_hash,
                "lifecycle": candidate.lifecycle if candidate else "generated",
                "rule": rule,
                "validations": [
                    {"validator_name": item.validator_name, "result": item.result}
                    for item in validations
                ],
                "ai_verification": None
                if ai is None
                else {
                    "provider": ai.provider,
                    "model": ai.model,
                    "verdict": ai.verdict,
                },
                "publication": None if publication is None else {"channel": publication.channel},
                "scenarios": scenarios,
            }
    finally:
        engine.dispose()


def _registry_shell(database: str, detail: str, registry: str) -> dict[str, object]:
    return {
        "database": database,
        "database_detail": detail,
        "storage": "postgres" if database == "ok" and registry != "empty" else "not_written",
        "registry": registry,
        "sources": [],
        "run": None,
        "primitives": [],
        "relations": [],
        "candidates": [],
    }


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


def _ensure_sources(session: Session, snapshot: Snapshot) -> None:
    for item in snapshot.sources:
        source_id = stable_id("source", item.source_key)
        session.execute(
            insert(SourceRow)
            .values(
                source_id=source_id,
                source_key=item.source_key,
                authority_tier=item.authority_tier,
                source_type=item.source_type,
                official_url=item.official_url,
                enabled=True,
                schedule_cron=None,
            )
            .on_conflict_do_nothing(index_elements=["source_key"])
        )
        session.execute(
            insert(SourceVersionRow)
            .values(
                version_id=stable_id("sver", item.source_key, item.content_hash),
                source_id=source_id,
                version_label=item.version_label,
                discovered_at=_NOW,
                effective_at=_NOW,
                content_hash=item.content_hash,
            )
            .on_conflict_do_nothing(index_elements=["source_id", "content_hash"])
        )
    session.flush()


def _ensure_failures(session: Session, snapshot: Snapshot) -> None:
    for item in snapshot.failures:
        session.execute(
            insert(SourceRow)
            .values(
                source_id=stable_id("source", item.source_key),
                source_key=item.source_key,
                authority_tier=item.authority_tier,
                source_type=item.source_type,
                official_url=item.official_url,
                enabled=True,
                schedule_cron=None,
            )
            .on_conflict_do_nothing(index_elements=["source_key"])
        )
    session.flush()


def _ingest_failures(session: Session, pipeline_id: str, snapshot: Snapshot) -> None:
    for item in snapshot.failures:
        session.add(
            IngestionRunRow(
                ingestion_id=stable_id("ingest", pipeline_id, item.source_key),
                pipeline_run_id=pipeline_id,
                source_id=stable_id("source", item.source_key),
                source_version_id=None,
                attempt=1,
                status="failed",
                started_at=_NOW,
                finished_at=_NOW,
                fetched_count=0,
                created_count=0,
                updated_count=0,
                unchanged_count=0,
                rejected_count=0,
                error_json=json.dumps(item.error),
                retry_of=None,
                parser_version=PARSER,
            )
        )
    session.flush()


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
    snapshot: Snapshot,
) -> None:
    file_for = {
        "mitre-attack": "mitre-enterprise-19.2-extract.json",
        "aws-service-reference": "aws-service-reference-extract.json",
        "stratus-red-team": "stratus-iam-redacted.json",
    }
    artifact_ids: dict[str, str] = {}
    for key, filename in file_for.items():
        payload = snapshot.payloads[filename]
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
    entities = _entities(snapshot, version_ids, artifact_ids)
    for row in entities.values():
        session.add(row)
    session.flush()
    claim_ids = _claims(session, snapshot, entities, artifact_ids)
    _relations(session, snapshot, entities, claim_ids)


def hashlib_payload(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _entities(
    snapshot: Snapshot,
    version_ids: dict[str, str],
    artifact_ids: dict[str, str],
) -> dict[str, NormalizedEntityRow]:
    rows: dict[str, NormalizedEntityRow] = {}
    for item in snapshot.entities:
        rows[item.native_id] = _entity(
            item.entity_type,
            item.native_id,
            item.name,
            version_ids[item.source_key],
            artifact_ids[item.source_key],
            json.dumps(item.attributes),
        )
    return rows


def _entity(
    entity_type: str,
    native_id: str,
    name: str,
    version_id: str,
    artifact_id: str,
    attributes_json: str,
) -> NormalizedEntityRow:
    return NormalizedEntityRow(
        entity_id=stable_id("entity", entity_type, native_id, version_id),
        entity_type=entity_type,
        native_id=native_id,
        name=name[:200],
        source_version_id=version_id,
        artifact_id=artifact_id,
        attributes_json=attributes_json,
    )


def _claims(
    session: Session,
    snapshot: Snapshot,
    entities: dict[str, NormalizedEntityRow],
    artifact_ids: dict[str, str],
) -> dict[str, str]:
    claim_ids: dict[str, str] = {}
    for claim in snapshot.claims:
        claim_id = stable_id("claim", claim.subject_native_id, claim.object_value)
        session.add(
            EvidenceClaimRow(
                claim_id=claim_id,
                subject_entity_id=entities[claim.subject_native_id].entity_id,
                predicate=claim.predicate,
                object_value=claim.object_value,
                object_entity_id=entities[claim.object_native_id].entity_id,
                artifact_id=artifact_ids[claim.source_key],
                source_location=claim.source_location,
                extraction_method=claim.extraction_method,
                confidence=claim.confidence,
                valid_from=None,
                valid_to=None,
            )
        )
        claim_ids[f"{claim.subject_native_id}:{claim.object_value}"] = claim_id
    session.flush()
    return claim_ids


def _relations(
    session: Session,
    snapshot: Snapshot,
    entities: dict[str, NormalizedEntityRow],
    claim_ids: dict[str, str],
) -> dict[str, str]:
    relation_ids: dict[str, str] = {}
    pending_claims: list[tuple[str, str]] = []
    for item in snapshot.relations:
        left = item.from_native_id
        right = item.to_native_id
        relation_id = stable_id("relation", left, right, item.relation_type)
        session.add(
            EvidenceRelationRow(
                relation_id=relation_id,
                from_entity_id=entities[left].entity_id,
                to_entity_id=entities[right].entity_id,
                relation_type=item.relation_type,
                mapping_method=item.mapping_method,
                mapping_confidence=item.mapping_confidence,
                review_state=item.review_state,
                rationale=item.rationale,
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
                findings_json=json.dumps(item.get("findings", [])),
                corpus_version=_text(item["corpus_version"]),
                executed_at=_NOW,
                duration_ms=index,
            )
        )
    ai = _object(overview["ai_verification"])
    verification_id = stable_id("aiverify", version_id, _text(ai["response_hash"]))
    session.add(
        AIVerificationRow(
            verification_id=verification_id,
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
    suggestions = overview.get("suggestions", [])
    if isinstance(suggestions, list):
        for index, suggestion in enumerate(suggestions):
            if not isinstance(suggestion, dict):
                continue
            session.add(
                AISuggestionRow(
                    suggestion_id=stable_id("suggest", verification_id, str(index)),
                    verification_id=verification_id,
                    rule_version_id=version_id,
                    suggestion_json=json.dumps(suggestion),
                    recorded_at=_NOW,
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


def _read_snapshot(session: Session) -> Snapshot:
    stored = session.scalars(select(NormalizedEntityRow)).all()
    native_by_id = {row.entity_id: row.native_id for row in stored}
    entities = tuple(
        EntityDraft(
            entity_type=row.entity_type,
            native_id=row.native_id,
            name=row.name,
            source_key="",
            attributes=_json_object(row.attributes_json),
        )
        for row in stored
    )
    relations = tuple(
        RelationDraft(
            from_native_id=native_by_id[row.from_entity_id],
            to_native_id=native_by_id[row.to_entity_id],
            relation_type=row.relation_type,
            mapping_method=row.mapping_method,
            mapping_confidence=row.mapping_confidence,
            review_state=row.review_state,
            rationale=row.rationale,
        )
        for row in session.scalars(select(EvidenceRelationRow)).all()
    )
    return Snapshot(
        sources=(),
        failures=(),
        entities=entities,
        claims=(),
        relations=relations,
        payloads={},
    )


def _write_compiled(session: Session, overview: dict[str, object]) -> None:
    stored = session.scalars(select(NormalizedEntityRow)).all()
    native_by_id = {row.entity_id: row.native_id for row in stored}
    relation_ids: dict[str, str] = {}
    for row in session.scalars(select(EvidenceRelationRow)).all():
        left = native_by_id[row.from_entity_id]
        right = native_by_id[row.to_entity_id]
        relation_ids[f"{left}:{right}"] = row.relation_id
    entities = {row.native_id: row for row in stored}
    primitive_ids = _primitives(session, overview, relation_ids)
    _candidate(session, overview, entities, primitive_ids)


def _json_object(value: str) -> dict[str, object]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        return {}
    return {str(key): item for key, item in parsed.items()}


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
