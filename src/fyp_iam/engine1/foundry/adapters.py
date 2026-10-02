"""Pinned source adapters. They do not open a network connection."""

from __future__ import annotations

import json
from pathlib import Path

from fyp_iam.engine1.foundry.compiler import (
    ClaimDraft,
    EntityDraft,
    FailureDraft,
    RelationDraft,
    Snapshot,
    SourceDraft,
    mapping_decision,
)
from fyp_iam.engine1.foundry.pins import load_pins

_PIN = Path(__file__).resolve().parent / "pins" / "aws-ttc-discovery.json"
_PARSER = "foundry-pin-parser-0.1"


def assemble_snapshot() -> Snapshot:
    pins = load_pins()
    entities: list[EntityDraft] = []
    claims: list[ClaimDraft] = []
    relations: list[RelationDraft] = []
    for technique_pin in pins.techniques.values():
        entities.append(
            EntityDraft(
                entity_type="technique",
                native_id=technique_pin.native_id,
                name=technique_pin.name,
                source_key="mitre-attack",
                attributes={},
            )
        )
    services: set[str] = set()
    for action_pin in pins.actions.values():
        prefix = action_pin.native_id.split(":", 1)[0]
        services.add(prefix)
        entities.append(
            EntityDraft(
                entity_type="aws_action",
                native_id=action_pin.native_id,
                name=action_pin.native_id,
                source_key="aws-service-reference",
                attributes={"resources": list(action_pin.resources)},
            )
        )
        for resource in action_pin.resources:
            native = f"aws:{resource}"
            if any(item.native_id == native for item in entities):
                continue
            entities.append(
                EntityDraft(
                    entity_type="aws_resource",
                    native_id=native,
                    name=resource,
                    source_key="aws-service-reference",
                    attributes={},
                )
            )
    for prefix in sorted(services):
        entities.append(
            EntityDraft(
                entity_type="aws_service",
                native_id=prefix,
                name=prefix,
                source_key="aws-service-reference",
                attributes={},
            )
        )
    known_actions = {item.native_id for item in entities if item.entity_type == "aws_action"}
    techniques = {item.native_id: item for item in entities if item.entity_type == "technique"}
    for behavior in pins.behaviors:
        entities.append(
            EntityDraft(
                entity_type="attack_behavior",
                native_id=behavior.native_id,
                name=behavior.title,
                source_key="stratus-red-team",
                attributes={},
            )
        )
        for action_name in behavior.actions:
            if action_name not in known_actions:
                continue
            claims.append(
                ClaimDraft(
                    subject_native_id=behavior.native_id,
                    predicate="requires_action",
                    object_value=action_name,
                    object_native_id=action_name,
                    source_key="stratus-red-team",
                    source_location="techniques.actions",
                    extraction_method="redacted-field-extract-0.1",
                    confidence="0.40",
                )
            )
            relations.append(
                RelationDraft(
                    from_native_id=behavior.native_id,
                    to_native_id=action_name,
                    relation_type="uses_action",
                    mapping_method="preserved-action-field",
                    mapping_confidence="0.40",
                    review_state="proposed",
                    rationale="The preserved Stratus metadata names this AWS action",
                )
            )
        for technique_id in behavior.cited_technique_ids:
            technique = techniques.get(technique_id)
            if technique is None:
                continue
            named = [name for name in behavior.actions if name in known_actions] or [""]
            decisions = [
                mapping_decision(behavior.native_id, name, technique.native_id, technique.name)
                for name in named
            ]
            state, rationale = next(
                (item for item in decisions if item[0] == "proposed"),
                decisions[0],
            )
            relations.append(
                RelationDraft(
                    from_native_id=behavior.native_id,
                    to_native_id=technique.native_id,
                    relation_type="cites_technique",
                    mapping_method="cited-id-checked-against-stix-name",
                    mapping_confidence="0.70" if state == "proposed" else "0.00",
                    review_state=state,
                    rationale=rationale,
                )
            )
    sources = tuple(
        SourceDraft(
            source_key=str(item["source_key"]),
            authority_tier=_tier(item["authority_tier"]),
            source_type=str(item["source_type"]),
            official_url=str(item["official_url"]),
            version_label=str(item["version_label"]),
            content_hash=str(item["content_hash"]),
            enabled=True,
        )
        for item in pins.source_rows
    )
    return Snapshot(
        sources=sources,
        failures=(probe_threat_technique_catalog(),),
        entities=tuple(entities),
        claims=tuple(claims),
        relations=tuple(relations),
        payloads=dict(pins.payloads),
    )


def _tier(value: object) -> int:
    if not isinstance(value, int):
        raise RuntimeError("source tier is missing")
    return value


def probe_threat_technique_catalog(transport: object | None = None) -> FailureDraft:
    """Record a bounded catalog probe. The default transport is the pinned failure."""

    document = json.loads(_PIN.read_text(encoding="utf-8"))
    if transport is not None:
        if not callable(transport):
            raise RuntimeError("TTC transport must be callable")
        try:
            status, _body = transport(str(document["url"]))
        except OSError as exc:
            document = {
                **document,
                "status": "failed",
                "reason": "connection_error",
                "http_status": 0,
                "detail": exc.__class__.__name__,
            }
        else:
            code = int(status)
            document = {
                **document,
                "status": "failed",
                "reason": "repository_not_found" if code == 404 else "probe_failed",
                "http_status": code,
            }
    return FailureDraft(
        source_key="aws-threat-technique-catalog",
        authority_tier=1,
        source_type="threat_catalog",
        official_url=str(document["url"]),
        error={
            "reason": document["reason"],
            "http_status": document["http_status"],
            "detail": document["detail"],
            "checked_at": document["checked_at"],
            "parser_version": _PARSER,
        },
    )
