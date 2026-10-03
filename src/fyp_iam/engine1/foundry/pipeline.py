"""Present a foundry run. Adapters fill the snapshot. The compiler reads that snapshot."""

from __future__ import annotations

from fyp_iam.core.ids import sha256_key
from fyp_iam.engine1.foundry.adapters import assemble_snapshot
from fyp_iam.engine1.foundry.compiler import (
    Snapshot,
    compile_snapshot,
)
from fyp_iam.engine1.foundry.compiler import (
    mapping_decision as decide_mapping,
)
from fyp_iam.engine1.foundry.pins import TechniquePin, load_pins
from fyp_iam.engine1.foundry.verifier import fake_verify

PARSER = "foundry-pin-parser-0.1"

__all__ = ["PARSER", "build_foundry", "fake_verify", "mapping_decision", "rules_for_engine3"]


def mapping_decision(behavior_id: str, action: str, technique: TechniquePin) -> tuple[str, str]:
    return decide_mapping(behavior_id, action, technique.native_id, technique.name)


def build_foundry(*, persisted: bool, storage: str) -> dict[str, object]:
    """Run the pinned slice. The same pins always produce the same semantic hash."""

    snapshot = assemble_snapshot()
    compiled = compile_snapshot(snapshot)
    return present(snapshot, compiled, persisted=persisted, storage=storage)


def present(
    snapshot: Snapshot,
    compiled: dict[str, object],
    *,
    persisted: bool,
    storage: str,
) -> dict[str, object]:
    candidate = compiled["candidate"]
    semantic_hash = "sha256:" + ("0" * 64)
    if isinstance(candidate, dict) and isinstance(candidate.get("semantic_hash"), str):
        semantic_hash = candidate["semantic_hash"]
    relations = [
        {
            "from_native_id": item.from_native_id,
            "to_native_id": item.to_native_id,
            "relation_type": item.relation_type,
            "mapping_method": item.mapping_method,
            "mapping_confidence": item.mapping_confidence,
            "review_state": item.review_state,
            "rationale": item.rationale,
        }
        for item in snapshot.relations
    ]
    sources = [
        {
            "source_key": item.source_key,
            "authority_tier": item.authority_tier,
            "source_type": item.source_type,
            "official_url": item.official_url,
            "version_label": item.version_label,
            "enabled": item.enabled,
            "content_hash": item.content_hash,
            "last_status": "succeeded",
        }
        for item in snapshot.sources
    ]
    sources.extend(
        {
            "source_key": item.source_key,
            "authority_tier": item.authority_tier,
            "source_type": item.source_type,
            "official_url": item.official_url,
            "version_label": item.version_label,
            "enabled": False,
            "content_hash": "",
            "last_status": "disabled",
        }
        for item in snapshot.disabled_sources
    )
    for failure in snapshot.failures:
        sources.append(
            {
                "source_key": failure.source_key,
                "authority_tier": failure.authority_tier,
                "source_type": failure.source_type,
                "official_url": failure.official_url,
                "version_label": "unavailable",
                "enabled": True,
                "content_hash": "",
                "last_status": "failed",
                "last_error": failure.error,
            }
        )
    pins = load_pins()
    return {
        "schema_version": "0.1",
        "persisted": persisted,
        "storage": storage,
        "sources": sources,
        "failures": [item.error for item in snapshot.failures],
        "run": {
            "status": "partial" if snapshot.failures else "succeeded",
            "fetched_count": len(snapshot.sources) + len(snapshot.failures),
            "created_count": len(snapshot.sources),
            "unchanged_count": 0,
            "rejected_count": sum(1 for item in relations if item["review_state"] == "rejected"),
            "failed_count": len(snapshot.failures),
            "parser_version": PARSER,
            "content_hash": sha256_key(pins.bundle_hash, semantic_hash),
        },
        "primitives": compiled["primitives"],
        "relations": relations,
        "candidate": candidate,
        "validations": compiled["validations"],
        "quality_report": compiled["quality_report"],
        "ai_verification": compiled["ai_verification"],
        "suggestions": compiled["suggestions"],
        "publication": compiled["publication"],
        "evaluation": compiled["evaluation"],
        "lineage": compiled["lineage"],
    }


def rules_for_engine3(
    overview: dict[str, object], *, include_experimental: bool = False
) -> list[dict[str, object]]:
    """Stable publications are the default. Experimental rules need an explicit opt-in."""

    publication = overview.get("publication")
    candidate = overview.get("candidate")
    if not isinstance(publication, dict) or not isinstance(candidate, dict):
        return []
    channel = publication.get("channel")
    if channel == "stable" or (channel == "experimental" and include_experimental):
        rule = candidate.get("rule")
        if isinstance(rule, dict):
            return [rule]
    return []
