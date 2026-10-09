"""Read-only projection of the deterministic, pinned Engine 1 slice.

Preview never connects to a database and never creates a publication. It is a
demonstration of candidate eligibility, not a persisted registry state.
"""

from __future__ import annotations

from typing import cast

from fyp_iam.engine1.foundry.compiler import OPTIONAL_VALIDATOR_NAMES
from fyp_iam.engine1.foundry.pipeline import build_foundry


def _snapshot() -> dict[str, object]:
    return build_foundry(persisted=False, storage="preview")


def preview_overview() -> dict[str, object]:
    snapshot = _snapshot()
    sources = cast(list[dict[str, object]], snapshot["sources"])
    primitives = cast(list[dict[str, object]], snapshot["primitives"])
    relations = cast(list[dict[str, object]], snapshot["relations"])
    candidate = cast(dict[str, object] | None, snapshot["candidate"])
    run = cast(dict[str, object], snapshot["run"])
    return {
        "schema_version": "0.1",
        "database": "not_connected",
        "database_detail": "offline_preview",
        "storage": "preview",
        "registry": "ready",
        "sources": [
            {
                key: source[key]
                for key in (
                    "source_key",
                    "authority_tier",
                    "source_type",
                    "version_label",
                    "enabled",
                    "last_status",
                )
            }
            for source in sources
        ],
        "run": {
            key: run[key]
            for key in (
                "status",
                "fetched_count",
                "created_count",
                "unchanged_count",
                "rejected_count",
                "parser_version",
            )
        },
        "primitives": [
            {
                key: primitive[key]
                for key in (
                    "primitive_key",
                    "outcome_category",
                    "required_actions",
                    "attack_mapping_state",
                    "state_transition",
                )
            }
            for primitive in primitives
        ],
        "relations": [
            {
                key: relation[key]
                for key in (
                    "from_native_id",
                    "to_native_id",
                    "relation_type",
                    "review_state",
                    "rationale",
                )
            }
            for relation in relations
        ],
        "candidates": []
        if candidate is None
        else [
            {
                "rule_id": candidate["rule_id"],
                "version_id": candidate["version_id"],
                "semantic_hash": candidate["semantic_hash"],
                "lifecycle": candidate["lifecycle"],
                "channel": "preview_only",
            }
        ],
    }


def preview_rule(version_id: str) -> dict[str, object] | None:
    snapshot = _snapshot()
    candidate = cast(dict[str, object] | None, snapshot["candidate"])
    if candidate is None or candidate["version_id"] != version_id:
        return None
    validations = cast(list[dict[str, object]], snapshot["validations"])
    ai = cast(dict[str, object] | None, snapshot["ai_verification"])
    scenarios: list[object] = []
    for validation in validations:
        if validation["validator_name"] == "scenario_corpus":
            scenarios = cast(list[object], validation["findings"])
            break
    return {
        "rule_id": candidate["rule_id"],
        "version_id": candidate["version_id"],
        "semantic_hash": candidate["semantic_hash"],
        "lifecycle": candidate["lifecycle"],
        "rule": candidate["rule"],
        "validations": [
            {
                "validator_name": item["validator_name"],
                "result": item["result"],
                "optional": item["validator_name"] in OPTIONAL_VALIDATOR_NAMES,
                "findings": [
                    finding
                    for finding in cast(list[object], item["findings"])
                    if isinstance(finding, str)
                ],
            }
            for item in validations
        ],
        "ai_verification": None
        if ai is None
        else {"provider": ai["provider"], "model": ai["model"], "verdict": ai["verdict"]},
        "publication": None,
        "scenarios": scenarios,
        "quality_report": snapshot["quality_report"],
    }
