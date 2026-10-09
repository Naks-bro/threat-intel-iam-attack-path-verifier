"""Opt-in verification over complete current pinned inputs, never database fallback."""

from __future__ import annotations

import hashlib
import json

from pydantic import ValidationError

from fyp_iam.core.ids import stable_id
from fyp_iam.engine1.foundry.compiler import (
    DEFAULT_TOOLS,
    ExternalValidator,
    Snapshot,
    _evaluation,
    compile_snapshot,
)
from fyp_iam.engine1.foundry.ontology import ONTOLOGY_VERSION
from fyp_iam.engine1.foundry.pins import load_pins
from fyp_iam.engine1.foundry.verifier import PROMPT_VERSION, FakeVerifier, Verifier, run_verifier
from fyp_iam.engine1.foundry.verifier_models import (
    VerifierEvidence,
    VerifierRequest,
    _invalid_result,
)

_FILES = {
    "mitre-attack": "mitre-enterprise-19.2-extract.json",
    "aws-service-reference": "aws-service-reference-extract.json",
    "stratus-red-team": "stratus-iam-redacted.json",
}


def build_verifier_request(snapshot: Snapshot, compiled: dict[str, object]) -> VerifierRequest:
    """Use the three small redacted pins in full, without inventing source excerpts.

    This selector supports the current single credential family only. Historical
    stored rows lacking exact payloads fail closed rather than loading newer pins.
    Pin hashes are checked against the reviewed local manifest, not just caller metadata.
    """
    try:
        candidate = compiled["candidate"]
        if (
            not isinstance(candidate, dict)
            or candidate["primitive_key"] != "additional_cloud_credentials"
        ):
            raise ValueError("unsupported candidate")
        pins = load_pins()
        refs = candidate["evidence_ids"]
        supported_refs = {
            stable_id("evidence", behavior.native_id, action)
            for behavior in pins.behaviors
            for action in behavior.actions
            if action == "iam:CreateAccessKey" and "T1098.001" in behavior.cited_technique_ids
        }
        if not isinstance(refs, list) or len(refs) != 1 or refs[0] not in supported_refs:
            raise ValueError("unsupported evidence reference")
        sources = {source.source_key: source for source in snapshot.sources}
        if len(sources) != len(snapshot.sources) or set(sources) != set(_FILES):
            raise ValueError("source set mismatch")
        fragments = []
        for pinned in sorted(pins.source_rows, key=lambda row: str(row["source_key"])):
            key = str(pinned["source_key"])
            source = sources[key]
            raw = snapshot.payloads[_FILES[key]]
            if len(raw) > 4096:
                raise ValueError("source payload too large")
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            if (
                not source.enabled
                or digest != source.content_hash
                or digest != pinned["content_hash"]
                or source.version_label != pinned["version_label"]
                or source.official_url != pinned["official_url"]
            ):
                raise ValueError("source binding mismatch")
            fragments.append(
                VerifierEvidence.model_validate(
                    {
                        "evidence_id": refs[0]
                        if key == "stratus-red-team"
                        else stable_id("evidence", key, digest),
                        "source_key": key,
                        "source_version": source.version_label,
                        "text": raw.decode("utf-8"),
                        "content_hash": digest,
                    }
                )
            )
        return VerifierRequest.model_validate(
            {
                "candidate_version_id": candidate["version_id"],
                "candidate_semantic_hash": candidate["semantic_hash"],
                "candidate_json": json.dumps(candidate["rule"]),
                "evidence_snapshot_hash": candidate["evidence_snapshot_hash"],
                "ontology_version": ONTOLOGY_VERSION,
                "prompt_version": PROMPT_VERSION,
                "evidence": tuple(fragments),
            }
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise ValueError("verifier evidence unavailable") from exc


async def compile_verified_snapshot(
    snapshot: Snapshot,
    *,
    adapter: Verifier | None = None,
    tools: tuple[ExternalValidator, ...] = DEFAULT_TOOLS,
    timeout_seconds: float = 5,
    allow_external: bool = False,
) -> dict[str, object]:
    """Compile once, then replace the legacy fake result with a bound critique.

    No persistence or external provider is implicit. Publication can only remain
    experimental when both deterministic checks and the checked critic pass.
    """
    compiled = compile_snapshot(snapshot, tools=tools)
    validations = compiled["validations"]
    assert isinstance(validations, list)
    passed = compiled["publication"] is not None
    try:
        request = build_verifier_request(snapshot, compiled)
    except (ValueError, ValidationError):
        response = _invalid_result()
        response.pop("response_hash")
        response["failure_code"] = "evidence_unavailable"
        response["response_hash"] = (
            "sha256:" + hashlib.sha256(json.dumps(response, sort_keys=True).encode()).hexdigest()
        )
    else:
        response = await run_verifier(
            request,
            adapter or FakeVerifier(validations_passed=passed),
            timeout_seconds=timeout_seconds,
            allow_external=allow_external,
        )
    compiled["ai_verification"] = response
    compiled["suggestions"] = response.get("suggestions", [])
    if response.get("verdict") != "pass":
        compiled["publication"] = None
    compiled["evaluation"] = _evaluation(validations, response, passed)
    return compiled
