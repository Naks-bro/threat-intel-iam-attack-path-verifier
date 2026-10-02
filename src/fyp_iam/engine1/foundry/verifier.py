"""Schema-only verifier. Imported text is data and cannot set the verdict."""

from __future__ import annotations

import hashlib
import json

PROMPT_VERSION = "verifier-prompt-0.1"


def fake_verify(
    *,
    validations_passed: bool,
    evidence_ids: list[str],
    source_text: str,
    suggestions: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    del source_text
    proposed = list(suggestions or [])
    if not validations_passed or not evidence_ids:
        verdict = "needs_review"
        findings = ["Deterministic validation did not pass or evidence ids are missing"]
    else:
        verdict = "pass"
        findings = ["Deterministic validators passed and every citation is an evidence id"]
    body = {
        "verdict": verdict,
        "findings": findings,
        "unsupported_claims": [],
        "missing_evidence": [] if evidence_ids else ["no evidence ids"],
        "contradictions": [],
        "citations": evidence_ids,
        "suggestions": proposed,
    }
    encoded = json.dumps(body, sort_keys=True)
    return {
        "provider": "fake",
        "model": "schema-only",
        "prompt_version": PROMPT_VERSION,
        "schema_version": "0.1",
        "verdict": verdict,
        "findings": findings,
        "citations": evidence_ids,
        "suggestions": proposed,
        "response_hash": "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    }
