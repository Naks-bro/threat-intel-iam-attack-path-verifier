"""Schema-only verifier. Imported text is data and cannot set the verdict."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from fyp_iam.engine1.foundry.verifier_models import VerifierRequest

PROMPT_VERSION = "verifier-prompt-0.1"


class Verifier(Protocol):
    provider: str
    model: str
    is_external: bool

    async def verify(self, request: VerifierRequest) -> dict[str, object]: ...


class FakeVerifier:
    """Deterministic wiring adapter, not independent AI semantic verification."""

    provider = "fake"
    model = "schema-only"
    is_external = False

    def __init__(self, *, validations_passed: bool) -> None:
        self.validations_passed = validations_passed

    async def verify(self, request: VerifierRequest) -> dict[str, object]:
        response = fake_verify(
            validations_passed=self.validations_passed,
            evidence_ids=[item.evidence_id for item in request.evidence],
            source_text="",
        )
        response.pop("response_hash")
        response.update(
            candidate_version_id=request.candidate_version_id,
            evidence_snapshot_hash=request.evidence_snapshot_hash,
            request_hash=request.request_hash,
        )
        return response


async def run_verifier(
    request: VerifierRequest,
    adapter: Verifier,
    *,
    timeout_seconds: float = 5,
    allow_external: bool = False,
) -> dict[str, object]:
    """Cooperative deadline for trusted adapters, not a plugin isolation boundary.

    Real adapters must be nonblocking and set transport deadlines themselves.
    External invocation requires explicit opt-in; no external adapter ships here.
    """
    from fyp_iam.engine1.foundry.verifier_models import _invalid_result, checked_verification

    def failed(code: str) -> dict[str, object]:
        result = _invalid_result()
        result["failure_code"] = code
        result.pop("response_hash")
        result["response_hash"] = (
            "sha256:" + hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
        )
        return result

    if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30:
        return failed("invalid_timeout")
    if adapter.is_external and not allow_external:
        return failed("external_provider_disabled")
    try:
        raw = await asyncio.wait_for(adapter.verify(request), timeout=timeout_seconds)
    except TimeoutError:
        return failed("provider_timeout")
    except Exception:
        return failed("provider_error")
    if (
        not isinstance(raw, dict)
        or raw.get("provider") != adapter.provider
        or raw.get("model") != adapter.model
    ):
        return failed("provider_binding_failed")
    return checked_verification(
        raw,
        version_id=request.candidate_version_id,
        evidence_hash=request.evidence_snapshot_hash,
        evidence_ids=[item.evidence_id for item in request.evidence],
        request_hash=request.request_hash,
    )


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
