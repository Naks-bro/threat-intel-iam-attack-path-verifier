"""Closed response contract for an opt-in, provider-neutral verifier."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from fyp_iam.engine1.foundry.verifier import PROMPT_VERSION


class VerifierSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=1000)
    citations: list[str] = Field(min_length=1)


class VerifierResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=64)
    prompt_version: str = Field(min_length=1, max_length=64)
    schema_version: Literal["0.1"]
    candidate_version_id: str = Field(min_length=1)
    evidence_snapshot_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    verdict: Literal["pass", "needs_review", "reject"]
    findings: list[str] = Field(min_length=1)
    citations: list[str] = Field(min_length=1)
    suggestions: list[VerifierSuggestion] = Field(default_factory=list)


def checked_verification(
    raw: dict[str, object], *, version_id: str, evidence_hash: str, evidence_ids: list[str]
) -> dict[str, object]:
    """Normalize a verifier response or return a non-publishing review result."""

    try:
        response = VerifierResponse.model_validate(raw)
    except ValidationError:
        return _invalid_result()
    cited = set(response.citations)
    if (
        response.candidate_version_id != version_id
        or response.evidence_snapshot_hash != evidence_hash
        or not cited.issubset(evidence_ids)
        or any(not set(item.citations).issubset(evidence_ids) for item in response.suggestions)
    ):
        return _invalid_result()
    body = response.model_dump()
    body["response_hash"] = (
        "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
    )
    return body


def _invalid_result() -> dict[str, object]:
    body: dict[str, object] = {
        "provider": "invalid_response",
        "model": "rejected",
        "prompt_version": PROMPT_VERSION,
        "schema_version": "0.1",
        "verdict": "needs_review",
        "findings": ["Verifier response failed schema, version, or evidence binding"],
        "citations": [],
        "suggestions": [],
    }
    body["response_hash"] = (
        "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
    )
    return body
