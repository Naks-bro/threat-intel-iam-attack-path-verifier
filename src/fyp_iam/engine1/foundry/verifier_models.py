"""Closed response contract for an opt-in, provider-neutral verifier."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from fyp_iam.contracts.models import ApprovedRule, reject_sensitive_text
from fyp_iam.engine1.foundry.ontology import ONTOLOGY_VERSION
from fyp_iam.engine1.foundry.verifier import PROMPT_VERSION

_Citation = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")]
_Finding = Annotated[str, Field(min_length=1, max_length=2000)]
_Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class VerifierEvidence(BaseModel):
    """Immutable public-source excerpt. Instructions in text remain untrusted data."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_id: _Citation
    source_key: Literal["mitre-attack", "aws-service-reference", "stratus-red-team"]
    source_version: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1, max_length=4096)
    content_hash: _Digest

    @model_validator(mode="after")
    def valid_content(self) -> VerifierEvidence:
        reject_sensitive_text(self.text)
        reject_sensitive_text(self.source_version)
        if not self.text.strip() or not self.source_version.strip():
            raise ValueError("blank evidence metadata or text")
        if self.content_hash != "sha256:" + hashlib.sha256(self.text.encode()).hexdigest():
            raise ValueError("evidence content hash mismatch")
        return self


class VerifierRequest(BaseModel):
    """Bounded frozen input; hash binds selected bytes, not their truth or completeness."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    candidate_version_id: _Citation
    candidate_semantic_hash: _Digest
    candidate_json: str = Field(min_length=1, max_length=32768)
    evidence_snapshot_hash: _Digest
    ontology_version: str = Field(min_length=1, max_length=64)
    prompt_version: str = Field(min_length=1, max_length=64)
    evidence: tuple[VerifierEvidence, ...] = Field(min_length=1, max_length=64)

    @field_validator("candidate_json")
    @classmethod
    def canonical_rule(cls, value: str) -> str:
        return ApprovedRule.model_validate_json(value).model_dump_json()

    @model_validator(mode="after")
    def bound_request(self) -> VerifierRequest:
        if self.ontology_version != ONTOLOGY_VERSION or self.prompt_version != PROMPT_VERSION:
            raise ValueError("unsupported verifier request version")
        if (
            self.candidate_semantic_hash
            != "sha256:" + hashlib.sha256(self.candidate_json.encode()).hexdigest()
        ):
            raise ValueError("candidate semantic hash mismatch")
        ids = [item.evidence_id for item in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate selected evidence")
        rule = ApprovedRule.model_validate_json(self.candidate_json)
        if not set(rule.evidence_refs).issubset(ids):
            raise ValueError("candidate evidence references are not selected")
        if len(self.model_dump_json().encode()) > 65536:
            raise ValueError("verifier request exceeds byte limit")
        return self

    @property
    def request_hash(self) -> str:
        encoded = json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


_UNSAFE_OUTPUT = re.compile(
    r"```|<\s*script\b|javascript:|onerror\s*=|"
    r"\baws\s+[a-z0-9-]+\s+[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b|"
    r"\b(?:terraform|powershell|pwsh|curl|wget)\s+|"
    r"\b(?:subprocess|boto3)\s*[.(]|os\.system|\b(?:exec|eval)\s*\(|"
    r"\b(?:MATCH|MERGE|CREATE)\s*\(|"
    r"\b(?:ignore|override|disregard)\s+(?:all\s+)?(?:previous|prior|system|the\s+validators)\b",
    re.IGNORECASE,
)


def _review_text(value: str) -> str:
    """Conservative output filter, not a complete prompt-injection detector."""
    cleaned = reject_sensitive_text(value).strip()
    if not cleaned or _UNSAFE_OUTPUT.search(cleaned):
        raise ValueError("verifier text is blank or contains disallowed output markers")
    return cleaned


def _unique_citations(values: list[str]) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError("duplicate verifier citation")
    return values


class VerifierSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=1000)
    citations: list[_Citation] = Field(min_length=1, max_length=128)

    @field_validator("text")
    @classmethod
    def safe_text(cls, value: str) -> str:
        return _review_text(value)

    @field_validator("citations")
    @classmethod
    def unique_citations(cls, values: list[str]) -> list[str]:
        return _unique_citations(values)


class VerifierResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=64)
    prompt_version: str = Field(min_length=1, max_length=64)
    schema_version: Literal["0.1"]
    candidate_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
    evidence_snapshot_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    request_hash: _Digest | None = None
    verdict: Literal["pass", "needs_review", "reject"]
    findings: list[_Finding] = Field(min_length=1, max_length=50)
    citations: list[_Citation] = Field(min_length=1, max_length=128)
    suggestions: list[VerifierSuggestion] = Field(default_factory=list, max_length=20)

    @field_validator("provider", "model", "prompt_version")
    @classmethod
    def safe_metadata(cls, value: str) -> str:
        return _review_text(value)

    @field_validator("findings")
    @classmethod
    def safe_findings(cls, values: list[str]) -> list[str]:
        return [_review_text(value) for value in values]

    @field_validator("citations")
    @classmethod
    def unique_citations(cls, values: list[str]) -> list[str]:
        return _unique_citations(values)


class VerifierEvidenceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    evidence_id: _Citation
    source_key: Literal["mitre-attack", "aws-service-reference", "stratus-red-team"]
    source_version: str = Field(min_length=1, max_length=128)
    content_hash: _Digest


class VerifierRecordSummary(BaseModel):
    """Rechecked record metadata, not source/candidate payload disclosure."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    packet_id: _Citation
    pipeline_run_id: _Citation
    recorded_at: datetime
    rule_version_id: _Citation
    rule_semantic_hash: _Digest
    evidence_snapshot_hash: _Digest
    request_hash: _Digest
    response_hash: _Digest
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=64)
    prompt_version: str = Field(min_length=1, max_length=64)
    ontology_version: str = Field(min_length=1, max_length=64)
    verdict: Literal["pass", "needs_review", "reject"]
    findings: list[_Finding] = Field(min_length=1, max_length=50)
    citations: list[_Citation] = Field(min_length=1, max_length=128)
    evidence: list[VerifierEvidenceSummary] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def checked_metadata(self) -> VerifierRecordSummary:
        for value in (self.provider, self.model, self.prompt_version, self.ontology_version):
            _review_text(value)
        for finding in self.findings:
            _review_text(finding)
        ids = [item.evidence_id for item in self.evidence]
        if (
            len(ids) != len(set(ids))
            or len(self.citations) != len(set(self.citations))
            or not set(self.citations).issubset(ids)
            or self.recorded_at.tzinfo is None
        ):
            raise ValueError("invalid verifier summary metadata")
        return self


def checked_verification(
    raw: dict[str, object],
    *,
    version_id: str,
    evidence_hash: str,
    evidence_ids: list[str],
    request_hash: str | None = None,
) -> dict[str, object]:
    """Normalize a verifier response or return a non-publishing review result."""

    try:
        response = VerifierResponse.model_validate(raw)
    except ValidationError:
        return _invalid_result()
    cited = set(response.citations)
    if (
        response.candidate_version_id != version_id
        or response.prompt_version != PROMPT_VERSION
        or response.evidence_snapshot_hash != evidence_hash
        or response.request_hash != request_hash
        or not cited.issubset(evidence_ids)
        or any(not set(item.citations).issubset(evidence_ids) for item in response.suggestions)
    ):
        return _invalid_result()
    body = response.model_dump(exclude_none=True)
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
