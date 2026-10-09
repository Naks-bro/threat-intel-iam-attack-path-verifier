"""Local CTI records. These models are Proposed and are not an accepted cross-engine contract."""

import re
from datetime import datetime

from pydantic import Field, field_validator

from fyp_iam.contracts.models import ContractModel, IdStr, ensure_utc, reject_sensitive_text

_REFERENCE = re.compile(r"^https://attack\.mitre\.org/techniques/T[0-9]{4}/$")
_EXECUTABLE = re.compile(
    r"<\s*script|javascript:|onerror\s*=|\bcypher\b|match\s*\(|\bterraform\b|"
    r"\bsubprocess\b|\bboto3\b|os\.system|\bcurl\s|\bwget\s|\bpowershell\b|"
    r"\baws\s+iam\b|\baws\s+sts\b",
    re.IGNORECASE,
)


def reject_executable_text(value: str) -> str:
    cleaned = reject_sensitive_text(value)
    if _EXECUTABLE.search(cleaned):
        raise ValueError("value contains an executable or markup marker")
    return cleaned


class SourceArtifact(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    artifact_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    source_name: str = Field(pattern=r"^mitre-attack$")
    source_version: str = Field(min_length=1, max_length=64)
    retrieved_at: datetime
    official_reference: str
    license_note: str = Field(min_length=1, max_length=500)
    framework: str = Field(pattern=r"^mitre-attack$")
    external_id: str = Field(pattern=r"^T[0-9]{4}$")
    technique_name: str = Field(min_length=1, max_length=200)
    excerpt: str = Field(min_length=1, max_length=1000)
    excerpt_location: str = Field(pattern=r"^excerpt$")

    @field_validator("retrieved_at")
    @classmethod
    def utc_retrieved_at(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator(
        "source_version",
        "license_note",
        "technique_name",
        "excerpt",
        "official_reference",
    )
    @classmethod
    def clean_text(cls, value: str) -> str:
        return reject_executable_text(value)

    @field_validator("official_reference")
    @classmethod
    def official_host(cls, value: str) -> str:
        if _REFERENCE.fullmatch(value) is None:
            raise ValueError("official reference is not on the local allowlist")
        return value


class SourceProvenance(ContractModel):
    source_name: str = Field(pattern=r"^mitre-attack$")
    source_version: str = Field(min_length=1, max_length=64)
    retrieved_at: datetime
    official_reference: str
    license_note: str = Field(min_length=1, max_length=500)
    artifact_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("retrieved_at")
    @classmethod
    def utc_retrieved_at(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class NormalizedTechnique(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    record_id: IdStr
    provenance: SourceProvenance
    framework: str = Field(pattern=r"^mitre-attack$")
    external_id: str = Field(pattern=r"^T[0-9]{4}$")
    technique_name: str = Field(min_length=1, max_length=200)
    aws_iam_relevant: bool
    evidence_excerpt: str = Field(min_length=1, max_length=1000)
    evidence_location: str = Field(pattern=r"^excerpt$")


class ApprovalEvent(ContractModel):
    """Immutable human decision. Intake does not create this event."""

    schema_version: str = Field(pattern=r"^0\.1$")
    event_id: IdStr
    rule_id: IdStr
    rule_version: int = Field(ge=1, le=1000)
    artifact_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    decision: str = Field(pattern=r"^(approved|rejected)$")
    reviewer_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    decided_at: datetime
    comment: str = Field(min_length=1, max_length=1000)
    scope: str = Field(pattern=r"^synthetic-benchmark$")

    @field_validator("decided_at")
    @classmethod
    def utc_decided_at(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("comment")
    @classmethod
    def clean_comment(cls, value: str) -> str:
        return reject_executable_text(value)
