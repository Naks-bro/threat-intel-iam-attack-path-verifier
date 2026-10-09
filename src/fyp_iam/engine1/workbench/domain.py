"""Workbench records. These types do not import a database driver."""

from datetime import datetime

from pydantic import Field, field_validator

from fyp_iam.contracts.models import ContractModel, ensure_utc


class WorkbenchSnapshot(ContractModel):
    """One pinned technique after normalize and deterministic validation."""

    pin_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    source_name: str = Field(min_length=1, max_length=64)
    source_version: str = Field(min_length=1, max_length=64)
    official_reference: str
    retrieved_at: datetime
    content_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    byte_count: int = Field(ge=1)
    record_id: str = Field(min_length=1, max_length=80)
    technique_id: str = Field(pattern=r"^T[0-9]{4}$")
    technique_name: str = Field(min_length=1, max_length=200)
    parser_version: str = Field(pattern=r"^allowlisted-technique-map-0\.1$")
    aws_iam_relevant: bool
    lifecycle: str = Field(pattern=r"^(needs_review|unsupported)$")
    rule_id: str | None = None
    rule_version: int | None = Field(default=None, ge=1, le=1000)
    rule_json: str | None = None
    validation_status: str = Field(pattern=r"^(passed|unsupported)$")
    explanation: str = Field(min_length=1, max_length=2000)
    limitations: list[str] = Field(min_length=1, max_length=8)

    @field_validator("retrieved_at")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class WorkbenchView(ContractModel):
    """Read model for the pending-review screen."""

    schema_version: str = Field(pattern=r"^0\.1$")
    pin_id: str
    technique_id: str
    technique_name: str
    official_reference: str
    artifact_sha256: str
    normalized_record_id: str
    lifecycle: str = Field(pattern=r"^(needs_review|unsupported)$")
    rule_id: str | None = None
    rule_version: int | None = None
    validation_status: str
    explanation: str
    limitations: list[str]
    persisted: bool
    storage: str = Field(pattern=r"^(not_written|postgres)$")
