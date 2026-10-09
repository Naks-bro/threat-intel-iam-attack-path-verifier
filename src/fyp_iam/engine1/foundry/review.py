"""Exact-version local-operator review contract, not authentication or publication."""

import hashlib
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fyp_iam.contracts.models import ensure_utc, reject_sensitive_text

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")]
ReviewScope = Literal[
    "read_only_account_analysis", "isolated_lab_validation", "synthetic_benchmark"
]


class ReviewCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: Identifier
    rule_version_id: Identifier
    rule_semantic_hash: Digest
    evidence_snapshot_hash: Digest
    quality_report_hash: Digest
    verifier_request_hash: Digest
    verifier_response_hash: Digest
    scope: ReviewScope
    decision: Literal["approved", "rejected", "revision_requested"]
    comment: str = Field(default="", max_length=2000)

    @field_validator("comment")
    @classmethod
    def safe_comment(cls, value: str) -> str:
        # Plain text only; no account credentials or raw AWS identifiers in history.
        reject_sensitive_text(value)
        if any(ord(char) < 32 and char not in "\n\t" for char in value):
            raise ValueError("review comment contains control characters")
        return value.strip()

    @model_validator(mode="after")
    def explained_nonapproval(self) -> "ReviewCommand":
        if self.decision != "approved" and not self.comment:
            raise ValueError("rejection and revision require a comment")
        return self


class ReviewRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    decision_id: Identifier
    command: ReviewCommand
    reviewer_alias: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    identity_boundary: Literal["local_operator_alias"] = "local_operator_alias"
    decided_at: datetime
    record_hash: Digest

    @field_validator("decided_at")
    @classmethod
    def timestamp(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def checked_hash(self) -> "ReviewRecord":
        reject_sensitive_text(self.reviewer_alias)
        if self.record_hash != review_record_hash(self):
            raise ValueError("review record hash mismatch")
        return self


def review_record_hash(record: ReviewRecord) -> str:
    return (
        "sha256:"
        + hashlib.sha256(record.model_dump_json(exclude={"record_hash"}).encode()).hexdigest()
    )


class ReviewState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    rule_version_id: Identifier
    scope: ReviewScope
    latest: ReviewRecord | None
    release_eligibility: Literal["not_evaluated"] = "not_evaluated"

    @model_validator(mode="after")
    def bound_state(self) -> "ReviewState":
        if self.latest is not None and (
            self.latest.command.rule_version_id != self.rule_version_id
            or self.latest.command.scope != self.scope
        ):
            raise ValueError("review state binding mismatch")
        return self
