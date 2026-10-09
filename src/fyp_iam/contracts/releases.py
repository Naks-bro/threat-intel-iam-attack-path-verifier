"""Portable stable release contract; digests are integrity checks, not signatures."""

import hashlib
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fyp_iam.contracts.models import ApprovedRule, RuleStatus, ensure_utc, reject_sensitive_text

ReleaseScope = Literal[
    "read_only_account_analysis", "isolated_lab_validation", "synthetic_benchmark"
]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")]


class StableReleaseCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    request_id: Identifier
    rule_version_id: Identifier
    scope: ReleaseScope
    review_decision_id: Identifier
    review_record_hash: Digest


class StableRuleRelease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["0.1"] = "0.1"
    policy_version: Literal["local-benchmark-gate-0.1"] = "local-benchmark-gate-0.1"
    channel: Literal["stable"] = "stable"
    release_id: Identifier
    command: StableReleaseCommand
    rule_semantic_hash: Digest
    evidence_snapshot_hash: Digest
    quality_report_hash: Digest
    verifier_request_hash: Digest
    verifier_response_hash: Digest
    reviewer_alias: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    publisher_alias: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    identity_boundary: Literal["local_operator_alias"] = "local_operator_alias"
    reviewed_at: datetime
    published_at: datetime
    candidate_json: str = Field(min_length=1, max_length=32768)
    rule_json: str = Field(min_length=1, max_length=32768)
    record_hash: Digest

    @field_validator("candidate_json", "rule_json")
    @classmethod
    def canonical_rule(cls, value: str) -> str:
        return ApprovedRule.model_validate_json(value).model_dump_json()

    @field_validator("reviewed_at", "published_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def bound_release(self) -> "StableRuleRelease":
        candidate = ApprovedRule.model_validate_json(self.candidate_json)
        rule = ApprovedRule.model_validate_json(self.rule_json)
        if (
            self.command.scope != "synthetic_benchmark"
            or candidate.status != RuleStatus.proposed
            or rule.status != RuleStatus.approved
            or candidate.model_dump(exclude={"status", "approval"})
            != rule.model_dump(exclude={"status", "approval"})
            or self.rule_semantic_hash != digest(self.candidate_json)
            or rule.approval.reviewer_id != self.reviewer_alias
            or rule.approval.decided_at != self.reviewed_at
            or rule.approval.comment != approval_comment(self.command)
            or self.published_at < self.reviewed_at
            or self.record_hash != release_hash(self)
            or len(self.model_dump_json().encode()) > 131072
        ):
            raise ValueError("stable release binding mismatch")
        reject_sensitive_text(self.reviewer_alias)
        reject_sensitive_text(self.publisher_alias)
        return self


def approval_comment(command: StableReleaseCommand) -> str:
    return f"Approved for {command.scope}; exact review {command.review_decision_id}."


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def release_hash(release: StableRuleRelease) -> str:
    return digest(release.model_dump_json(exclude={"record_hash"}))
