"""Request bodies for the local analysis API."""

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from fyp_iam.contracts.models import (
    ApprovedRule,
    ConditionResolution,
    ContractModel,
    DiscoveryLimits,
    IAMGraphSnapshot,
    RuleStatus,
    ensure_utc,
)
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine1.models import ApprovalEvent, NormalizedTechnique
from fyp_iam.engine2.coverage import NormalizationCoverage
from fyp_iam.engine2.records import SyntheticAccount


class AnalyzeRequest(ContractModel):
    rules: list[ApprovedRule] = Field(max_length=100)
    snapshot: IAMGraphSnapshot
    limits: DiscoveryLimits | None = None
    condition_resolutions: dict[str, ConditionResolution] = Field(default_factory=dict)
    evaluated_at: datetime | None = None

    @field_validator("evaluated_at")
    @classmethod
    def utc_evaluated_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return ensure_utc(value)


class SyntheticAnalyzeRequest(ContractModel):
    rules: list[ApprovedRule] = Field(min_length=1, max_length=100)
    account: SyntheticAccount
    limits: DiscoveryLimits | None = None
    condition_resolutions: dict[str, ConditionResolution] = Field(default_factory=dict)
    evaluated_at: datetime | None = None

    @field_validator("evaluated_at")
    @classmethod
    def utc_synthetic_evaluated_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return ensure_utc(value)


class SyntheticAnalyzeResponse(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    snapshot: IAMGraphSnapshot
    coverage: NormalizationCoverage
    report: AnalysisReport


class IntakeRequest(ContractModel):
    artifact_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")


class IntakeResponse(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    record: NormalizedTechnique
    candidate: ApprovedRule

    @model_validator(mode="after")
    def stays_unapproved(self) -> "IntakeResponse":
        if self.candidate.status == RuleStatus.approved:
            raise ValueError("intake does not export an approved rule")
        return self


class ApprovalRequest(ContractModel):
    artifact_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    decision: str = Field(pattern=r"^(approved|rejected)$")
    reviewer_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    decided_at: datetime
    comment: str = Field(min_length=1, max_length=1000)

    @field_validator("decided_at")
    @classmethod
    def utc_decided_at(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("comment")
    @classmethod
    def clean_comment(cls, value: str) -> str:
        if "<" in value or ">" in value:
            raise ValueError("approval comment was rejected")
        return value


class ApprovalResponse(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    event: ApprovalEvent
    exported_rule: ApprovedRule | None = None

    @model_validator(mode="after")
    def export_follows_decision(self) -> "ApprovalResponse":
        approved = self.event.decision == "approved"
        exported = self.exported_rule
        if approved and (exported is None or exported.status != RuleStatus.approved):
            raise ValueError("an approved decision must export an approved rule")
        if not approved and self.exported_rule is not None:
            raise ValueError("a rejected decision must not export a rule")
        return self
