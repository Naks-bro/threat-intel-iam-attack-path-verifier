"""Request bodies for the local analysis API."""

from datetime import datetime

from pydantic import Field, field_validator

from fyp_iam.contracts.models import (
    ApprovedRule,
    ConditionResolution,
    ContractModel,
    DiscoveryLimits,
    IAMGraphSnapshot,
    ensure_utc,
)


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
