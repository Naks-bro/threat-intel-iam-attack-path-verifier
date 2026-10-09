"""Proposed handoff metadata for a read-only AWS collection run.

This is not a policy document, graph snapshot, or effective-permission verdict.
It contains no raw AWS account ID, ARN, credential, or policy body.
"""

import re
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from fyp_iam.contracts.models import ContractModel, IdStr, ensure_utc, reject_sensitive_text

_ACCOUNT_ID = re.compile(r"\b\d{12}\b")
_CODE = r"^[a-z][a-z0-9_]{0,63}$"
_OPERATION = r"^(iam|organizations):(?:Get|List|Describe)[A-Za-z0-9]{1,64}$"
_HMAC = r"^hmac-sha256:[0-9a-f]{64}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"


class CollectionOutcome(StrEnum):
    succeeded = "succeeded"
    partial = "partial"


class TaskOutcome(StrEnum):
    succeeded = "succeeded"
    partial = "partial"
    denied = "denied"
    throttled = "throttled"
    failed = "failed"


class PolicyLayer(StrEnum):
    identity_policy = "identity_policy"
    trust_policy = "trust_policy"
    permissions_boundary = "permissions_boundary"
    service_control_policy = "service_control_policy"
    resource_control_policy = "resource_control_policy"
    session_policy = "session_policy"
    resource_policy = "resource_policy"


class CoverageState(StrEnum):
    collected = "collected"
    absent = "absent"
    partial = "partial"
    not_collected = "not_collected"
    unavailable = "unavailable"


def _safe_label(value: str) -> str:
    if _ACCOUNT_ID.search(value):
        raise ValueError("raw account identifier is not allowed")
    return reject_sensitive_text(value)


class CollectionTask(ContractModel):
    operation: str = Field(pattern=_OPERATION)
    subject_principal_key: str | None = Field(default=None, pattern=r"^p_[0-9a-f]{32}$")
    subject_policy_fingerprint: str | None = Field(default=None, pattern=_HMAC)
    attempt: int = Field(ge=1, le=10)
    outcome: TaskOutcome
    page_count: int = Field(ge=0)
    item_count: int = Field(ge=0)
    pagination_complete: bool
    response_digest: str | None = Field(default=None, pattern=_DIGEST)
    error_code: str | None = Field(default=None, pattern=_CODE)

    @model_validator(mode="after")
    def consistent_outcome(self) -> "CollectionTask":
        if self.subject_principal_key is not None and self.subject_policy_fingerprint is not None:
            raise ValueError("task must have at most one subject")
        if self.outcome == TaskOutcome.succeeded and (
            not self.pagination_complete or self.error_code is not None
        ):
            raise ValueError("successful task must have complete pagination and no error")
        if self.outcome != TaskOutcome.succeeded and self.error_code is None:
            raise ValueError("incomplete task needs a sanitized error code")
        return self


class LayerCoverage(ContractModel):
    layer: PolicyLayer
    state: CoverageState
    authorization_evaluated: Literal[False] = False
    object_count: int | None = Field(default=None, ge=0)
    reason_code: str | None = Field(default=None, pattern=_CODE)

    @model_validator(mode="after")
    def consistent_coverage(self) -> "LayerCoverage":
        if self.state == CoverageState.absent and self.object_count != 0:
            raise ValueError("absent means checked and zero objects found")
        if self.state == CoverageState.collected and self.object_count is None:
            raise ValueError("collected layer needs a count")
        if (
            self.state
            in {
                CoverageState.partial,
                CoverageState.not_collected,
                CoverageState.unavailable,
            }
            and self.reason_code is None
        ):
            raise ValueError("incomplete layer needs a reason code")
        if self.state in {CoverageState.not_collected, CoverageState.unavailable} and (
            self.object_count is not None
        ):
            raise ValueError("unread layer cannot claim an object count")
        return self


class CollectionManifest(ContractModel):
    """Sealed run summary; source records are a separate, future contract."""

    schema_version: Literal["0.1"] = "0.1"
    data_kind: Literal["synthetic", "real_account_observed"]
    run_id: IdStr
    snapshot_id: IdStr
    account_alias: str = Field(min_length=1, max_length=80)
    account_fingerprint: str = Field(pattern=_HMAC)
    collector_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")
    started_at: datetime
    sealed_at: datetime
    outcome: CollectionOutcome
    snapshot_digest: str = Field(pattern=_DIGEST)
    tasks: list[CollectionTask] = Field(min_length=1, max_length=1000)
    coverage: list[LayerCoverage] = Field(min_length=len(PolicyLayer), max_length=len(PolicyLayer))

    @field_validator("account_alias", "run_id", "snapshot_id", "collector_version")
    @classmethod
    def safe_identifiers(cls, value: str) -> str:
        return _safe_label(value)

    @field_validator("started_at", "sealed_at")
    @classmethod
    def utc_time(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def sealed_consistency(self) -> "CollectionManifest":
        if self.sealed_at < self.started_at:
            raise ValueError("seal precedes collection start")
        layers = [item.layer for item in self.coverage]
        if len(set(layers)) != len(PolicyLayer):
            raise ValueError("coverage must name each policy layer exactly once")
        if self.outcome == CollectionOutcome.succeeded and any(
            item.outcome != TaskOutcome.succeeded for item in self.tasks
        ):
            raise ValueError("successful run contains an incomplete task")
        if self.outcome == CollectionOutcome.partial and all(
            item.outcome == TaskOutcome.succeeded for item in self.tasks
        ):
            raise ValueError("partial run must identify an incomplete task")
        return self
