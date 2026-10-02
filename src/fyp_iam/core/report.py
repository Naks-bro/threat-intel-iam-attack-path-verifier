"""Pipeline envelope. This is not a cross-engine evidence contract."""

from pydantic import Field

from fyp_iam.contracts.models import (
    AttackPath,
    ContractModel,
    DiscoveryLimits,
    Finding,
    IdStr,
    VerificationResult,
)


class AnalysisIssue(ContractModel):
    code: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    message: str = Field(min_length=1, max_length=500)
    rule_id: IdStr | None = None


class AnalysisReport(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    snapshot_id: IdStr
    findings: list[Finding]
    attack_paths: list[AttackPath]
    verifications: list[VerificationResult]
    issues: list[AnalysisIssue]
    limits: DiscoveryLimits
    truncation_reasons: list[str]
