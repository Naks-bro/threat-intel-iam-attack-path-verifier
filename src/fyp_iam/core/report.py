"""Pipeline envelope. This is not a cross-engine evidence contract."""

from pydantic import Field

from fyp_iam.contracts.models import (
    AttackPath,
    ContractModel,
    DiscoveryLimits,
    Finding,
    IdStr,
    RuleRef,
    VerificationResult,
)


class AnalysisIssue(ContractModel):
    code: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    message: str = Field(min_length=1, max_length=500)
    rule_id: IdStr | None = None


class AnalysisReport(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    snapshot_id: IdStr
    graph_input_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    start_node_id: IdStr | None = None
    input_rule_refs: list[RuleRef] = Field(default_factory=list)
    input_rule_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    findings: list[Finding]
    attack_paths: list[AttackPath]
    verifications: list[VerificationResult]
    issues: list[AnalysisIssue]
    limits: DiscoveryLimits
    truncation_reasons: list[str]
