"""Request bodies for the local analysis API."""

from datetime import datetime

from pydantic import Field, field_validator, model_validator

from fyp_iam.contracts.models import (
    ApprovedRule,
    ConditionResolution,
    ContractModel,
    DiscoveryLimits,
    IAMGraphSnapshot,
    IdStr,
    RuleStatus,
    ensure_utc,
)
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine1.foundry.quality import QualityReport
from fyp_iam.engine1.foundry.verifier_models import VerifierRecordSummary
from fyp_iam.engine1.models import ApprovalEvent, NormalizedTechnique
from fyp_iam.engine2.coverage import NormalizationCoverage
from fyp_iam.engine2.records import SyntheticAccount


class AnalyzeRequest(ContractModel):
    rules: list[ApprovedRule] = Field(max_length=100)
    snapshot: IAMGraphSnapshot
    start_node_id: IdStr | None = None
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
    start_node_id: IdStr | None = None
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


class FoundrySource(ContractModel):
    source_key: str
    authority_tier: int = Field(ge=1, le=3)
    source_type: str
    version_label: str
    enabled: bool
    last_status: str


class FoundryRun(ContractModel):
    status: str
    fetched_count: int = Field(ge=0)
    created_count: int = Field(ge=0)
    unchanged_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    parser_version: str


class FoundryPrimitive(ContractModel):
    primitive_key: str
    outcome_category: str
    required_actions: list[str]
    attack_mapping_state: str
    state_transition: str


class FoundryRelation(ContractModel):
    from_native_id: str
    to_native_id: str
    relation_type: str
    review_state: str
    rationale: str


class FoundryCandidate(ContractModel):
    rule_id: str
    version_id: str
    semantic_hash: str
    lifecycle: str
    channel: str


class FoundryOverviewResponse(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    database: str
    database_detail: str
    storage: str
    registry: str
    sources: list[FoundrySource]
    run: FoundryRun | None
    primitives: list[FoundryPrimitive]
    relations: list[FoundryRelation]
    candidates: list[FoundryCandidate]


class FoundryValidation(ContractModel):
    validator_name: str
    result: str
    optional: bool = False
    findings: list[str] = Field(default_factory=list)


class FoundryAIVerification(ContractModel):
    provider: str
    model: str
    verdict: str


class FoundryPublication(ContractModel):
    channel: str


class FoundryScenario(ContractModel):
    scenario_id: str
    case_class: str | None = None
    expect: str
    actual: str | None = None
    result: str


class FoundryRuleResponse(ContractModel):
    rule_id: str
    version_id: str
    semantic_hash: str
    lifecycle: str
    rule: dict[str, object]
    validations: list[FoundryValidation]
    ai_verification: FoundryAIVerification | None
    publication: FoundryPublication | None
    scenarios: list[FoundryScenario]
    quality_report: QualityReport | None = None
    verifier_record: VerifierRecordSummary | None = None

    @model_validator(mode="after")
    def quality_matches_version(self) -> "FoundryRuleResponse":
        verifier = self.verifier_record
        if verifier is not None and (
            verifier.rule_version_id != self.version_id
            or verifier.rule_semantic_hash != self.semantic_hash
            or (
                self.quality_report is not None
                and verifier.evidence_snapshot_hash != self.quality_report.evidence_snapshot_hash
            )
        ):
            raise ValueError("verifier record binding does not match the rule version")
        report = self.quality_report
        if report is not None and (
            report.rule_version_id != self.version_id
            or report.rule_semantic_hash != self.semantic_hash
        ):
            raise ValueError("quality report binding does not match the rule version")
        return self
