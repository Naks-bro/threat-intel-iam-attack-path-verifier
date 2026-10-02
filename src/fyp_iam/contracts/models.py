"""Proposed v0.1 contracts plus the local-slice fields recorded in ADR-004.

These models are precise enough for fixtures and tests. They are not an accepted
team contract until an ADR marks them accepted.
"""

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_SENSITIVE = re.compile(
    r"arn:aws:|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|aws_secret_access_key",
    re.IGNORECASE,
)
_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$"
_KEY = r"^[A-Za-z0-9_.:-]{1,64}$"


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def reject_sensitive_text(value: str) -> str:
    if _SENSITIVE.search(value):
        raise ValueError("value contains a disallowed credential or ARN marker")
    return value


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RuleStatus(StrEnum):
    draft = "draft"
    proposed = "proposed"
    approved = "approved"
    rejected = "rejected"
    deprecated = "deprecated"
    superseded = "superseded"


class ApprovalDecision(StrEnum):
    approved = "approved"
    rejected = "rejected"
    pending = "pending"


class Severity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class CreatorKind(StrEnum):
    human = "human"
    hybrid = "hybrid"
    deterministic = "deterministic"


class NodeType(StrEnum):
    principal = "principal"
    policy = "policy"
    resource = "resource"
    account = "account"
    organization_unit = "organization_unit"
    service = "service"


class EdgeType(StrEnum):
    MEMBER_OF = "MEMBER_OF"
    HAS_POLICY = "HAS_POLICY"
    HAS_BOUNDARY = "HAS_BOUNDARY"
    TRUSTS = "TRUSTS"
    CAN_ASSUME = "CAN_ASSUME"
    CAN_PASS_ROLE = "CAN_PASS_ROLE"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_MODIFY_POLICY = "CAN_MODIFY_POLICY"
    CAN_CREATE_AS = "CAN_CREATE_AS"


class AuthorizationEffect(StrEnum):
    allow = "allow"
    deny = "deny"


class EdgeConfidence(StrEnum):
    deterministic = "deterministic"
    unknown = "unknown"


class SnapshotValidationStatus(StrEnum):
    valid = "valid"
    valid_with_warnings = "valid_with_warnings"
    invalid = "invalid"


class VerificationStatus(StrEnum):
    supported_by_fixture = "supported_by_fixture"
    denied_by_fixture = "denied_by_fixture"
    inconclusive = "inconclusive"
    error = "error"
    verified_in_mapped_sandbox = "verified_in_mapped_sandbox"
    supported_by_policy_simulation = "supported_by_policy_simulation"
    denied_by_policy_simulation = "denied_by_policy_simulation"
    not_applicable = "not_applicable"


class ConditionResolution(StrEnum):
    """Explicit fixture context. Condition key values are not IAM-evaluated."""

    satisfied = "satisfied"
    unsatisfied = "unsatisfied"
    unsupported = "unsupported"


class ReviewState(StrEnum):
    open = "open"


IdStr = Annotated[str, Field(pattern=_ID)]
Text = Annotated[str, Field(min_length=1, max_length=4000)]


class TechniqueRef(ContractModel):
    framework: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    external_id: str = Field(pattern=r"^[A-Za-z0-9._:-]{1,64}$")
    version: str = Field(min_length=1, max_length=64)


class ResourceSelector(ContractModel):
    kind: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    constraint: str = Field(min_length=1, max_length=128)


class RequiredCapability(ContractModel):
    action: str = Field(pattern=r"^[a-z0-9*]+:[A-Za-z0-9*]+$")
    resource_selector: ResourceSelector


class Precondition(ContractModel):
    type: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    subject: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=200)

    @field_validator("value")
    @classmethod
    def clean_value(cls, value: str) -> str:
        return reject_sensitive_text(value)


class PatternStep(ContractModel):
    from_role: str = Field(alias="from", min_length=1, max_length=128)
    relationship: EdgeType
    to_role: str = Field(alias="to", min_length=1, max_length=128)


class Approval(ContractModel):
    decision: ApprovalDecision
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
        return reject_sensitive_text(value)


class CreatedBy(ContractModel):
    kind: CreatorKind
    model_or_method: str = Field(min_length=1, max_length=128)


class ApprovedRule(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    rule_id: IdStr
    rule_version: int = Field(ge=1, le=1000)
    title: str = Field(min_length=1, max_length=200)
    description: Text
    status: RuleStatus
    severity: Severity
    technique_refs: list[TechniqueRef] = Field(min_length=1, max_length=20)
    required_capabilities: list[RequiredCapability] = Field(min_length=1, max_length=20)
    preconditions: list[Precondition] = Field(default_factory=list, max_length=20)
    path_pattern: list[PatternStep] = Field(min_length=1, max_length=8)
    evidence_refs: list[IdStr] = Field(min_length=1, max_length=50)
    limitations: list[str] = Field(min_length=1, max_length=20)
    approval: Approval
    created_by: CreatedBy
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def utc_created_at(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("title", "description")
    @classmethod
    def clean_text(cls, value: str) -> str:
        return reject_sensitive_text(value)

    @field_validator("limitations")
    @classmethod
    def clean_limitations(cls, value: list[str]) -> list[str]:
        return [reject_sensitive_text(item) for item in value]

    @model_validator(mode="after")
    def approval_matches_status(self) -> "ApprovedRule":
        approved = self.approval.decision == ApprovalDecision.approved
        if self.status == RuleStatus.approved and not approved:
            raise ValueError("approved rules require approval.decision == approved")
        if self.status != RuleStatus.approved and approved:
            raise ValueError("approval.decision approved requires status approved")
        return self


class SnapshotScope(ContractModel):
    provider: str = Field(pattern=r"^aws$")
    account_alias: str = Field(min_length=1, max_length=64)
    regions: list[str] = Field(min_length=1, max_length=20)
    collected_at: datetime

    @field_validator("account_alias")
    @classmethod
    def alias_not_account_id(cls, value: str) -> str:
        cleaned = reject_sensitive_text(value)
        if re.fullmatch(r"\d{12}", cleaned):
            raise ValueError("use an account alias, not an AWS account ID")
        return cleaned

    @field_validator("regions")
    @classmethod
    def region_names(cls, value: list[str]) -> list[str]:
        for region in value:
            if not re.fullmatch(r"global|[a-z]{2}-[a-z]+-\d", region):
                raise ValueError("unsupported region label")
        return value

    @field_validator("collected_at")
    @classmethod
    def utc_collected_at(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class GraphNode(ContractModel):
    node_id: IdStr
    node_type: NodeType
    subtype: str | None = Field(default=None, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    arn_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    properties: dict[str, str | int | bool] = Field(default_factory=dict)

    @field_validator("display_name")
    @classmethod
    def clean_display_name(cls, value: str) -> str:
        return reject_sensitive_text(value)

    @field_validator("subtype")
    @classmethod
    def clean_subtype(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[a-z0-9_]{1,64}", value):
            raise ValueError("invalid subtype")
        return value

    @field_validator("properties")
    @classmethod
    def clean_properties(cls, value: dict[str, str | int | bool]) -> dict[str, str | int | bool]:
        for key, item in value.items():
            if not re.fullmatch(_KEY, key):
                raise ValueError("invalid property key")
            if isinstance(item, str):
                reject_sensitive_text(item)
                if len(item) > 200:
                    raise ValueError("property value is too long")
        return value


class GraphEdge(ContractModel):
    edge_id: IdStr
    edge_type: EdgeType
    source_id: IdStr
    target_id: IdStr
    derivation: str = Field(pattern=r"^policy_analysis$")
    policy_refs: list[IdStr] = Field(min_length=1, max_length=20)
    condition_summary: dict[str, str] = Field(default_factory=dict)
    confidence: EdgeConfidence
    effect: AuthorizationEffect = AuthorizationEffect.allow

    @field_validator("condition_summary")
    @classmethod
    def clean_conditions(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not re.fullmatch(_KEY, key):
                raise ValueError("invalid condition key")
            reject_sensitive_text(item)
            if len(item) > 200:
                raise ValueError("condition value is too long")
        return value


class PolicyDocumentRef(ContractModel):
    policy_id: IdStr
    content_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    redacted: bool = Field(json_schema_extra={"const": True})

    @field_validator("redacted")
    @classmethod
    def must_be_redacted(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("policy documents must be redacted references, not raw documents")
        return value


class CollectionInfo(ContractModel):
    collector_version: str = Field(min_length=1, max_length=64)
    permissions_profile: str = Field(min_length=1, max_length=128)
    complete: bool
    warnings: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("warnings")
    @classmethod
    def clean_warnings(cls, value: list[str]) -> list[str]:
        return [reject_sensitive_text(item) for item in value]


class ValidationReport(ContractModel):
    status: SnapshotValidationStatus
    errors: list[str] = Field(default_factory=list, max_length=50)
    warnings: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def invalid_requires_error(self) -> "ValidationReport":
        if self.status == SnapshotValidationStatus.invalid and not self.errors:
            raise ValueError("invalid snapshots must record at least one error")
        return self


class IAMGraphSnapshot(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    snapshot_id: IdStr
    scope: SnapshotScope
    nodes: list[GraphNode] = Field(min_length=1, max_length=500)
    edges: list[GraphEdge] = Field(default_factory=list, max_length=2000)
    policy_documents: list[PolicyDocumentRef] = Field(default_factory=list, max_length=200)
    collection: CollectionInfo
    validation: ValidationReport

    @model_validator(mode="after")
    def graph_integrity(self) -> "IAMGraphSnapshot":
        node_ids = [node.node_id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("duplicate node_id")
        edge_ids = [edge.edge_id for edge in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("duplicate edge_id")
        known = set(node_ids)
        semantic: set[tuple[str, str, str, str]] = set()
        for edge in self.edges:
            if edge.source_id == edge.target_id:
                raise ValueError("edges must not be self-loops")
            if edge.source_id not in known or edge.target_id not in known:
                raise ValueError("edge endpoint is not in the snapshot")
            key = (edge.source_id, edge.target_id, edge.edge_type.value, edge.effect.value)
            if key in semantic:
                raise ValueError("duplicate semantic edge")
            semantic.add(key)
        return self


class DiscoveryLimits(ContractModel):
    max_hops: int = Field(default=4, ge=1, le=32)
    max_paths_per_start: int = Field(default=100, ge=1, le=1000)
    max_paths: int = Field(default=100, ge=1, le=1000)
    timeout_ms: int = Field(default=5000, ge=0, le=60_000)
    max_expansions: int = Field(default=10_000, ge=0, le=100_000)


class AttackHop(ContractModel):
    position: int = Field(ge=0)
    edge_id: IdStr
    required_action: str = Field(
        min_length=1,
        max_length=64,
        description="Graph edge-type label. This is not an AWS API call.",
    )
    resource: IdStr
    effect: AuthorizationEffect
    condition_keys: list[str] = Field(default_factory=list, max_length=20)


class DiscoveryInfo(ContractModel):
    algorithm: str = Field(pattern=r"^bounded_bfs$")
    max_hops: int = Field(ge=1, le=32)
    limits: DiscoveryLimits


class RuleRef(ContractModel):
    rule_id: IdStr
    rule_version: int = Field(ge=1)


class AttackPath(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    path_id: IdStr
    snapshot_id: IdStr
    rule_refs: list[RuleRef] = Field(min_length=1, max_length=20)
    start_node_id: IdStr
    goal_node_id: IdStr
    hops: list[AttackHop] = Field(min_length=1, max_length=32)
    discovery: DiscoveryInfo
    deduplication_key: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class PolicySimulation(ContractModel):
    status: str = Field(pattern=r"^not_run$")
    evaluations: list[str] = Field(default_factory=list, max_length=50)
    missing_context: list[str] = Field(default_factory=list, max_length=50)
    unsupported_controls: list[str] = Field(default_factory=list, max_length=50)


class SandboxCheck(ContractModel):
    status: str = Field(pattern=r"^not_mapped$")
    scenario_id: None = None
    run_id: None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class LocalFixtureCheck(ContractModel):
    adapter: str = Field(pattern=r"^local_fixture$")
    missing_context: list[str] = Field(default_factory=list, max_length=50)
    unsupported_conditions: list[str] = Field(default_factory=list, max_length=50)
    denied_edge_ids: list[str] = Field(default_factory=list, max_length=32)
    notes: list[str] = Field(default_factory=list, max_length=20)


class VerificationResult(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    verification_id: IdStr
    path_id: IdStr
    status: VerificationStatus
    policy_simulation: PolicySimulation
    sandbox: SandboxCheck
    local_fixture: LocalFixtureCheck
    evidence_refs: list[IdStr] = Field(default_factory=list, max_length=50)
    limitations: list[str] = Field(min_length=1, max_length=20)
    started_at: datetime
    finished_at: datetime

    @field_validator("started_at", "finished_at")
    @classmethod
    def utc_times(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class PriorityFeatures(ContractModel):
    severity: Severity
    verification_status: VerificationStatus
    hop_count: int = Field(ge=0)
    explicit_deny_count: int = Field(ge=0)
    missing_context_count: int = Field(ge=0)
    collection_complete: bool


class PriorityModel(ContractModel):
    name: str = Field(pattern=r"^baseline-v1$")
    features: PriorityFeatures
    score: float = Field(ge=0, le=1)


class FindingExplanation(ContractModel):
    what: str = Field(min_length=1, max_length=2000)
    why: str = Field(min_length=1, max_length=4000)
    evidence: list[IdStr] = Field(min_length=1, max_length=50)
    verification_status: VerificationStatus
    simulator: str = Field(pattern=r"^not_run$")
    sandbox: str = Field(pattern=r"^not_mapped$")


class RemediationProposal(ContractModel):
    proposal: str = Field(min_length=1, max_length=1000)
    requires_human_review: bool = True

    @field_validator("requires_human_review")
    @classmethod
    def human_review_required(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("remediation proposals require human review")
        return value


class Finding(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    finding_id: IdStr
    verification_id: IdStr
    priority: Severity
    priority_model: PriorityModel
    summary: str = Field(min_length=1, max_length=1000)
    explanation: FindingExplanation
    remediation: list[RemediationProposal] = Field(min_length=1, max_length=10)
    review_state: ReviewState
