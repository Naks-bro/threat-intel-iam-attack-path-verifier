"""Small constructors shared by checked-in fixtures and tests."""

import hashlib
from datetime import UTC, datetime

from fyp_iam.contracts.models import (
    Approval,
    ApprovalDecision,
    ApprovedRule,
    AuthorizationEffect,
    CollectionInfo,
    CreatedBy,
    CreatorKind,
    EdgeConfidence,
    EdgeType,
    GraphEdge,
    GraphNode,
    IAMGraphSnapshot,
    NodeType,
    PatternStep,
    Precondition,
    RequiredCapability,
    ResourceSelector,
    RuleStatus,
    Severity,
    SnapshotScope,
    SnapshotValidationStatus,
    TechniqueRef,
    ValidationReport,
)

EVALUATED_AT = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def synthetic_arn_hash(node_id: str) -> str:
    digest = hashlib.sha256(f"synthetic:{node_id}".encode()).hexdigest()
    return f"sha256:{digest}"


def make_node(
    node_id: str,
    node_type: NodeType,
    display_name: str,
    *,
    subtype: str | None = None,
    properties: dict[str, str | int | bool] | None = None,
) -> GraphNode:
    return GraphNode(
        node_id=node_id,
        node_type=node_type,
        subtype=subtype,
        display_name=display_name,
        arn_hash=synthetic_arn_hash(node_id),
        properties=properties or {},
    )


def make_edge(
    edge_id: str,
    edge_type: EdgeType,
    source_id: str,
    target_id: str,
    policy_ref: str,
    *,
    effect: AuthorizationEffect = AuthorizationEffect.allow,
    conditions: dict[str, str] | None = None,
    confidence: EdgeConfidence = EdgeConfidence.deterministic,
) -> GraphEdge:
    return GraphEdge(
        edge_id=edge_id,
        edge_type=edge_type,
        source_id=source_id,
        target_id=target_id,
        derivation="policy_analysis",
        policy_refs=[policy_ref],
        condition_summary=conditions or {},
        confidence=confidence,
        effect=effect,
    )


def make_snapshot(
    snapshot_id: str,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    *,
    complete: bool = True,
    warnings: list[str] | None = None,
    validation_status: SnapshotValidationStatus = SnapshotValidationStatus.valid,
    validation_errors: list[str] | None = None,
) -> IAMGraphSnapshot:
    return IAMGraphSnapshot(
        schema_version="0.1",
        snapshot_id=snapshot_id,
        scope=SnapshotScope(
            provider="aws",
            account_alias="synthetic-lab",
            regions=["global"],
            collected_at=EVALUATED_AT,
        ),
        nodes=nodes,
        edges=edges,
        policy_documents=[],
        collection=CollectionInfo(
            collector_version="local-fixture-0.1",
            permissions_profile="none-synthetic-fixture",
            complete=complete,
            warnings=warnings or [],
        ),
        validation=ValidationReport(
            status=validation_status,
            errors=validation_errors or [],
            warnings=[],
        ),
    )


def assume_chain_rule(
    rule_id: str,
    *,
    preconditions: list[Precondition] | None = None,
    status: RuleStatus = RuleStatus.approved,
) -> ApprovedRule:
    decision = (
        ApprovalDecision.approved if status == RuleStatus.approved else ApprovalDecision.rejected
    )
    return ApprovedRule(
        schema_version="0.1",
        rule_id=rule_id,
        rule_version=1,
        title="Two-hop role assumption to an administrative role",
        description=(
            "A principal may reach another role through two derived CAN_ASSUME edges. "
            "The description is data and is never executed."
        ),
        status=status,
        severity=Severity.high,
        technique_refs=[
            TechniqueRef(
                framework="mitre-attack",
                external_id="T1548",
                version="pinned-at-fixture",
            )
        ],
        required_capabilities=[
            RequiredCapability(
                action="sts:AssumeRole",
                resource_selector=ResourceSelector(kind="role", constraint="derived_edge"),
            )
        ],
        preconditions=preconditions or [],
        path_pattern=[
            PatternStep(from_role="principal", relationship=EdgeType.CAN_ASSUME, to_role="mid"),
            PatternStep(from_role="mid", relationship=EdgeType.CAN_ASSUME, to_role="admin_role"),
        ],
        evidence_refs=[f"evidence_{rule_id}"],
        limitations=[
            "This rule matches derived graph edges only. It does not evaluate IAM policy JSON."
        ],
        approval=Approval(
            decision=decision,
            reviewer_id="reviewer_alias",
            decided_at=EVALUATED_AT,
            comment="Approved for the synthetic benchmark only.",
        ),
        created_by=CreatedBy(kind=CreatorKind.human, model_or_method="hand-authored-fixture"),
        created_at=EVALUATED_AT,
    )


def principal(node_id: str, display_name: str, subtype: str) -> GraphNode:
    return make_node(node_id, NodeType.principal, display_name, subtype=subtype)
