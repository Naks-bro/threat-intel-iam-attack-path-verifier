"""Transparent baseline findings. Ranking is not verification."""

from fyp_iam.contracts.models import (
    ApprovedRule,
    AttackPath,
    Finding,
    FindingExplanation,
    IAMGraphSnapshot,
    PriorityFeatures,
    PriorityModel,
    RemediationProposal,
    ReviewState,
    Severity,
    VerificationResult,
    VerificationStatus,
)
from fyp_iam.core.ids import stable_id

_SEVERITY_WEIGHT = {
    Severity.low: 0.25,
    Severity.medium: 0.5,
    Severity.high: 0.75,
    Severity.critical: 1.0,
}
_STATUS_WEIGHT = {
    VerificationStatus.supported_by_fixture: 1.0,
    VerificationStatus.denied_by_fixture: 0.25,
    VerificationStatus.inconclusive: 0.5,
    VerificationStatus.error: 0.0,
}
_PRIORITY_RANK = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
}


def priority_rank(priority: Severity) -> int:
    return _PRIORITY_RANK[priority]


def build_finding(
    snapshot: IAMGraphSnapshot,
    rule: ApprovedRule,
    path: AttackPath,
    verification: VerificationResult,
) -> Finding:
    status = verification.status
    if status not in _STATUS_WEIGHT:
        raise ValueError("findings require a local fixture verification status")
    priority = _priority_label(rule.severity, status)
    features = PriorityFeatures(
        severity=rule.severity,
        verification_status=status,
        hop_count=len(path.hops),
        explicit_deny_count=len(verification.local_fixture.denied_edge_ids),
        missing_context_count=len(verification.local_fixture.missing_context),
        collection_complete=snapshot.collection.complete,
    )
    score = round(_SEVERITY_WEIGHT[rule.severity] * _STATUS_WEIGHT[status], 4)
    techniques = ", ".join(ref.external_id for ref in rule.technique_refs)
    hop_text = _hop_text(snapshot, path)
    gaps = _gaps(snapshot, verification)
    proposal = (
        "Review the derived edges cited by this finding and remove unintended trust "
        "or capability. This proposal is not applied automatically."
    )
    return Finding(
        schema_version="0.1",
        finding_id=stable_id("finding", verification.verification_id),
        verification_id=verification.verification_id,
        priority=priority,
        priority_model=PriorityModel(name="baseline-v1", features=features, score=score),
        summary=(
            f"Rule {rule.rule_id} matched a {len(path.hops)}-hop candidate. "
            f"Local fixture status: {status.value}."
        ),
        explanation=FindingExplanation(
            what=(
                f"Candidate path from {path.start_node_id} to {path.goal_node_id} "
                f"in snapshot {snapshot.snapshot_id}."
            ),
            why=(
                f"Approved rule {rule.rule_id} version {rule.rule_version} ({rule.title}) "
                f"matched technique refs {techniques}. Hops: {hop_text}. "
                f"Unknown or unsupported: {gaps}. "
                f"Simulator status is not_run. Sandbox status is not_mapped. "
                f"Fixture adapter status is {status.value}."
            ),
            evidence=verification.evidence_refs,
            verification_status=status,
            simulator="not_run",
            sandbox="not_mapped",
        ),
        remediation=[RemediationProposal(proposal=proposal, requires_human_review=True)],
        review_state=ReviewState.open,
    )


def _hop_text(snapshot: IAMGraphSnapshot, path: AttackPath) -> str:
    edges = {edge.edge_id: edge for edge in snapshot.edges}
    parts: list[str] = []
    for hop in path.hops:
        edge = edges.get(hop.edge_id)
        if edge is None:
            refs = "missing"
            conditions = "missing"
        else:
            refs = ",".join(edge.policy_refs) or "none"
            conditions = ",".join(sorted(edge.condition_summary)) or "none"
        parts.append(
            f"{hop.position}:{hop.edge_id}:{hop.required_action}:{hop.effect.value}"
            f":policies={refs}:conditions={conditions}"
        )
    return "; ".join(parts)


def _gaps(snapshot: IAMGraphSnapshot, verification: VerificationResult) -> str:
    local = verification.local_fixture
    parts: list[str] = []
    if local.missing_context:
        parts.append("missing=" + ",".join(local.missing_context))
    if local.unsupported_conditions:
        parts.append("unsupported=" + ",".join(local.unsupported_conditions))
    if local.denied_edge_ids:
        parts.append("denied=" + ",".join(local.denied_edge_ids))
    if local.notes:
        parts.append("notes=" + "; ".join(local.notes))
    if not snapshot.collection.complete:
        warnings = snapshot.collection.warnings or ["collection incomplete"]
        parts.append("collection_incomplete=" + "; ".join(warnings))
    return "; ".join(parts) if parts else "none"


def _priority_label(severity: Severity, status: VerificationStatus) -> Severity:
    if status == VerificationStatus.supported_by_fixture:
        return severity
    if status == VerificationStatus.inconclusive:
        return Severity.medium
    return Severity.low
