"""Local fixture verification. This module does not call AWS."""

from collections.abc import Mapping
from datetime import datetime

from fyp_iam.contracts.models import (
    ApprovedRule,
    AttackHop,
    AttackPath,
    AuthorizationEffect,
    ConditionResolution,
    DiscoveryInfo,
    EdgeConfidence,
    GraphEdge,
    IAMGraphSnapshot,
    LocalFixtureCheck,
    PolicySimulation,
    RuleRef,
    SandboxCheck,
    VerificationResult,
    VerificationStatus,
)
from fyp_iam.core.ids import sha256_key, stable_id
from fyp_iam.engine3.discovery import Walk, service_trust_edges

LOCAL_LIMITATION = (
    "Local fixture verification does not call AWS IAM Policy Simulator and is not "
    "sandbox verification."
)
NOT_EXPLOITABILITY = "Fixture support is not proof that an attack would succeed in an AWS account."
CAPABILITIES_NOT_EVALUATED = (
    "required_capabilities are retained as provenance and are not evaluated as IAM "
    "policy statements in this slice."
)

_FORBIDDEN_STATUSES = frozenset(
    {
        VerificationStatus.verified_in_mapped_sandbox,
        VerificationStatus.supported_by_policy_simulation,
        VerificationStatus.denied_by_policy_simulation,
    }
)


def build_attack_path(
    snapshot: IAMGraphSnapshot,
    rule: ApprovedRule,
    walk: Walk,
    limits_info: DiscoveryInfo,
) -> AttackPath:
    edges = {edge.edge_id: edge for edge in snapshot.edges}
    hops: list[AttackHop] = []
    for position, edge_id in enumerate(walk.edge_ids):
        edge = edges[edge_id]
        hops.append(
            AttackHop(
                position=position,
                edge_id=edge.edge_id,
                required_action=edge.iam_action or edge.edge_type.value,
                resource=edge.target_id,
                effect=edge.effect,
                condition_keys=sorted(edge.condition_summary),
            )
        )
    identity = [
        snapshot.schema_version,
        snapshot.snapshot_id,
        rule.rule_id,
        str(rule.rule_version),
        *walk.edge_ids,
    ]
    return AttackPath(
        schema_version="0.1",
        path_id=stable_id("path", *identity),
        snapshot_id=snapshot.snapshot_id,
        rule_refs=[RuleRef(rule_id=rule.rule_id, rule_version=rule.rule_version)],
        start_node_id=walk.node_ids[0],
        goal_node_id=walk.node_ids[-1],
        hops=hops,
        discovery=limits_info,
        deduplication_key=sha256_key(*identity),
    )


def verify_path(
    snapshot: IAMGraphSnapshot,
    rule: ApprovedRule,
    path: AttackPath,
    condition_resolutions: dict[str, ConditionResolution],
    evaluated_at: datetime,
    binding: Mapping[str, str] | None = None,
) -> VerificationResult:
    edges = {edge.edge_id: edge for edge in snapshot.edges}
    missing: list[str] = []
    unsupported: list[str] = []
    denied: list[str] = []
    notes: list[str] = []
    operational_error = False

    if not snapshot.collection.complete:
        missing.append("collection")
        notes.append("snapshot collection is marked incomplete")

    for hop in path.hops:
        edge = edges.get(hop.edge_id)
        if edge is None:
            operational_error = True
            notes.append(f"missing edge {hop.edge_id}")
            continue
        _classify_edge(edge, condition_resolutions, missing, unsupported, denied, notes)

    hop_ids = {hop.edge_id for hop in path.hops}
    for edge in _bound_service_trusts(snapshot, rule, binding):
        if edge.edge_id in hop_ids:
            continue
        _classify_edge(edge, condition_resolutions, missing, unsupported, denied, notes)

    if operational_error:
        status = VerificationStatus.error
    elif missing or unsupported:
        status = VerificationStatus.inconclusive
    elif denied:
        status = VerificationStatus.denied_by_fixture
    else:
        status = VerificationStatus.supported_by_fixture

    if status in _FORBIDDEN_STATUSES:
        raise RuntimeError("local adapter attempted a non-fixture verdict")

    evidence = _evidence(rule, path, edges)
    limitations = [LOCAL_LIMITATION, NOT_EXPLOITABILITY, CAPABILITIES_NOT_EVALUATED]
    limitations.extend(rule.limitations)
    return VerificationResult(
        schema_version="0.1",
        verification_id=stable_id("verify", path.path_id, status.value),
        path_id=path.path_id,
        status=status,
        policy_simulation=PolicySimulation(status="not_run"),
        sandbox=SandboxCheck(status="not_mapped"),
        local_fixture=LocalFixtureCheck(
            adapter="local_fixture",
            missing_context=missing,
            unsupported_conditions=unsupported,
            denied_edge_ids=sorted(set(denied)),
            notes=notes,
        ),
        evidence_refs=evidence,
        limitations=limitations[:20],
        started_at=evaluated_at,
        finished_at=evaluated_at,
    )


def _bound_service_trusts(
    snapshot: IAMGraphSnapshot,
    rule: ApprovedRule,
    binding: Mapping[str, str] | None,
) -> list[GraphEdge]:
    if not binding:
        return []
    nodes_by_id = {node.node_id: node for node in snapshot.nodes}
    edges: list[GraphEdge] = []
    for item in rule.preconditions:
        if item.type != "role_trusts_service":
            continue
        subject = binding.get(item.subject)
        if subject is None:
            continue
        edges.extend(service_trust_edges(snapshot, nodes_by_id, subject, item.value))
    return edges


def _classify_edge(
    edge: GraphEdge,
    condition_resolutions: dict[str, ConditionResolution],
    missing: list[str],
    unsupported: list[str],
    denied: list[str],
    notes: list[str],
) -> None:
    if edge.confidence == EdgeConfidence.unknown:
        missing.append(f"{edge.edge_id}:confidence")
        notes.append(f"{edge.edge_id} has unknown confidence")
    if edge.condition_summary:
        resolution = condition_resolutions.get(edge.edge_id)
        keys = sorted(edge.condition_summary)
        if resolution is None:
            missing.extend(f"{edge.edge_id}:{key}" for key in keys)
        elif resolution == ConditionResolution.unsupported:
            unsupported.extend(f"{edge.edge_id}:{key}" for key in keys)
        elif resolution == ConditionResolution.unsatisfied:
            denied.append(edge.edge_id)
        elif resolution == ConditionResolution.satisfied:
            notes.append(f"{edge.edge_id} condition marked satisfied by fixture context")
    if edge.effect == AuthorizationEffect.deny:
        denied.append(edge.edge_id)


def _evidence(rule: ApprovedRule, path: AttackPath, edges: dict[str, GraphEdge]) -> list[str]:
    refs = set(rule.evidence_refs)
    for hop in path.hops:
        edge = edges.get(hop.edge_id)
        if edge is not None:
            refs.update(edge.policy_refs)
    return sorted(refs)
