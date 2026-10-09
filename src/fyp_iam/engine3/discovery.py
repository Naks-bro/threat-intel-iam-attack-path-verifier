"""Bounded breadth-first discovery over derived capability edges."""

from collections import deque
from dataclasses import dataclass

from fyp_iam.contracts.models import (
    ApprovedRule,
    AuthorizationEffect,
    DiscoveryLimits,
    EdgeType,
    GraphEdge,
    GraphNode,
    IAMGraphSnapshot,
    NodeType,
)
from fyp_iam.core.clock import Clock

_NODE_TYPE_NAMES = {item.value for item in NodeType}
_SUPPORTED_PRECONDITIONS = frozenset({"role_trusts_service", "target_is_iam_user"})


@dataclass(frozen=True)
class Walk:
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]


@dataclass(frozen=True)
class BoundWalk:
    walk: Walk
    binding: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class DiscoveryBatch:
    walks: tuple[BoundWalk, ...]
    truncation_reasons: tuple[str, ...]
    rejected_preconditions: int


def unsupported_precondition_types(rule: ApprovedRule) -> list[str]:
    return sorted(
        {
            item.type
            for item in rule.preconditions
            if item.type not in _SUPPORTED_PRECONDITIONS
            or (item.type == "target_is_iam_user" and item.value != "iam_user")
        }
    )


def unbound_precondition_subjects(rule: ApprovedRule) -> list[str]:
    variables = {step.from_role for step in rule.path_pattern}
    variables.update(step.to_role for step in rule.path_pattern)
    return sorted({item.subject for item in rule.preconditions if item.subject not in variables})


def node_matches_role(role: str, node: GraphNode) -> bool:
    if role in _NODE_TYPE_NAMES:
        return node.node_type.value == role
    return True


def discover_bound_walks(
    snapshot: IAMGraphSnapshot,
    rule: ApprovedRule,
    limits: DiscoveryLimits,
    clock: Clock,
    *,
    start_node_id: str | None = None,
) -> DiscoveryBatch:
    pattern = rule.path_pattern
    if len(pattern) > limits.max_hops:
        return DiscoveryBatch(walks=(), truncation_reasons=("max_hops",), rejected_preconditions=0)

    nodes_by_id = {node.node_id: node for node in snapshot.nodes}
    edges_by_id = {edge.edge_id: edge for edge in snapshot.edges}
    allowed = frozenset(step.relationship for step in pattern)
    adjacency = _adjacency(snapshot, allowed)
    if start_node_id is not None and start_node_id not in nodes_by_id:
        raise ValueError("starting identity is not in the snapshot")
    starts = sorted(
        node.node_id
        for node in snapshot.nodes
        if (start_node_id is None or node.node_id == start_node_id)
        and node_matches_role(pattern[0].from_role, node)
    )

    found: list[BoundWalk] = []
    seen: set[tuple[str, ...]] = set()
    reasons: list[str] = []
    rejected = 0
    expansions = 0
    started = clock.monotonic()
    stop = False

    for start_id in starts:
        if stop:
            break
        if len(found) >= limits.max_paths:
            reasons.append("max_paths")
            break
        per_start = 0
        queue: deque[Walk] = deque([Walk((start_id,), ())])
        while queue and not stop:
            if (clock.monotonic() - started) * 1000 > limits.timeout_ms:
                reasons.append("timeout")
                stop = True
                break
            current = queue.popleft()
            if len(current.edge_ids) == len(pattern):
                if current.edge_ids in seen:
                    continue
                bound = _bind_pattern(rule, current, nodes_by_id, edges_by_id)
                if bound is None:
                    continue
                if not _preconditions_ok(snapshot, rule, bound):
                    rejected += 1
                    seen.add(current.edge_ids)
                    continue
                seen.add(current.edge_ids)
                found.append(BoundWalk(current, tuple(sorted(bound.items()))))
                per_start += 1
                if per_start >= limits.max_paths_per_start:
                    reasons.append("max_paths_per_start")
                    break
                if len(found) >= limits.max_paths:
                    reasons.append("max_paths")
                    stop = True
                continue
            head = current.node_ids[-1]
            for edge in adjacency.get(head, ()):
                if expansions >= limits.max_expansions:
                    reasons.append("max_expansions")
                    stop = True
                    break
                expansions += 1
                if edge.edge_id in current.edge_ids or edge.target_id in current.node_ids:
                    continue
                if len(current.edge_ids) + 1 > limits.max_hops:
                    reasons.append("max_hops")
                    continue
                queue.append(
                    Walk(
                        current.node_ids + (edge.target_id,),
                        current.edge_ids + (edge.edge_id,),
                    )
                )

    found.sort(key=lambda item: (item.walk.edge_ids, item.binding))
    return DiscoveryBatch(
        walks=tuple(found),
        truncation_reasons=tuple(sorted(set(reasons))),
        rejected_preconditions=rejected,
    )


def _adjacency(
    snapshot: IAMGraphSnapshot, allowed: frozenset[EdgeType]
) -> dict[str, tuple[GraphEdge, ...]]:
    grouped: dict[str, list[GraphEdge]] = {}
    for edge in snapshot.edges:
        if edge.edge_type not in allowed:
            continue
        grouped.setdefault(edge.source_id, []).append(edge)
    return {
        source_id: tuple(sorted(edges, key=lambda item: (item.edge_type.value, item.edge_id)))
        for source_id, edges in grouped.items()
    }


def _bind_pattern(
    rule: ApprovedRule,
    walk: Walk,
    nodes_by_id: dict[str, GraphNode],
    edges_by_id: dict[str, GraphEdge],
) -> dict[str, str] | None:
    pattern = rule.path_pattern
    if len(walk.edge_ids) != len(pattern):
        return None
    binding: dict[str, str] = {}
    for index, step in enumerate(pattern):
        edge_id = walk.edge_ids[index]
        source_id = walk.node_ids[index]
        target_id = walk.node_ids[index + 1]
        edge = edges_by_id[edge_id]
        if edge.source_id != source_id or edge.target_id != target_id:
            return None
        if edge.edge_type != step.relationship:
            return None
        if edge.edge_type == EdgeType.CAN_CREATE_AS and (
            len(rule.required_capabilities) != 1
            or edge.iam_action != rule.required_capabilities[0].action
            or rule.required_capabilities[0].resource_selector.kind != "user"
            or rule.required_capabilities[0].resource_selector.constraint != "iam_user"
            or not any(
                item.type == "target_is_iam_user" and item.subject == step.to_role
                for item in rule.preconditions
            )
        ):
            return None
        if not _assign(binding, step.from_role, source_id, nodes_by_id):
            return None
        if not _assign(binding, step.to_role, target_id, nodes_by_id):
            return None
    return binding


def _assign(
    binding: dict[str, str], role: str, node_id: str, nodes_by_id: dict[str, GraphNode]
) -> bool:
    if not node_matches_role(role, nodes_by_id[node_id]):
        return False
    current = binding.get(role)
    if current is None:
        binding[role] = node_id
        return True
    return current == node_id


def _preconditions_ok(
    snapshot: IAMGraphSnapshot, rule: ApprovedRule, binding: dict[str, str]
) -> bool:
    nodes_by_id = {node.node_id: node for node in snapshot.nodes}
    for item in rule.preconditions:
        subject = binding.get(item.subject)
        if subject is None:
            return False
        if item.type == "target_is_iam_user":
            node = nodes_by_id[subject]
            if node.node_type != NodeType.principal or node.subtype != "iam_user":
                return False
        elif item.type == "role_trusts_service":
            if not service_trust_edges(snapshot, nodes_by_id, subject, item.value):
                return False
        else:
            return False
    return True


def service_trust_edges(
    snapshot: IAMGraphSnapshot,
    nodes_by_id: dict[str, GraphNode],
    subject_id: str,
    service_name: str,
) -> list[GraphEdge]:
    """Allow TRUSTS edges from a role to one service. Deny edges are not trust."""
    matches: list[GraphEdge] = []
    for edge in snapshot.edges:
        if edge.edge_type != EdgeType.TRUSTS or edge.source_id != subject_id:
            continue
        if edge.effect != AuthorizationEffect.allow:
            continue
        target = nodes_by_id[edge.target_id]
        if target.node_type != NodeType.service:
            continue
        principal = target.properties.get("service_principal", target.display_name)
        if principal == service_name:
            matches.append(edge)
    return matches
