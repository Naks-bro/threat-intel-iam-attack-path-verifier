"""Derive a portable IAM graph from synthetic records.

This is not AWS IAM evaluation. Only an exact ``sts:AssumeRole`` statement
paired with an exact matching trust statement becomes a ``CAN_ASSUME`` edge.
Wildcards, other actions, boundaries, SCPs, and resource policies are skipped
and recorded as coverage warnings.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

from fyp_iam.contracts.models import (
    AuthorizationEffect,
    CollectionInfo,
    EdgeConfidence,
    EdgeType,
    GraphEdge,
    GraphNode,
    IAMGraphSnapshot,
    NodeType,
    SnapshotScope,
    SnapshotValidationStatus,
    ValidationReport,
)
from fyp_iam.core.ids import stable_id
from fyp_iam.engine2.coverage import (
    LayerState,
    NormalizationCoverage,
    assert_reconciled,
)
from fyp_iam.engine2.records import (
    IdentityRecord,
    SyntheticAccount,
    TrustStatement,
    service_principal_name,
)

_ASSUME = "sts:AssumeRole"
_COLLECTED_AT = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
_LAYER_WARNING = (
    "Permission boundaries, SCPs, RCPs, session policies, and resource policies were not evaluated."
)


@dataclass
class _Derived:
    effect: AuthorizationEffect = AuthorizationEffect.allow
    conditions: set[str] = field(default_factory=set)
    policy_refs: set[str] = field(default_factory=set)

    def merge(self, effect: AuthorizationEffect, conditions: list[str], refs: list[str]) -> None:
        if effect == AuthorizationEffect.deny:
            self.effect = AuthorizationEffect.deny
        self.conditions.update(conditions)
        self.policy_refs.update(refs)


def normalize_synthetic_account(account: SyntheticAccount) -> IAMGraphSnapshot:
    snapshot, _coverage = normalize_with_coverage(account)
    return snapshot


def normalize_with_coverage(
    account: SyntheticAccount,
) -> tuple[IAMGraphSnapshot, NormalizationCoverage]:
    by_id = {item.node_id: item for item in account.identities}
    warnings: list[str] = [_LAYER_WARNING]
    skipped = False
    identity_total = 0
    identity_skipped = 0
    derived: dict[tuple[str, str], _Derived] = {}
    bounded = {item.node_id for item in account.identities if item.boundary_id is not None}

    for source in sorted(account.identities, key=lambda item: item.node_id):
        if source.boundary_id is not None:
            warnings.append(
                f"Permissions boundary {source.boundary_id} on {source.node_id} "
                "was recorded and not evaluated."
            )
        for statement in source.identity_statements:
            identity_total += 1
            if not _exact_assume(statement.actions):
                warnings.append(
                    f"Skipped identity statement {statement.statement_id}: "
                    "only exact sts:AssumeRole is supported."
                )
                skipped = True
                identity_skipped += 1
                continue
            statement_skipped = False
            for target_id in statement.resource_ids:
                if target_id == "*":
                    warnings.append(f"Skipped wildcard resource on {statement.statement_id}.")
                    skipped = True
                    statement_skipped = True
                    continue
                target = by_id.get(target_id)
                if target is None or target.subtype != "iam_role":
                    warnings.append(
                        f"Skipped {statement.statement_id}: {target_id} is not a known role."
                    )
                    skipped = True
                    statement_skipped = True
                    continue
                trusts, trust_skipped = _matching_trust(target, source.node_id, warnings)
                if trust_skipped or not trusts:
                    skipped = True
                if not trusts:
                    continue
                key = (source.node_id, target.node_id)
                item = derived.setdefault(key, _Derived())
                item.merge(statement.effect, statement.condition_keys, [statement.statement_id])
                for trust in trusts:
                    item.merge(trust.effect, trust.condition_keys, [trust.statement_id])
            if statement_skipped:
                identity_skipped += 1

    trust_total, unsupported_trusts = _trust_counts(account)
    service_trusts, service_skipped = _service_trusts(account, warnings)
    if unsupported_trusts or service_skipped:
        skipped = True
    nodes = [_principal(item) for item in sorted(account.identities, key=lambda item: item.node_id)]
    nodes.extend(_policy_nodes(account))
    nodes.extend(_boundary_nodes(account))
    nodes.extend(_service_nodes(service_trusts))
    edges = _assume_edges(derived, bounded)
    edges.extend(_attachment_edges(account))
    edges.extend(_boundary_edges(account))
    edges.extend(_service_edges(service_trusts))
    edges.sort(key=lambda item: item.edge_id)
    nodes.sort(key=lambda item: item.node_id)
    if len(warnings) > 50:
        warnings = [*warnings[:49], "Additional coverage warnings were truncated."]
    status = (
        SnapshotValidationStatus.valid_with_warnings if warnings else SnapshotValidationStatus.valid
    )
    snapshot = IAMGraphSnapshot(
        schema_version="0.1",
        snapshot_id=account.snapshot_id,
        scope=SnapshotScope(
            provider="aws",
            account_alias="synthetic-lab",
            regions=["global"],
            collected_at=_COLLECTED_AT,
        ),
        nodes=nodes,
        edges=edges,
        policy_documents=[],
        collection=CollectionInfo(
            collector_version="local-normalizer-0.1",
            permissions_profile="synthetic-records-no-aws-api",
            complete=not skipped,
            warnings=warnings,
        ),
        validation=ValidationReport(status=status, errors=[], warnings=list(warnings)),
    )
    assert_reconciled(account, snapshot)
    coverage = NormalizationCoverage(
        schema_version="0.1",
        identity_policy=_layer(identity_total, identity_skipped),
        trust_policy=_layer(trust_total, unsupported_trusts + service_skipped),
        permissions_boundary=(LayerState.recorded_not_evaluated if bounded else LayerState.absent),
        service_control_policy=LayerState.not_collected,
        resource_control_policy=LayerState.not_collected,
        session_policy=LayerState.not_collected,
        resource_policy=LayerState.not_collected,
        identity_count=len(account.identities),
        identity_statement_count=identity_total,
        trust_statement_count=trust_total,
        boundary_count=len(bounded),
        principal_count=sum(1 for node in snapshot.nodes if node.node_type == NodeType.principal),
        can_assume_count=sum(1 for edge in snapshot.edges if edge.edge_type == EdgeType.CAN_ASSUME),
        has_policy_count=sum(1 for edge in snapshot.edges if edge.edge_type == EdgeType.HAS_POLICY),
        has_boundary_count=sum(
            1 for edge in snapshot.edges if edge.edge_type == EdgeType.HAS_BOUNDARY
        ),
        reconciled=True,
    )
    return snapshot, coverage


def _exact_assume(actions: list[str]) -> bool:
    return actions == [_ASSUME]


def _layer(total: int, skipped: int) -> LayerState:
    if total == 0:
        return LayerState.absent
    if skipped:
        return LayerState.partial
    return LayerState.limited


def _trust_counts(account: SyntheticAccount) -> tuple[int, int]:
    total = 0
    skipped = 0
    for record in account.identities:
        for item in record.trust_statements:
            total += 1
            if not _exact_assume(item.actions) or "*" in item.principal_ids:
                skipped += 1
    return total, skipped


def _matching_trust(
    role: IdentityRecord, principal_id: str, warnings: list[str]
) -> tuple[list[TrustStatement], bool]:
    matches: list[TrustStatement] = []
    skipped = False
    for item in role.trust_statements:
        exact = _exact_assume(item.actions) and "*" not in item.principal_ids
        if not exact:
            warnings.append(
                f"Skipped trust statement {item.statement_id}: "
                "wildcards and other actions are unsupported."
            )
            skipped = True
            continue
        if principal_id in item.principal_ids:
            matches.append(item)
    if not matches:
        warnings.append(f"No exact trust on {role.node_id} for {principal_id}.")
    return matches, skipped


def _principal(record: IdentityRecord) -> GraphNode:
    return GraphNode(
        node_id=record.node_id,
        node_type=NodeType.principal,
        subtype=record.subtype,
        display_name=record.display_name,
        arn_hash=_hash(record.node_id),
        properties={},
    )


def _policy_nodes(account: SyntheticAccount) -> list[GraphNode]:
    nodes: list[GraphNode] = []
    for record in account.identities:
        if not record.identity_statements and not record.trust_statements:
            continue
        policy_id = f"policy:{record.node_id}"
        nodes.append(
            GraphNode(
                node_id=policy_id,
                node_type=NodeType.policy,
                subtype="identity_policy",
                display_name=record.display_name,
                arn_hash=_hash(policy_id),
                properties={},
            )
        )
    return nodes


def _boundary_nodes(account: SyntheticAccount) -> list[GraphNode]:
    nodes: dict[str, GraphNode] = {}
    for record in account.identities:
        boundary_id = record.boundary_id
        if boundary_id is None or boundary_id in nodes:
            continue
        nodes[boundary_id] = GraphNode(
            node_id=boundary_id,
            node_type=NodeType.policy,
            subtype="permissions_boundary",
            display_name=boundary_id.removeprefix("boundary:"),
            arn_hash=_hash(boundary_id),
            properties={},
        )
    return list(nodes.values())


def _service_trusts(
    account: SyntheticAccount, warnings: list[str]
) -> tuple[dict[tuple[str, str], _Derived], int]:
    derived: dict[tuple[str, str], _Derived] = {}
    skipped = 0
    for record in account.identities:
        if record.subtype != "iam_role":
            continue
        for statement in record.trust_statements:
            if not _exact_assume(statement.actions) or "*" in statement.principal_ids:
                continue
            for principal_id in statement.principal_ids:
                if principal_id.startswith("principal:"):
                    continue
                if service_principal_name(principal_id) is None:
                    warnings.append(
                        f"Skipped service principal on {statement.statement_id}: "
                        "only an exact service:name.amazonaws.com id is supported."
                    )
                    skipped += 1
                    continue
                key = (record.node_id, principal_id)
                item = derived.setdefault(key, _Derived())
                item.merge(statement.effect, statement.condition_keys, [statement.statement_id])
    return derived, skipped


def _service_nodes(derived: dict[tuple[str, str], _Derived]) -> list[GraphNode]:
    nodes: dict[str, GraphNode] = {}
    for _role_id, service_id in sorted(derived):
        if service_id in nodes:
            continue
        name = service_principal_name(service_id)
        if name is None:
            continue
        nodes[service_id] = GraphNode(
            node_id=service_id,
            node_type=NodeType.service,
            subtype="aws_service",
            display_name=name,
            arn_hash=_hash(service_id),
            properties={"service_principal": name},
        )
    return list(nodes.values())


def _service_edges(derived: dict[tuple[str, str], _Derived]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for role_id, service_id in sorted(derived):
        item = derived[(role_id, service_id)]
        confidence = EdgeConfidence.deterministic
        edges.append(
            GraphEdge(
                edge_id=stable_id("trust", role_id, service_id, item.effect.value),
                edge_type=EdgeType.TRUSTS,
                source_id=role_id,
                target_id=service_id,
                derivation="policy_analysis",
                policy_refs=sorted(item.policy_refs),
                condition_summary={key: "unevaluated" for key in sorted(item.conditions)},
                confidence=confidence,
                effect=item.effect,
            )
        )
    return edges


def _assume_edges(
    derived: dict[tuple[str, str], _Derived],
    bounded_sources: set[str],
) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for source_id, target_id in sorted(derived):
        item = derived[(source_id, target_id)]
        confidence = (
            EdgeConfidence.unknown if source_id in bounded_sources else EdgeConfidence.deterministic
        )
        edges.append(
            GraphEdge(
                edge_id=stable_id("edge", source_id, target_id, item.effect.value),
                edge_type=EdgeType.CAN_ASSUME,
                source_id=source_id,
                target_id=target_id,
                derivation="policy_analysis",
                policy_refs=sorted(item.policy_refs),
                condition_summary={key: "unevaluated" for key in sorted(item.conditions)},
                confidence=confidence,
                effect=item.effect,
            )
        )
    return edges


def _attachment_edges(account: SyntheticAccount) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for record in account.identities:
        if not record.identity_statements and not record.trust_statements:
            continue
        refs = [item.statement_id for item in record.identity_statements]
        refs.extend(item.statement_id for item in record.trust_statements)
        edges.append(
            GraphEdge(
                edge_id=stable_id("attach", record.node_id),
                edge_type=EdgeType.HAS_POLICY,
                source_id=record.node_id,
                target_id=f"policy:{record.node_id}",
                derivation="policy_analysis",
                policy_refs=sorted(refs),
                condition_summary={},
                confidence=EdgeConfidence.deterministic,
                effect=AuthorizationEffect.allow,
            )
        )
    return edges


def _boundary_edges(account: SyntheticAccount) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for record in account.identities:
        if record.boundary_id is None:
            continue
        edges.append(
            GraphEdge(
                edge_id=stable_id("boundary", record.node_id, record.boundary_id),
                edge_type=EdgeType.HAS_BOUNDARY,
                source_id=record.node_id,
                target_id=record.boundary_id,
                derivation="policy_analysis",
                policy_refs=[record.boundary_id],
                condition_summary={},
                confidence=EdgeConfidence.unknown,
                effect=AuthorizationEffect.allow,
            )
        )
    return edges


def _hash(node_id: str) -> str:
    digest = hashlib.sha256(f"synthetic:{node_id}".encode()).hexdigest()
    return f"sha256:{digest}"
