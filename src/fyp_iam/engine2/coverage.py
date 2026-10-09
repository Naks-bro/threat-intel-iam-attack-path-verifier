"""Reconcile a synthetic snapshot with the records that produced it.

Layer labels describe what this normalizer looked at. They are not an AWS
authorization decision.
"""

from enum import StrEnum

from pydantic import Field

from fyp_iam.contracts.models import (
    ContractModel,
    EdgeConfidence,
    EdgeType,
    IAMGraphSnapshot,
    NodeType,
)
from fyp_iam.engine2.records import SyntheticAccount, service_principal_name


class LayerState(StrEnum):
    absent = "absent"
    not_collected = "not_collected"
    recorded_not_evaluated = "recorded_not_evaluated"
    partial = "partial"
    limited = "limited"


class NormalizationCoverage(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    identity_policy: LayerState
    trust_policy: LayerState
    permissions_boundary: LayerState
    service_control_policy: LayerState
    resource_control_policy: LayerState
    session_policy: LayerState
    resource_policy: LayerState
    identity_count: int = Field(ge=0)
    identity_statement_count: int = Field(ge=0)
    trust_statement_count: int = Field(ge=0)
    boundary_count: int = Field(ge=0)
    principal_count: int = Field(ge=0)
    can_assume_count: int = Field(ge=0)
    has_policy_count: int = Field(ge=0)
    has_boundary_count: int = Field(ge=0)
    reconciled: bool


def reconciliation_errors(account: SyntheticAccount, snapshot: IAMGraphSnapshot) -> list[str]:
    """Return structural mismatches. An empty list means the counts agree."""
    errors: list[str] = []
    identities = {item.node_id: item for item in account.identities}
    principals = {node.node_id for node in snapshot.nodes if node.node_type == NodeType.principal}
    if principals != set(identities):
        errors.append("principal nodes do not match identity records")

    expected_policies = {
        f"policy:{item.node_id}"
        for item in account.identities
        if item.identity_statements or item.trust_statements
    }
    identity_policies = {
        node.node_id
        for node in snapshot.nodes
        if node.node_type == NodeType.policy and node.subtype == "identity_policy"
    }
    if identity_policies != expected_policies:
        errors.append("identity policy nodes do not match attached statements")

    expected_boundaries = {
        item.boundary_id for item in account.identities if item.boundary_id is not None
    }
    boundary_nodes = {
        node.node_id
        for node in snapshot.nodes
        if node.node_type == NodeType.policy and node.subtype == "permissions_boundary"
    }
    if boundary_nodes != expected_boundaries:
        errors.append("boundary nodes do not match boundary attachments")

    unexpected = [
        node.node_id
        for node in snapshot.nodes
        if node.node_type not in {NodeType.principal, NodeType.policy, NodeType.service}
    ]
    if unexpected:
        errors.append("snapshot contains a node type the normalizer does not emit")

    statement_ids: set[str] = set()
    for item in account.identities:
        statement_ids.update(statement.statement_id for statement in item.identity_statements)
        statement_ids.update(statement.statement_id for statement in item.trust_statements)
    nodes_by_id = {node.node_id: node for node in snapshot.nodes}
    expected_trusts = _expected_service_trusts(account)
    actual_trusts: set[tuple[str, str]] = set()
    has_policy = 0
    has_boundary = 0
    can_assume = 0
    for edge in snapshot.edges:
        if edge.edge_type == EdgeType.HAS_POLICY:
            has_policy += 1
            expected_target = f"policy:{edge.source_id}"
            if edge.target_id != expected_target or edge.target_id not in expected_policies:
                errors.append(f"{edge.edge_id} policy attachment does not match its source")
        elif edge.edge_type == EdgeType.HAS_BOUNDARY:
            has_boundary += 1
            record = identities.get(edge.source_id)
            if record is None or edge.target_id != record.boundary_id:
                errors.append(f"{edge.edge_id} boundary attachment does not match its source")
            if edge.confidence != EdgeConfidence.unknown:
                errors.append(f"{edge.edge_id} boundary was evaluated")
        elif edge.edge_type == EdgeType.CAN_ASSUME:
            can_assume += 1
            source = identities.get(edge.source_id)
            target = identities.get(edge.target_id)
            if source is None or target is None or target.subtype != "iam_role":
                errors.append(f"{edge.edge_id} assume endpoints are not an identity and a role")
            elif source.boundary_id is not None and edge.confidence != EdgeConfidence.unknown:
                errors.append(f"{edge.edge_id} ignores an unevaluated permissions boundary")
            if not set(edge.policy_refs).issubset(statement_ids):
                errors.append(f"{edge.edge_id} cites a statement that is not in the account")
        elif edge.edge_type == EdgeType.TRUSTS:
            actual_trusts.add((edge.source_id, edge.target_id))
            role = identities.get(edge.source_id)
            service_node = nodes_by_id.get(edge.target_id)
            service_name = service_principal_name(edge.target_id)
            if role is None or role.subtype != "iam_role" or service_node is None:
                errors.append(f"{edge.edge_id} trust endpoints are not a role and a service")
            elif service_node.node_type != NodeType.service or service_name is None:
                errors.append(f"{edge.edge_id} trust target is not an exact service principal")
            elif service_node.properties.get("service_principal") != service_name:
                errors.append(f"{edge.edge_id} service node name does not match its id")
            trust_ids = {item.statement_id for item in role.trust_statements} if role else set()
            if not set(edge.policy_refs).issubset(trust_ids):
                errors.append(f"{edge.edge_id} cites a trust statement that is not on its role")
        else:
            errors.append(f"{edge.edge_id} uses an edge type the normalizer does not emit")

    if has_policy != len(expected_policies):
        errors.append("HAS_POLICY count does not match identities that have statements")
    if has_boundary != sum(1 for item in account.identities if item.boundary_id is not None):
        errors.append("HAS_BOUNDARY count does not match boundary attachments")
    if actual_trusts != expected_trusts:
        errors.append("TRUSTS edges do not match exact service principals")
    service_nodes = {node.node_id for node in snapshot.nodes if node.node_type == NodeType.service}
    if service_nodes != {target for _source, target in expected_trusts}:
        errors.append("service nodes do not match TRUSTS targets")
    return errors


def _expected_service_trusts(account: SyntheticAccount) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for record in account.identities:
        if record.subtype != "iam_role":
            continue
        for statement in record.trust_statements:
            if statement.actions != ["sts:AssumeRole"] or "*" in statement.principal_ids:
                continue
            for principal_id in statement.principal_ids:
                if service_principal_name(principal_id) is not None:
                    pairs.add((record.node_id, principal_id))
    return pairs


def assert_reconciled(account: SyntheticAccount, snapshot: IAMGraphSnapshot) -> None:
    errors = reconciliation_errors(account, snapshot)
    if errors:
        joined = "; ".join(errors)
        raise RuntimeError(f"synthetic snapshot did not reconcile: {joined}")
