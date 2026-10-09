"""Pure row plan for the proposed 0011 observed-only graph tables.

No database write or AWS call occurs here. A future transaction must bind this
plan to the exact stored handoff and verify its digest after insert.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import ensure_utc, reject_sensitive_text
from fyp_iam.engine2.observed_graph import ObservedInventoryGraph, project_observed_inventory

_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$")


class GraphImportRejected(ValueError):
    """Fixed, non-sensitive reason a graph cannot fit the proposed schema."""


@dataclass(frozen=True)
class GraphImportPlan:
    graph: ObservedInventoryGraph
    projection: dict[str, Any]
    nodes: tuple[dict[str, Any], ...]
    edges: tuple[dict[str, Any], ...]
    evidence: tuple[dict[str, Any], ...]


def prepare_graph_import(
    handoff: CollectionHandoff, *, resolver_version: str, generated_at: datetime
) -> GraphImportPlan:
    """Reproject exact handoff bytes and map direct observations, never CAN edges."""

    if not _VERSION.fullmatch(resolver_version):
        raise GraphImportRejected("resolver_version_invalid")
    try:
        reject_sensitive_text(resolver_version)
        timestamp = ensure_utc(generated_at)
        sealed = CollectionHandoff.model_validate(handoff.model_dump(mode="json"))
        graph = project_observed_inventory(sealed)
    except (TypeError, ValueError):
        raise GraphImportRejected("graph_input_invalid") from None
    if graph.inventory_digest != sealed.manifest.snapshot_digest:
        raise GraphImportRejected("inventory_digest_mismatch")
    if graph.handoff_digest != sealed.content_digest():
        raise GraphImportRejected("handoff_digest_mismatch")

    principal_keys = {principal.principal_key for principal in sealed.inventory.principals}
    policy_keys = {policy.policy_key for policy in sealed.inventory.policies}
    trust_keys = {trust.statement_key for trust in sealed.inventory.trust_statements}
    snapshot_id = graph.snapshot_id
    nodes: list[dict[str, Any]] = []
    for node in graph.nodes:
        principal_key = node.key if node.kind in {"iam_user", "iam_role", "iam_group"} else None
        policy_key = node.key if node.kind == "policy" else None
        if (principal_key is not None and principal_key not in principal_keys) or (
            policy_key is not None and policy_key not in policy_keys
        ):
            raise GraphImportRejected("graph_node_source_missing")
        nodes.append(
            {
                "snapshot_id": snapshot_id,
                "node_key": node.key,
                "principal_key": principal_key,
                "policy_key": policy_key,
                "kind": node.kind,
                "display_alias": node.display_alias,
                "source_digest": node.source_digest,
            }
        )

    node_keys = {node["node_key"] for node in nodes}
    edges: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for relation in graph.relations:
        if relation.source_key not in node_keys or relation.target_key not in node_keys:
            raise GraphImportRejected("graph_edge_endpoint_missing")
        if relation.policy_key is not None and relation.policy_key not in policy_keys:
            raise GraphImportRejected("graph_edge_policy_missing")
        if relation.statement_key is not None and relation.statement_key not in trust_keys:
            raise GraphImportRejected("graph_edge_statement_missing")
        edges.append(
            {
                "snapshot_id": snapshot_id,
                "relation_id": relation.relation_id,
                "kind": relation.kind,
                "source_key": relation.source_key,
                "target_key": relation.target_key,
                "source_digest": relation.source_digest,
                "effect": relation.effect,
                "condition_state": relation.condition_state,
                "derivation": "observed_configuration",
            }
        )
        ordinal = 0
        if relation.statement_key is not None:
            evidence.append(
                {
                    "snapshot_id": snapshot_id,
                    "relation_id": relation.relation_id,
                    "evidence_ordinal": ordinal,
                    "evidence_role": "anchors",
                    "policy_key": None,
                    "identity_statement_key": None,
                    "trust_statement_key": relation.statement_key,
                }
            )
            ordinal += 1
        if relation.policy_key is not None:
            evidence.append(
                {
                    "snapshot_id": snapshot_id,
                    "relation_id": relation.relation_id,
                    "evidence_ordinal": ordinal,
                    "evidence_role": "supports" if ordinal else "anchors",
                    "policy_key": relation.policy_key,
                    "identity_statement_key": None,
                    "trust_statement_key": None,
                }
            )

    return GraphImportPlan(
        graph=graph,
        projection={
            "snapshot_id": snapshot_id,
            "inventory_digest": graph.inventory_digest,
            "handoff_digest": graph.handoff_digest,
            "projection_digest": graph.content_digest(),
            "resolver_version": resolver_version,
            "generated_at": timestamp,
            "source_coverage_complete": graph.source_coverage_complete,
            "incomplete_reason_codes": list(graph.incomplete_reason_codes),
            "authorization_evaluated": False,
        },
        nodes=tuple(nodes),
        edges=tuple(edges),
        evidence=tuple(evidence),
    )
