"""Structural, offline what-if preview over a synthetic graph fixture.

Removing an edge here does not edit an IAM policy or establish effective AWS
permissions. It only compares bounded candidate-path discovery results.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from fyp_iam.contracts.models import (
    ApprovedRule,
    AttackPath,
    ConditionResolution,
    DiscoveryLimits,
    IAMGraphSnapshot,
)
from fyp_iam.core.ids import stable_id
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.engine3.scope import require_synthetic_snapshot

LIMITATION = (
    "This is a structural synthetic what-if preview, not an AWS policy change, "
    "effective-permission evaluation, or verified risk reduction."
)


@dataclass(frozen=True)
class EdgeRemovalPreview:
    original_snapshot_id: str
    hypothetical_snapshot_id: str
    removed_edge_id: str
    baseline: AnalysisReport
    hypothetical: AnalysisReport
    disappeared_candidate_paths: int
    appeared_candidate_paths: int
    comparison_complete: bool
    limitation: str = LIMITATION


def preview_edge_removal(
    rules: list[ApprovedRule],
    snapshot: IAMGraphSnapshot,
    edge_id: str,
    *,
    evaluated_at: datetime,
    condition_resolutions: Mapping[str, ConditionResolution] | None = None,
    limits: DiscoveryLimits | None = None,
) -> EdgeRemovalPreview:
    """Compare one hypothetical graph-edge removal against the unchanged fixture."""
    require_synthetic_snapshot(snapshot)
    if edge_id not in {edge.edge_id for edge in snapshot.edges}:
        raise ValueError("edge_id is not present in the snapshot")

    hypothetical_id = stable_id("whatif", snapshot.snapshot_id, edge_id)
    hypothetical = IAMGraphSnapshot.model_validate(
        {
            **snapshot.model_dump(mode="python"),
            "snapshot_id": hypothetical_id,
            "edges": [edge for edge in snapshot.edges if edge.edge_id != edge_id],
        }
    )
    baseline_report = analyze(
        rules,
        snapshot,
        limits=limits,
        condition_resolutions=condition_resolutions,
        evaluated_at=evaluated_at,
    )
    hypothetical_report = analyze(
        rules,
        hypothetical,
        limits=limits,
        condition_resolutions=condition_resolutions,
        evaluated_at=evaluated_at,
    )
    before = {_path_signature(path) for path in baseline_report.attack_paths}
    after = {_path_signature(path) for path in hypothetical_report.attack_paths}
    return EdgeRemovalPreview(
        original_snapshot_id=snapshot.snapshot_id,
        hypothetical_snapshot_id=hypothetical_id,
        removed_edge_id=edge_id,
        baseline=baseline_report,
        hypothetical=hypothetical_report,
        disappeared_candidate_paths=len(before - after),
        appeared_candidate_paths=len(after - before),
        comparison_complete=not (
            baseline_report.truncation_reasons or hypothetical_report.truncation_reasons
        ),
    )


def _path_signature(path: AttackPath) -> tuple[tuple[tuple[str, int], ...], tuple[str, ...]]:
    return (
        tuple((ref.rule_id, ref.rule_version) for ref in path.rule_refs),
        tuple(hop.edge_id for hop in path.hops),
    )
