"""Foundry consumer seam: obtain a freshly gated stable export for each analysis."""

from collections.abc import Callable

from fyp_iam.contracts.models import ApprovedRule, IAMGraphSnapshot
from fyp_iam.contracts.releases import ReleaseScope, StableRuleRelease
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.engine3.scope import require_synthetic_snapshot

ExportLoader = Callable[[str, ReleaseScope], StableRuleRelease]


def analyze_published_release(
    release_id: str,
    snapshot: IAMGraphSnapshot,
    *,
    scope: ReleaseScope,
    export_loader: ExportLoader,
    start_node_id: str | None = None,
) -> AnalysisReport:
    """Loader must call the trusted current-input exporter, not cache old JSON.

    This is a point-in-time eligibility check, not distributed revocation or a
    signature. The lower-level legacy analyze(rules, snapshot) remains a fixture
    API and must not be used to bypass the foundry release boundary.
    """
    release = export_loader(release_id, scope)
    # Reparse at the consumer boundary, including against mutable/model_copy misuse.
    release = StableRuleRelease.model_validate_json(release.model_dump_json())
    if release.release_id != release_id or release.command.scope != scope:
        raise ValueError("Stable release target mismatch")
    require_synthetic_snapshot(snapshot)
    return analyze(
        [ApprovedRule.model_validate_json(release.rule_json)],
        snapshot,
        start_node_id=start_node_id,
    )
