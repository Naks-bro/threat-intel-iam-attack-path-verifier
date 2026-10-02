"""Connect approved rules and a graph snapshot to findings."""

from collections.abc import Mapping, Sequence
from datetime import datetime

from fyp_iam.contracts.models import (
    ApprovedRule,
    AttackPath,
    ConditionResolution,
    DiscoveryInfo,
    DiscoveryLimits,
    Finding,
    IAMGraphSnapshot,
    RuleStatus,
    SnapshotValidationStatus,
    VerificationResult,
)
from fyp_iam.core.clock import Clock, SystemClock
from fyp_iam.core.report import AnalysisIssue, AnalysisReport
from fyp_iam.engine3.discovery import (
    discover_bound_walks,
    unbound_precondition_subjects,
    unsupported_precondition_types,
)
from fyp_iam.engine3.verify import build_attack_path, verify_path
from fyp_iam.engine4.findings import build_finding, priority_rank


def analyze(
    rules: Sequence[ApprovedRule],
    snapshot: IAMGraphSnapshot,
    *,
    limits: DiscoveryLimits | None = None,
    condition_resolutions: Mapping[str, ConditionResolution] | None = None,
    evaluated_at: datetime | None = None,
    clock: Clock | None = None,
) -> AnalysisReport:
    active_clock = clock or SystemClock()
    active_limits = limits or DiscoveryLimits()
    when = evaluated_at or active_clock.now()
    if when.tzinfo is None or when.utcoffset() is None:
        raise ValueError("evaluated_at must be timezone-aware")
    resolutions = dict(condition_resolutions or {})
    issues: list[AnalysisIssue] = []
    reasons: list[str] = []
    rows: list[tuple[int, str, Finding, AttackPath, VerificationResult]] = []

    if snapshot.validation.status == SnapshotValidationStatus.invalid:
        issues.append(
            AnalysisIssue(
                code="snapshot_invalid",
                message="Snapshot validation status is invalid, so no paths were verified.",
            )
        )
        return _report(snapshot.snapshot_id, [], [], [], issues, active_limits, [])

    info = DiscoveryInfo(
        algorithm="bounded_bfs",
        max_hops=active_limits.max_hops,
        limits=active_limits,
    )
    for rule in sorted(rules, key=lambda item: (item.rule_id, item.rule_version)):
        if rule.status != RuleStatus.approved:
            issues.append(
                AnalysisIssue(
                    code="rule_not_approved",
                    message="Only approved rules are eligible for verification.",
                    rule_id=rule.rule_id,
                )
            )
            continue
        unsupported = unsupported_precondition_types(rule)
        if unsupported:
            issues.append(
                AnalysisIssue(
                    code="unsupported_precondition",
                    message=f"Unsupported precondition types: {', '.join(unsupported)}.",
                    rule_id=rule.rule_id,
                )
            )
            continue
        unbound = unbound_precondition_subjects(rule)
        if unbound:
            issues.append(
                AnalysisIssue(
                    code="unbound_precondition_subject",
                    message=(
                        "Precondition subjects are not pattern variables: "
                        + ", ".join(unbound)
                        + "."
                    ),
                    rule_id=rule.rule_id,
                )
            )
            continue
        batch = discover_bound_walks(snapshot, rule, active_limits, active_clock)
        reasons.extend(batch.truncation_reasons)
        if batch.rejected_preconditions:
            issues.append(
                AnalysisIssue(
                    code="precondition_not_met",
                    message="At least one structural walk failed a supported precondition.",
                    rule_id=rule.rule_id,
                )
            )
        for bound in batch.walks:
            path = build_attack_path(snapshot, rule, bound.walk, info)
            verification = verify_path(snapshot, rule, path, resolutions, when)
            finding = build_finding(snapshot, rule, path, verification)
            rows.append(
                (
                    priority_rank(finding.priority),
                    path.deduplication_key,
                    finding,
                    path,
                    verification,
                )
            )

    rows.sort(key=lambda item: (item[0], str(item[1])))
    if reasons:
        unique_reasons = sorted(set(reasons))
        issues.append(
            AnalysisIssue(
                code="discovery_truncated",
                message=f"Path discovery hit a bound: {', '.join(unique_reasons)}.",
            )
        )
    else:
        unique_reasons = []
    issues.sort(key=lambda item: (item.code, item.rule_id or ""))
    findings = [row[2] for row in rows]
    paths = [row[3] for row in rows]
    verifications = [row[4] for row in rows]
    return _report(
        snapshot.snapshot_id,
        findings,
        paths,
        verifications,
        issues,
        active_limits,
        unique_reasons,
    )


def _report(
    snapshot_id: str,
    findings: list[Finding],
    paths: list[AttackPath],
    verifications: list[VerificationResult],
    issues: list[AnalysisIssue],
    limits: DiscoveryLimits,
    reasons: list[str],
) -> AnalysisReport:
    return AnalysisReport(
        schema_version="0.1",
        snapshot_id=snapshot_id,
        findings=findings,
        attack_paths=paths,
        verifications=verifications,
        issues=issues,
        limits=limits,
        truncation_reasons=reasons,
    )
