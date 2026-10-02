"""Findings cite evidence and gaps. They do not claim cloud verification."""

from fyp_iam.contracts.models import VerificationStatus
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.fixtures.cases import (
    FixtureCase,
    condition_dependent_case,
    explicit_deny_case,
    missing_context_case,
    positive_case,
)

_FORBIDDEN = (
    "supported_by_policy_simulation",
    "denied_by_policy_simulation",
    "verified_in_mapped_sandbox",
)


def _why(case: FixtureCase) -> str:
    report = analyze(
        case.rules,
        case.snapshot,
        condition_resolutions=case.condition_resolutions,
        evaluated_at=case.evaluated_at,
    )
    why = report.findings[0].explanation.why
    for phrase in _FORBIDDEN:
        assert phrase not in why
    assert report.findings[0].explanation.simulator == "not_run"
    assert report.findings[0].explanation.sandbox == "not_mapped"
    assert "Simulator status is not_run" in why
    assert "Sandbox status is not_mapped" in why
    return why


def test_positive_finding_cites_hop_policies() -> None:
    why = _why(positive_case())
    assert "policies=policy_alice_dev" in why
    assert "policies=policy_dev_admin" in why
    assert "Unknown or unsupported: none" in why
    assert "T1548" in why


def test_denied_finding_names_the_denied_edge() -> None:
    case = explicit_deny_case()
    report = analyze(case.rules, case.snapshot, evaluated_at=case.evaluated_at)
    assert report.verifications[0].status == VerificationStatus.denied_by_fixture
    assert "denied=edge_dev_admin" in report.findings[0].explanation.why


def test_inconclusive_finding_names_the_missing_context() -> None:
    why = _why(missing_context_case())
    assert "missing=collection,edge_dev_admin:aws:MultiFactorAuthPresent" in why
    assert "collection_incomplete=condition context was not collected" in why
    assert "conditions=aws:MultiFactorAuthPresent" in why


def test_satisfied_condition_is_labeled_as_fixture_context() -> None:
    why = _why(condition_dependent_case())
    assert "marked satisfied by fixture context" in why
    assert "conditions=aws:MultiFactorAuthPresent" in why
    assert "Fixture adapter status is supported_by_fixture" in why
