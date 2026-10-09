from fyp_iam.contracts.models import EdgeType, VerificationStatus
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.engine3.verify import LOCAL_LIMITATION
from fyp_iam.fixtures.cases import all_cases, credential_creation_case
from fyp_iam.fixtures.loader import load_fixture

EXPECTATIONS = {
    "positive": (1, VerificationStatus.supported_by_fixture),
    "hard_negative": (0, None),
    "explicit_deny": (1, VerificationStatus.denied_by_fixture),
    "condition_dependent": (1, VerificationStatus.supported_by_fixture),
    "cyclic": (1, VerificationStatus.supported_by_fixture),
    "missing_context": (1, VerificationStatus.inconclusive),
    "credential_creation": (1, VerificationStatus.supported_by_fixture),
}


def test_fixture_files_cover_the_required_cases(fixture_dir) -> None:
    loaded = [load_fixture(fixture_dir, case.case_id) for case in all_cases()]
    assert [case.case_id for case in loaded] == list(EXPECTATIONS)


def test_checked_in_paired_fixture_matches_its_builder(fixture_dir) -> None:
    checked_in = load_fixture(fixture_dir, "credential_creation")
    built = credential_creation_case()
    assert checked_in.snapshot.model_dump(mode="json") == built.snapshot.model_dump(mode="json")


def test_each_fixture_has_the_expected_local_verdict(fixture_dir) -> None:
    for case_id, (finding_count, status) in EXPECTATIONS.items():
        case = load_fixture(fixture_dir, case_id)
        report = analyze(
            case.rules,
            case.snapshot,
            condition_resolutions=case.condition_resolutions,
            evaluated_at=case.evaluated_at,
        )
        assert len(report.findings) == finding_count
        assert len(report.attack_paths) == finding_count
        assert len(report.verifications) == finding_count
        if status is None:
            assert report.verifications == []
            assert report.truncation_reasons == []
            continue
        verification = report.verifications[0]
        assert verification.status == status
        assert verification.policy_simulation.status == "not_run"
        assert verification.sandbox.status == "not_mapped"
        assert LOCAL_LIMITATION in verification.limitations
        assert report.findings[0].verification_id == verification.verification_id
        assert report.findings[0].explanation.simulator == "not_run"
        assert report.findings[0].remediation[0].requires_human_review is True
        assert verification.status not in {
            VerificationStatus.supported_by_policy_simulation,
            VerificationStatus.denied_by_policy_simulation,
            VerificationStatus.verified_in_mapped_sandbox,
        }


def test_positive_fixture_is_the_known_two_hop_path(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "positive")
    report = analyze(
        case.rules,
        case.snapshot,
        condition_resolutions=case.condition_resolutions,
        evaluated_at=case.evaluated_at,
    )
    path = report.attack_paths[0]
    assert path.start_node_id == "principal:user/alice"
    assert path.goal_node_id == "principal:role/admin"
    assert [hop.edge_id for hop in path.hops] == ["edge_alice_dev", "edge_dev_admin"]
    assert report.findings[0].priority.value == "high"
    assert "policy_dev_admin" in report.findings[0].explanation.evidence


def test_positive_fixture_fails_closed_without_the_trust_edge(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "positive")
    edges = [edge for edge in case.snapshot.edges if edge.edge_type != EdgeType.TRUSTS]
    snapshot = case.snapshot.model_copy(update={"edges": edges})
    report = analyze(case.rules, snapshot, evaluated_at=case.evaluated_at)
    assert report.findings == []
    assert any(issue.code == "precondition_not_met" for issue in report.issues)


def test_cyclic_fixture_returns_one_simple_path(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "cyclic")
    report = analyze(case.rules, case.snapshot, evaluated_at=case.evaluated_at)
    path = report.attack_paths[0]
    node_ids = [path.start_node_id, *[hop.resource for hop in path.hops]]
    assert node_ids == ["principal:a", "principal:b", "principal:c"]
    assert len(node_ids) == len(set(node_ids))
    assert [hop.edge_id for hop in path.hops] == ["edge_a_b", "edge_b_c"]


def test_missing_context_names_the_gap(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "missing_context")
    report = analyze(case.rules, case.snapshot, evaluated_at=case.evaluated_at)
    missing = report.verifications[0].local_fixture.missing_context
    assert "collection" in missing
    assert "edge_dev_admin:aws:MultiFactorAuthPresent" in missing


def test_repeated_analysis_is_deterministic(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "cyclic")
    first = analyze(case.rules, case.snapshot, evaluated_at=case.evaluated_at)
    second = analyze(list(reversed(case.rules)), case.snapshot, evaluated_at=case.evaluated_at)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
