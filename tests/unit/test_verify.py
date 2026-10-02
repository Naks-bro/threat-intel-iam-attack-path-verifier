from datetime import UTC, datetime

from fyp_iam.contracts.models import (
    ApprovedRule,
    AttackHop,
    AuthorizationEffect,
    ConditionResolution,
    DiscoveryInfo,
    DiscoveryLimits,
    EdgeConfidence,
    EdgeType,
    PatternStep,
    Precondition,
    RuleStatus,
    SnapshotValidationStatus,
    VerificationStatus,
)
from fyp_iam.engine3.discovery import Walk
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.engine3.verify import (
    LOCAL_LIMITATION,
    build_attack_path,
    verify_path,
)
from fyp_iam.fixtures.builders import (
    assume_chain_rule,
    make_edge,
    make_snapshot,
    principal,
)
from fyp_iam.fixtures.cases import positive_case

WHEN = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)


def _allow_path() -> tuple[object, object, object]:
    nodes = [
        principal("principal:user/alice", "alice", "iam_user"),
        principal("principal:role/dev", "dev", "iam_role"),
        principal("principal:role/admin", "admin", "iam_role"),
    ]
    edges = [
        make_edge(
            "edge_alice_dev",
            EdgeType.CAN_ASSUME,
            "principal:user/alice",
            "principal:role/dev",
            "policy_alice_dev",
        ),
        make_edge(
            "edge_dev_admin",
            EdgeType.CAN_ASSUME,
            "principal:role/dev",
            "principal:role/admin",
            "policy_dev_admin",
            effect=AuthorizationEffect.deny,
        ),
    ]
    snapshot = make_snapshot("snapshot_verify", nodes, edges)
    rule = assume_chain_rule("rule_verify")
    path = build_attack_path(
        snapshot,
        rule,
        Walk(
            ("principal:user/alice", "principal:role/dev", "principal:role/admin"),
            ("edge_alice_dev", "edge_dev_admin"),
        ),
        DiscoveryInfo(algorithm="bounded_bfs", max_hops=4, limits=DiscoveryLimits()),
    )
    return snapshot, rule, path


def test_explicit_deny_is_not_called_policy_simulation() -> None:
    snapshot, rule, path = _allow_path()
    result = verify_path(snapshot, rule, path, {}, WHEN)
    assert result.status == VerificationStatus.denied_by_fixture
    assert result.policy_simulation.status == "not_run"
    assert result.sandbox.status == "not_mapped"
    assert LOCAL_LIMITATION in result.limitations
    assert result.local_fixture.denied_edge_ids == ["edge_dev_admin"]


def test_condition_value_true_is_not_implicitly_satisfied() -> None:
    nodes = [
        principal("principal:user/alice", "alice", "iam_user"),
        principal("principal:role/admin", "admin", "iam_role"),
    ]
    edges = [
        make_edge(
            "edge_direct",
            EdgeType.CAN_ASSUME,
            "principal:user/alice",
            "principal:role/admin",
            "policy_mfa",
            conditions={"aws:MultiFactorAuthPresent": "true"},
        )
    ]
    snapshot = make_snapshot("snapshot_condition_value", nodes, edges)
    rule = assume_chain_rule("rule_condition_value").model_copy(
        update={
            "path_pattern": [
                PatternStep(
                    from_role="principal",
                    relationship=EdgeType.CAN_ASSUME,
                    to_role="admin_role",
                )
            ]
        }
    )
    report = analyze([rule], snapshot, evaluated_at=WHEN)
    assert report.verifications[0].status == VerificationStatus.inconclusive
    assert (
        "edge_direct:aws:MultiFactorAuthPresent"
        in report.verifications[0].local_fixture.missing_context
    )


def test_unsupported_condition_is_inconclusive() -> None:
    case = positive_case()
    edges = [
        make_edge(
            "edge_alice_dev",
            EdgeType.CAN_ASSUME,
            "principal:user/alice",
            "principal:role/dev",
            "policy_alice_dev",
        ),
        make_edge(
            "edge_dev_admin",
            EdgeType.CAN_ASSUME,
            "principal:role/dev",
            "principal:role/admin",
            "policy_condition",
            conditions={"aws:RequestedRegion": "ap-south-1"},
        ),
    ]
    snapshot = make_snapshot("snapshot_unsupported", case.snapshot.nodes[:3], edges)
    report = analyze(
        [assume_chain_rule("rule_unsupported")],
        snapshot,
        condition_resolutions={"edge_dev_admin": ConditionResolution.unsupported},
        evaluated_at=WHEN,
    )
    assert report.verifications[0].status == VerificationStatus.inconclusive
    assert report.verifications[0].local_fixture.unsupported_conditions


def test_incomplete_collection_outranks_explicit_deny() -> None:
    snapshot, rule, path = _allow_path()
    incomplete = snapshot.model_copy(
        update={"collection": snapshot.collection.model_copy(update={"complete": False})}
    )
    result = verify_path(incomplete, rule, path, {}, WHEN)
    assert result.status == VerificationStatus.inconclusive


def test_unknown_confidence_is_inconclusive() -> None:
    nodes = [
        principal("principal:user/alice", "alice", "iam_user"),
        principal("principal:role/dev", "dev", "iam_role"),
        principal("principal:role/admin", "admin", "iam_role"),
    ]
    edges = [
        make_edge(
            "edge_alice_dev",
            EdgeType.CAN_ASSUME,
            "principal:user/alice",
            "principal:role/dev",
            "policy_alice_dev",
            confidence=EdgeConfidence.unknown,
        ),
        make_edge(
            "edge_dev_admin",
            EdgeType.CAN_ASSUME,
            "principal:role/dev",
            "principal:role/admin",
            "policy_dev_admin",
        ),
    ]
    snapshot = make_snapshot("snapshot_unknown", nodes, edges)
    report = analyze([assume_chain_rule("rule_unknown")], snapshot, evaluated_at=WHEN)
    assert report.verifications[0].status == VerificationStatus.inconclusive


def test_missing_edge_is_an_operational_error() -> None:
    snapshot, rule, path = _allow_path()
    broken = path.model_copy(
        update={
            "hops": [
                AttackHop(
                    position=0,
                    edge_id="edge_absent",
                    required_action="CAN_ASSUME",
                    resource="principal:role/dev",
                    effect=AuthorizationEffect.allow,
                )
            ]
        }
    )
    result = verify_path(snapshot, rule, broken, {}, WHEN)
    assert result.status == VerificationStatus.error


def test_description_is_not_executed() -> None:
    import inspect

    import fyp_iam.engine3.pipeline as pipeline

    source = inspect.getsource(pipeline)
    assert "subprocess" not in source
    assert "os.system" not in source
    payload = assume_chain_rule("rule_text").model_dump(mode="json", by_alias=True)
    payload["description"] = "MATCH (n) DETACH DELETE n; rm -rf /"
    rule = ApprovedRule.model_validate(payload)
    case = positive_case()
    report = analyze([rule], case.snapshot, evaluated_at=WHEN)
    assert report.findings[0].explanation.simulator == "not_run"


def test_invalid_snapshot_status_skips_verification() -> None:
    case = positive_case()
    invalid = case.snapshot.model_copy(
        update={
            "validation": case.snapshot.validation.model_copy(
                update={
                    "status": SnapshotValidationStatus.invalid,
                    "errors": ["synthetic invalid flag"],
                }
            )
        }
    )
    report = analyze(case.rules, invalid, evaluated_at=WHEN)
    assert report.findings == []
    assert report.issues[0].code == "snapshot_invalid"


def test_unapproved_rule_is_skipped() -> None:
    case = positive_case()
    rejected = assume_chain_rule("rule_rejected", status=RuleStatus.rejected)
    report = analyze([rejected], case.snapshot, evaluated_at=WHEN)
    assert report.findings == []
    assert report.issues[0].code == "rule_not_approved"


def test_unsupported_precondition_is_explicit() -> None:
    case = positive_case()
    rule = case.rules[0].model_copy(
        update={
            "preconditions": [Precondition(type="scp_allows", subject="admin_role", value="yes")]
        }
    )
    report = analyze([rule], case.snapshot, evaluated_at=WHEN)
    assert report.findings == []
    assert report.issues[0].code == "unsupported_precondition"
