import inspect
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from fyp_iam.contracts.models import (
    AuthorizationEffect,
    EdgeType,
    Precondition,
    VerificationStatus,
)
from fyp_iam.engine2.coverage import LayerState, assert_reconciled
from fyp_iam.engine2.live import LiveCollectionDisabled, collect_live_account
from fyp_iam.engine2.normalize import normalize_synthetic_account, normalize_with_coverage
from fyp_iam.engine2.records import (
    IdentityRecord,
    IdentityStatement,
    SyntheticAccount,
    TrustStatement,
)
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.fixtures.builders import assume_chain_rule

WHEN = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
ALICE = "principal:user/alice"
DEV = "principal:role/dev"
ADMIN = "principal:role/admin"


def _allow(
    statement_id: str,
    resource_id: str,
    conditions: list[str] | None = None,
) -> IdentityStatement:
    return IdentityStatement(
        statement_id=statement_id,
        effect=AuthorizationEffect.allow,
        actions=["sts:AssumeRole"],
        resource_ids=[resource_id],
        condition_keys=conditions or [],
    )


def _trust(
    statement_id: str,
    principal_id: str,
    *,
    effect: AuthorizationEffect = AuthorizationEffect.allow,
) -> TrustStatement:
    return TrustStatement(
        statement_id=statement_id,
        effect=effect,
        actions=["sts:AssumeRole"],
        principal_ids=[principal_id],
    )


def _account() -> SyntheticAccount:
    return SyntheticAccount(
        snapshot_id="snapshot_normalized_chain",
        identities=[
            IdentityRecord(
                node_id=ALICE,
                display_name="alice",
                subtype="iam_user",
                identity_statements=[_allow("stmt_alice_dev", DEV)],
            ),
            IdentityRecord(
                node_id=DEV,
                display_name="dev",
                subtype="iam_role",
                identity_statements=[_allow("stmt_dev_admin", ADMIN)],
                trust_statements=[_trust("trust_dev_alice", ALICE)],
            ),
            IdentityRecord(
                node_id=ADMIN,
                display_name="admin",
                subtype="iam_role",
                trust_statements=[_trust("trust_admin_dev", DEV)],
            ),
        ],
    )


def _assume_edges(snapshot: object) -> list:
    return [edge for edge in snapshot.edges if edge.edge_type == EdgeType.CAN_ASSUME]  # type: ignore[attr-defined]


def test_normalized_chain_is_supported_by_the_existing_verifier() -> None:
    snapshot = normalize_synthetic_account(_account())
    pairs = {(edge.source_id, edge.target_id, edge.effect) for edge in _assume_edges(snapshot)}
    assert pairs == {
        (ALICE, DEV, AuthorizationEffect.allow),
        (DEV, ADMIN, AuthorizationEffect.allow),
    }
    assert all(edge.confidence.value == "deterministic" for edge in _assume_edges(snapshot))
    assert any(edge.edge_type == EdgeType.HAS_POLICY for edge in snapshot.edges)
    report = analyze([assume_chain_rule("rule_normalized")], snapshot, evaluated_at=WHEN)
    assert report.verifications[0].status == VerificationStatus.supported_by_fixture
    assert report.findings[0].explanation.simulator == "not_run"


def test_normalization_is_deterministic() -> None:
    first = normalize_synthetic_account(_account())
    second = normalize_synthetic_account(_account())
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_unrelated_action_does_not_become_an_assume_edge() -> None:
    account = SyntheticAccount(
        snapshot_id="snapshot_s3_only",
        identities=[
            IdentityRecord(
                node_id=ALICE,
                display_name="alice",
                subtype="iam_user",
                identity_statements=[
                    IdentityStatement(
                        statement_id="stmt_s3",
                        effect=AuthorizationEffect.allow,
                        actions=["s3:GetObject"],
                        resource_ids=[DEV],
                    )
                ],
            ),
            IdentityRecord(
                node_id=DEV,
                display_name="dev",
                subtype="iam_role",
                trust_statements=[_trust("trust_dev_alice", ALICE)],
            ),
        ],
    )
    snapshot = normalize_synthetic_account(account)
    assert _assume_edges(snapshot) == []
    assert snapshot.collection.complete is False
    report = analyze([assume_chain_rule("rule_s3")], snapshot, evaluated_at=WHEN)
    assert report.findings == []


def test_explicit_deny_survives_normalization() -> None:
    account = _account()
    account.identities[0].identity_statements[0] = IdentityStatement(
        statement_id="stmt_alice_dev_deny",
        effect=AuthorizationEffect.deny,
        actions=["sts:AssumeRole"],
        resource_ids=[DEV],
    )
    snapshot = normalize_synthetic_account(account)
    denied = [
        edge
        for edge in _assume_edges(snapshot)
        if edge.source_id == ALICE and edge.effect == AuthorizationEffect.deny
    ]
    assert len(denied) == 1
    report = analyze([assume_chain_rule("rule_deny")], snapshot, evaluated_at=WHEN)
    assert any(item.status == VerificationStatus.denied_by_fixture for item in report.verifications)


def test_condition_key_is_not_evaluated() -> None:
    account = _account()
    account.identities[1].identity_statements[0] = _allow(
        "stmt_dev_admin", ADMIN, conditions=["aws:MultiFactorAuthPresent"]
    )
    snapshot = normalize_synthetic_account(account)
    conditioned = [edge for edge in _assume_edges(snapshot) if edge.target_id == ADMIN]
    assert conditioned[0].condition_summary == {"aws:MultiFactorAuthPresent": "unevaluated"}
    assert conditioned[0].confidence.value == "deterministic"
    report = analyze([assume_chain_rule("rule_condition")], snapshot, evaluated_at=WHEN)
    assert any(item.status == VerificationStatus.inconclusive for item in report.verifications)


def test_wildcard_action_is_not_treated_as_allow() -> None:
    account = _account()
    account.identities[0].identity_statements[0] = IdentityStatement(
        statement_id="stmt_wild",
        effect=AuthorizationEffect.allow,
        actions=["sts:*"],
        resource_ids=[DEV],
    )
    snapshot = normalize_synthetic_account(account)
    assert all(edge.source_id != ALICE for edge in _assume_edges(snapshot))
    assert snapshot.collection.complete is False


def test_missing_trust_does_not_emit_assume() -> None:
    account = _account()
    account.identities[1].trust_statements = []
    snapshot = normalize_synthetic_account(account)
    assert all(edge.source_id != ALICE for edge in _assume_edges(snapshot))


def test_live_collector_makes_no_aws_call() -> None:
    import fyp_iam.engine2.live as live
    import fyp_iam.engine2.normalize as normalize

    source = inspect.getsource(live) + inspect.getsource(normalize)
    assert "boto3" not in source
    assert "subprocess" not in source
    with pytest.raises(LiveCollectionDisabled):
        collect_live_account()


def test_user_trust_policy_is_rejected() -> None:
    with pytest.raises(ValidationError):
        IdentityRecord(
            node_id=ALICE,
            display_name="alice",
            subtype="iam_user",
            trust_statements=[_trust("trust_user", DEV)],
        )


def test_normalized_snapshot_has_no_raw_arn() -> None:
    payload = normalize_synthetic_account(_account()).model_dump_json()
    assert "arn:aws:" not in payload


def test_coverage_counts_match_the_input_records() -> None:
    snapshot, coverage = normalize_with_coverage(_account())
    assert coverage.reconciled is True
    assert coverage.identity_count == 3
    assert coverage.identity_statement_count == 2
    assert coverage.trust_statement_count == 2
    assert coverage.can_assume_count == 2
    assert coverage.has_policy_count == 3
    assert coverage.has_boundary_count == 0
    assert coverage.identity_policy == LayerState.limited
    assert coverage.trust_policy == LayerState.limited
    assert coverage.permissions_boundary == LayerState.absent
    assert coverage.service_control_policy == LayerState.not_collected
    assert snapshot.collection.complete is True


def test_permissions_boundary_is_recorded_and_not_treated_as_allow() -> None:
    account = _account()
    account.identities[1].boundary_id = "boundary:dev-cap"
    snapshot, coverage = normalize_with_coverage(account)
    boundaries = [edge for edge in snapshot.edges if edge.edge_type == EdgeType.HAS_BOUNDARY]
    assert len(boundaries) == 1
    assert boundaries[0].source_id == DEV
    assert boundaries[0].target_id == "boundary:dev-cap"
    assert boundaries[0].confidence.value == "unknown"
    assume = [edge for edge in _assume_edges(snapshot) if edge.source_id == DEV]
    assert len(assume) == 1
    assert assume[0].confidence.value == "unknown"
    assert coverage.permissions_boundary == LayerState.recorded_not_evaluated
    assert coverage.has_boundary_count == 1
    assert snapshot.collection.complete is True
    report = analyze([assume_chain_rule("rule_boundary")], snapshot, evaluated_at=WHEN)
    assert report.verifications[0].status == VerificationStatus.inconclusive


def test_shared_boundary_is_one_policy_node() -> None:
    account = _account()
    account.identities[1].boundary_id = "boundary:shared"
    account.identities[2].boundary_id = "boundary:shared"
    snapshot, coverage = normalize_with_coverage(account)
    boundary_nodes = [node for node in snapshot.nodes if node.subtype == "permissions_boundary"]
    assert len(boundary_nodes) == 1
    assert coverage.has_boundary_count == 2


def test_unreferenced_wildcard_trust_marks_collection_incomplete() -> None:
    account = SyntheticAccount(
        snapshot_id="snapshot_wild_trust",
        identities=[
            IdentityRecord(node_id=ALICE, display_name="alice", subtype="iam_user"),
            IdentityRecord(
                node_id=DEV,
                display_name="dev",
                subtype="iam_role",
                trust_statements=[
                    TrustStatement(
                        statement_id="trust_wild",
                        effect=AuthorizationEffect.allow,
                        actions=["sts:*"],
                        principal_ids=[ALICE],
                    )
                ],
            ),
        ],
    )
    snapshot, coverage = normalize_with_coverage(account)
    assert _assume_edges(snapshot) == []
    assert snapshot.collection.complete is False
    assert coverage.trust_policy == LayerState.partial
    assert coverage.identity_policy == LayerState.absent


def _lambda_rule():
    return assume_chain_rule(
        "rule_lambda_trust",
        preconditions=[
            Precondition(
                type="role_trusts_service",
                subject="admin_role",
                value="lambda.amazonaws.com",
            )
        ],
    )


def _with_lambda_trust(
    *,
    effect: AuthorizationEffect = AuthorizationEffect.allow,
    conditions: list[str] | None = None,
) -> SyntheticAccount:
    account = _account()
    account.identities[2].trust_statements.append(
        TrustStatement(
            statement_id="trust_admin_lambda",
            effect=effect,
            actions=["sts:AssumeRole"],
            principal_ids=["service:lambda.amazonaws.com"],
            condition_keys=conditions or [],
        )
    )
    return account


def test_exact_service_trust_satisfies_the_approved_rule() -> None:
    snapshot, coverage = normalize_with_coverage(_with_lambda_trust())
    trusts = [edge for edge in snapshot.edges if edge.edge_type == EdgeType.TRUSTS]
    assert [(edge.source_id, edge.target_id, edge.effect) for edge in trusts] == [
        (ADMIN, "service:lambda.amazonaws.com", AuthorizationEffect.allow)
    ]
    service = next(node for node in snapshot.nodes if node.node_type.value == "service")
    assert service.properties["service_principal"] == "lambda.amazonaws.com"
    assert coverage.trust_policy == LayerState.limited
    assert snapshot.collection.complete is True
    report = analyze([_lambda_rule()], snapshot, evaluated_at=WHEN)
    assert report.verifications[0].status == VerificationStatus.supported_by_fixture
    assert report.verifications[0].policy_simulation.status == "not_run"


def test_missing_service_trust_does_not_satisfy_the_precondition() -> None:
    snapshot = normalize_synthetic_account(_account())
    report = analyze([_lambda_rule()], snapshot, evaluated_at=WHEN)
    assert report.findings == []
    assert any(issue.code == "precondition_not_met" for issue in report.issues)


def test_denied_service_trust_is_not_a_trust() -> None:
    snapshot = normalize_synthetic_account(_with_lambda_trust(effect=AuthorizationEffect.deny))
    trusts = [edge for edge in snapshot.edges if edge.edge_type == EdgeType.TRUSTS]
    assert trusts[0].effect == AuthorizationEffect.deny
    report = analyze([_lambda_rule()], snapshot, evaluated_at=WHEN)
    assert report.findings == []
    assert any(issue.code == "precondition_not_met" for issue in report.issues)


def test_service_trust_condition_stays_inconclusive() -> None:
    snapshot = normalize_synthetic_account(_with_lambda_trust(conditions=["aws:SourceAccount"]))
    trusts = [edge for edge in snapshot.edges if edge.edge_type == EdgeType.TRUSTS]
    assert trusts[0].condition_summary == {"aws:SourceAccount": "unevaluated"}
    assert trusts[0].confidence.value == "deterministic"
    report = analyze([_lambda_rule()], snapshot, evaluated_at=WHEN)
    assert report.verifications[0].status == VerificationStatus.inconclusive


def test_non_aws_service_name_does_not_become_a_trust() -> None:
    account = _account()
    account.identities[2].trust_statements.append(
        TrustStatement(
            statement_id="trust_admin_other",
            effect=AuthorizationEffect.allow,
            actions=["sts:AssumeRole"],
            principal_ids=["service:lambda.example.com"],
        )
    )
    snapshot, coverage = normalize_with_coverage(account)
    assert all(edge.edge_type != EdgeType.TRUSTS for edge in snapshot.edges)
    assert snapshot.collection.complete is False
    assert coverage.trust_policy == LayerState.partial


def test_reconciliation_rejects_a_dropped_edge() -> None:
    account = _account()
    snapshot = normalize_synthetic_account(account)
    kept = [edge for edge in snapshot.edges if edge.edge_type != EdgeType.HAS_POLICY]
    kept.extend(edge for edge in snapshot.edges if edge.edge_type == EdgeType.HAS_POLICY)
    broken = snapshot.model_copy(update={"edges": kept[:-1]})
    with pytest.raises(RuntimeError, match="did not reconcile"):
        assert_reconciled(account, broken)


def test_duplicate_identity_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SyntheticAccount(
            snapshot_id="snapshot_dup",
            identities=[
                IdentityRecord(node_id=ALICE, display_name="alice", subtype="iam_user"),
                IdentityRecord(node_id=ALICE, display_name="alice-again", subtype="iam_user"),
            ],
        )
