"""Normalized records should agree with the hand-built fixture verdicts."""

from fyp_iam.contracts.models import (
    AuthorizationEffect,
    ConditionResolution,
    EdgeType,
    IAMGraphSnapshot,
    VerificationStatus,
)
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine2.compare import capability_pairs
from fyp_iam.engine2.normalize import normalize_synthetic_account
from fyp_iam.engine2.records import (
    IdentityRecord,
    IdentityStatement,
    SyntheticAccount,
    TrustStatement,
)
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.fixtures.cases import (
    FixtureCase,
    condition_dependent_case,
    cyclic_case,
    explicit_deny_case,
    hard_negative_case,
    missing_context_case,
    positive_case,
)

ALICE = "principal:user/alice"
DEV = "principal:role/dev"
ADMIN = "principal:role/admin"
LAMBDA = "service:lambda.amazonaws.com"


def _statement(
    statement_id: str,
    resource_ids: list[str],
    *,
    effect: AuthorizationEffect = AuthorizationEffect.allow,
    actions: list[str] | None = None,
    conditions: list[str] | None = None,
) -> IdentityStatement:
    return IdentityStatement(
        statement_id=statement_id,
        effect=effect,
        actions=actions or ["sts:AssumeRole"],
        resource_ids=resource_ids,
        condition_keys=conditions or [],
    )


def _trust(statement_id: str, principal_id: str) -> TrustStatement:
    return TrustStatement(
        statement_id=statement_id,
        effect=AuthorizationEffect.allow,
        actions=["sts:AssumeRole"],
        principal_ids=[principal_id],
    )


def _chain(
    *,
    second_effect: AuthorizationEffect = AuthorizationEffect.allow,
    second_conditions: list[str] | None = None,
    extra_alice: IdentityStatement | None = None,
    lambda_trust: bool = False,
) -> SyntheticAccount:
    alice_statements = [_statement("stmt_alice_dev", [DEV])]
    if extra_alice is not None:
        alice_statements.append(extra_alice)
    admin_trusts = [_trust("trust_admin_dev", DEV)]
    if lambda_trust:
        admin_trusts.append(_trust("trust_admin_lambda", LAMBDA))
    return SyntheticAccount(
        snapshot_id="snapshot_compared",
        identities=[
            IdentityRecord(
                node_id=ALICE,
                display_name="alice",
                subtype="iam_user",
                identity_statements=alice_statements,
            ),
            IdentityRecord(
                node_id=DEV,
                display_name="dev",
                subtype="iam_role",
                identity_statements=[
                    _statement(
                        "stmt_dev_admin",
                        [ADMIN],
                        effect=second_effect,
                        conditions=second_conditions,
                    )
                ],
                trust_statements=[_trust("trust_dev_alice", ALICE)],
            ),
            IdentityRecord(
                node_id=ADMIN,
                display_name="admin",
                subtype="iam_role",
                trust_statements=admin_trusts,
            ),
        ],
    )


def _endpoint_resolutions(
    snapshot: IAMGraphSnapshot, fixture: FixtureCase
) -> dict[str, ConditionResolution]:
    endpoints = {edge.edge_id: (edge.source_id, edge.target_id) for edge in fixture.snapshot.edges}
    wanted = {
        endpoints[edge_id]: resolution
        for edge_id, resolution in fixture.condition_resolutions.items()
    }
    mapped: dict[str, ConditionResolution] = {}
    for edge in snapshot.edges:
        key = (edge.source_id, edge.target_id)
        if key in wanted and edge.edge_type == EdgeType.CAN_ASSUME:
            mapped[edge.edge_id] = wanted[key]
    return mapped


def _compare(
    account: SyntheticAccount, fixture: FixtureCase
) -> tuple[AnalysisReport, AnalysisReport]:
    snapshot = normalize_synthetic_account(account)
    assert capability_pairs(snapshot) == capability_pairs(fixture.snapshot)
    normalized = analyze(
        fixture.rules,
        snapshot,
        condition_resolutions=_endpoint_resolutions(snapshot, fixture),
        evaluated_at=fixture.evaluated_at,
    )
    expected = analyze(
        fixture.rules,
        fixture.snapshot,
        condition_resolutions=fixture.condition_resolutions,
        evaluated_at=fixture.evaluated_at,
    )
    assert [item.status for item in normalized.verifications] == [
        item.status for item in expected.verifications
    ]
    return normalized, expected


def test_positive_records_match_the_fixture() -> None:
    normalized, expected = _compare(_chain(lambda_trust=True), positive_case())
    assert normalized.verifications[0].status == VerificationStatus.supported_by_fixture
    assert expected.verifications[0].status == VerificationStatus.supported_by_fixture
    assert normalized.verifications[0].policy_simulation.status == "not_run"


def test_explicit_deny_records_match_the_fixture() -> None:
    normalized, _expected = _compare(
        _chain(second_effect=AuthorizationEffect.deny),
        explicit_deny_case(),
    )
    assert normalized.verifications[0].status == VerificationStatus.denied_by_fixture


def test_satisfied_condition_records_match_the_fixture() -> None:
    account = _chain(second_conditions=["aws:MultiFactorAuthPresent"])
    normalized, _expected = _compare(account, condition_dependent_case())
    assert normalized.verifications[0].status == VerificationStatus.supported_by_fixture
    snapshot = normalize_synthetic_account(account)
    conditioned = [
        edge for edge in snapshot.edges if edge.source_id == DEV and edge.target_id == ADMIN
    ]
    assert conditioned[0].condition_summary == {"aws:MultiFactorAuthPresent": "unevaluated"}
    assert "true" not in conditioned[0].condition_summary.values()


def test_missing_context_records_match_the_fixture() -> None:
    account = _chain(
        second_conditions=["aws:MultiFactorAuthPresent"],
        extra_alice=_statement("stmt_s3", [DEV], actions=["s3:GetObject"]),
    )
    snapshot = normalize_synthetic_account(account)
    assert snapshot.collection.complete is False
    normalized, expected = _compare(account, missing_context_case())
    assert normalized.verifications[0].status == VerificationStatus.inconclusive
    assert "collection" in normalized.verifications[0].local_fixture.missing_context
    assert "collection" in expected.verifications[0].local_fixture.missing_context


def test_cyclic_records_match_the_fixture() -> None:
    account = SyntheticAccount(
        snapshot_id="snapshot_compared_cycle",
        identities=[
            IdentityRecord(
                node_id="principal:a",
                display_name="a",
                subtype="iam_role",
                identity_statements=[_statement("stmt_a_b", ["principal:b"])],
                trust_statements=[_trust("trust_a_b", "principal:b")],
            ),
            IdentityRecord(
                node_id="principal:b",
                display_name="b",
                subtype="iam_role",
                identity_statements=[_statement("stmt_b", ["principal:a", "principal:c"])],
                trust_statements=[_trust("trust_b_a", "principal:a")],
            ),
            IdentityRecord(
                node_id="principal:c",
                display_name="c",
                subtype="iam_role",
                trust_statements=[_trust("trust_c_b", "principal:b")],
            ),
        ],
    )
    normalized, expected = _compare(account, cyclic_case())
    assert len(normalized.attack_paths) == 1
    assert [hop.resource for hop in normalized.attack_paths[0].hops] == [
        hop.resource for hop in expected.attack_paths[0].hops
    ]
    assert normalized.attack_paths[0].start_node_id == "principal:a"


def test_unrelated_access_has_the_same_empty_verdict() -> None:
    account = SyntheticAccount(
        snapshot_id="snapshot_compared_negative",
        identities=[
            IdentityRecord(
                node_id=ALICE,
                display_name="alice",
                subtype="iam_user",
                identity_statements=[_statement("stmt_s3", [DEV], actions=["s3:GetObject"])],
            ),
            IdentityRecord(
                node_id=DEV,
                display_name="dev",
                subtype="iam_role",
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
    fixture = hard_negative_case()
    snapshot = normalize_synthetic_account(account)
    assert all(edge.edge_type != EdgeType.CAN_ASSUME for edge in snapshot.edges)
    assert EdgeType.CAN_ACCESS.value not in {item[0] for item in capability_pairs(snapshot)}
    normalized = analyze(fixture.rules, snapshot, evaluated_at=fixture.evaluated_at)
    expected = analyze(fixture.rules, fixture.snapshot, evaluated_at=fixture.evaluated_at)
    assert normalized.findings == []
    assert expected.findings == []
