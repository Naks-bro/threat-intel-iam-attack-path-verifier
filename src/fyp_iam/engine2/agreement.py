"""Score normalized records against the hand-built fixture capability edges."""

from pydantic import Field

from fyp_iam.contracts.models import AuthorizationEffect, ContractModel
from fyp_iam.engine2.compare import capability_pairs, pair_scores
from fyp_iam.engine2.normalize import normalize_synthetic_account
from fyp_iam.engine2.records import (
    IdentityRecord,
    IdentityStatement,
    SyntheticAccount,
    TrustStatement,
)
from fyp_iam.fixtures.cases import (
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


class EdgeAgreement(ContractModel):
    case_id: str = Field(pattern=r"^[a-z0-9_]+$")
    comparable: bool
    precision: float | None = Field(default=None, ge=0, le=1)
    recall: float | None = Field(default=None, ge=0, le=1)
    note: str = Field(min_length=1, max_length=200)


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


def _cycle() -> SyntheticAccount:
    return SyntheticAccount(
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


def graph_edge_agreement() -> list[EdgeAgreement]:
    """Compare normalized capability edges with the hand-built fixtures.

    ``hard_negative`` uses ``CAN_ACCESS``, which this normalizer does not emit,
    so that case is reported and not scored.
    """
    comparable = (
        ("positive", _chain(lambda_trust=True), positive_case()),
        ("explicit_deny", _chain(second_effect=AuthorizationEffect.deny), explicit_deny_case()),
        (
            "condition_dependent",
            _chain(second_conditions=["aws:MultiFactorAuthPresent"]),
            condition_dependent_case(),
        ),
        (
            "missing_context",
            _chain(
                second_conditions=["aws:MultiFactorAuthPresent"],
                extra_alice=_statement("stmt_s3", [DEV], actions=["s3:GetObject"]),
            ),
            missing_context_case(),
        ),
        ("cyclic", _cycle(), cyclic_case()),
    )
    scores: list[EdgeAgreement] = []
    for case_id, account, fixture in comparable:
        precision, recall = pair_scores(
            capability_pairs(fixture.snapshot),
            capability_pairs(normalize_synthetic_account(account)),
        )
        scores.append(
            EdgeAgreement(
                case_id=case_id,
                comparable=True,
                precision=precision,
                recall=recall,
                note="Capability pairs compared. This is not exploitability.",
            )
        )
    scores.append(
        EdgeAgreement(
            case_id=hard_negative_case().case_id,
            comparable=False,
            note="CAN_ACCESS is outside the normalizer vocabulary and is not scored.",
        )
    )
    return scores
