"""The six synthetic cases required by the first vertical slice."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from fyp_iam.contracts.models import (
    ApprovedRule,
    AuthorizationEffect,
    ConditionResolution,
    EdgeType,
    GraphNode,
    IAMGraphSnapshot,
    NodeType,
    Precondition,
    SnapshotValidationStatus,
)
from fyp_iam.fixtures.builders import (
    EVALUATED_AT,
    assume_chain_rule,
    make_edge,
    make_node,
    make_snapshot,
    principal,
)


class FixtureCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(pattern=r"^[a-z0-9_]+$")
    description: str = Field(min_length=1, max_length=500)
    rules: list[ApprovedRule] = Field(min_length=1)
    snapshot: IAMGraphSnapshot
    condition_resolutions: dict[str, ConditionResolution] = Field(default_factory=dict)
    evaluated_at: datetime


def _chain_nodes() -> list[GraphNode]:
    return [
        principal("principal:user/alice", "alice", "iam_user"),
        principal("principal:role/dev", "dev", "iam_role"),
        principal("principal:role/admin", "admin", "iam_role"),
    ]


def positive_case() -> FixtureCase:
    nodes = [
        *_chain_nodes(),
        make_node(
            "service:lambda.amazonaws.com",
            NodeType.service,
            "lambda.amazonaws.com",
            subtype="aws_service",
            properties={"service_principal": "lambda.amazonaws.com"},
        ),
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
        ),
        make_edge(
            "edge_admin_trusts_lambda",
            EdgeType.TRUSTS,
            "principal:role/admin",
            "service:lambda.amazonaws.com",
            "policy_admin_trust",
        ),
    ]
    rule = assume_chain_rule(
        "rule_positive_assume_chain",
        preconditions=[
            Precondition(
                type="role_trusts_service",
                subject="admin_role",
                value="lambda.amazonaws.com",
            )
        ],
    )
    return FixtureCase(
        case_id="positive",
        description="Known two-hop CAN_ASSUME path whose administrative role trusts Lambda.",
        rules=[rule],
        snapshot=make_snapshot("snapshot_positive", nodes, edges),
        evaluated_at=EVALUATED_AT,
    )


def hard_negative_case() -> FixtureCase:
    edges = [
        make_edge(
            "edge_alice_access_dev",
            EdgeType.CAN_ACCESS,
            "principal:user/alice",
            "principal:role/dev",
            "policy_access_dev",
        ),
        make_edge(
            "edge_dev_access_admin",
            EdgeType.CAN_ACCESS,
            "principal:role/dev",
            "principal:role/admin",
            "policy_access_admin",
        ),
    ]
    return FixtureCase(
        case_id="hard_negative",
        description=(
            "Same principals, but only CAN_ACCESS edges, so the assume-chain rule does not match."
        ),
        rules=[assume_chain_rule("rule_hard_negative")],
        snapshot=make_snapshot("snapshot_hard_negative", _chain_nodes(), edges),
        evaluated_at=EVALUATED_AT,
    )


def explicit_deny_case() -> FixtureCase:
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
            "policy_dev_admin_deny",
            effect=AuthorizationEffect.deny,
        ),
    ]
    return FixtureCase(
        case_id="explicit_deny",
        description="The second derived hop is an explicit deny.",
        rules=[assume_chain_rule("rule_explicit_deny")],
        snapshot=make_snapshot("snapshot_explicit_deny", _chain_nodes(), edges),
        evaluated_at=EVALUATED_AT,
    )


def condition_dependent_case() -> FixtureCase:
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
            "policy_dev_admin_mfa",
            conditions={"aws:MultiFactorAuthPresent": "true"},
        ),
    ]
    return FixtureCase(
        case_id="condition_dependent",
        description=(
            "The second hop has a condition key. Fixture context marks it satisfied. "
            "The condition value itself is not evaluated as IAM logic."
        ),
        rules=[assume_chain_rule("rule_condition_dependent")],
        snapshot=make_snapshot("snapshot_condition_dependent", _chain_nodes(), edges),
        condition_resolutions={"edge_dev_admin": ConditionResolution.satisfied},
        evaluated_at=EVALUATED_AT,
    )


def cyclic_case() -> FixtureCase:
    nodes = [
        principal("principal:a", "a", "iam_role"),
        principal("principal:b", "b", "iam_role"),
        principal("principal:c", "c", "iam_role"),
    ]
    edges = [
        make_edge("edge_a_b", EdgeType.CAN_ASSUME, "principal:a", "principal:b", "policy_a_b"),
        make_edge("edge_b_a", EdgeType.CAN_ASSUME, "principal:b", "principal:a", "policy_b_a"),
        make_edge("edge_b_c", EdgeType.CAN_ASSUME, "principal:b", "principal:c", "policy_b_c"),
    ]
    return FixtureCase(
        case_id="cyclic",
        description="A cycle between a and b exists, and one simple path reaches c.",
        rules=[assume_chain_rule("rule_cyclic")],
        snapshot=make_snapshot("snapshot_cyclic", nodes, edges),
        evaluated_at=EVALUATED_AT,
    )


def missing_context_case() -> FixtureCase:
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
            "policy_dev_admin_mfa",
            conditions={"aws:MultiFactorAuthPresent": "true"},
        ),
    ]
    return FixtureCase(
        case_id="missing_context",
        description="Collection is incomplete and the condition has no fixture resolution.",
        rules=[assume_chain_rule("rule_missing_context")],
        snapshot=make_snapshot(
            "snapshot_missing_context",
            _chain_nodes(),
            edges,
            complete=False,
            warnings=["condition context was not collected"],
            validation_status=SnapshotValidationStatus.valid_with_warnings,
        ),
        evaluated_at=EVALUATED_AT,
    )


def all_cases() -> list[FixtureCase]:
    return [
        positive_case(),
        hard_negative_case(),
        explicit_deny_case(),
        condition_dependent_case(),
        cyclic_case(),
        missing_context_case(),
    ]
