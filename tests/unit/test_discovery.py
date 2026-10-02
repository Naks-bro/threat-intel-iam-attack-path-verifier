from fyp_iam.contracts.models import (
    AuthorizationEffect,
    DiscoveryLimits,
    EdgeType,
    NodeType,
    PatternStep,
)
from fyp_iam.core.clock import SystemClock
from fyp_iam.engine3.discovery import discover_bound_walks
from fyp_iam.fixtures.builders import (
    assume_chain_rule,
    make_edge,
    make_node,
    make_snapshot,
    principal,
)


class ManualClock:
    def __init__(self) -> None:
        self._now = 0.0

    def monotonic(self) -> float:
        current = self._now
        self._now += 10.0
        return current

    def now(self) -> object:
        raise AssertionError("discovery does not need wall time")


def _two_hop_snapshot(edge_order: list[str]) -> object:
    nodes = [
        principal("principal:user/alice", "alice", "iam_user"),
        principal("principal:role/dev", "dev", "iam_role"),
        principal("principal:role/admin", "admin", "iam_role"),
    ]
    edges = {
        "edge_alice_dev": make_edge(
            "edge_alice_dev",
            EdgeType.CAN_ASSUME,
            "principal:user/alice",
            "principal:role/dev",
            "policy_alice_dev",
        ),
        "edge_dev_admin": make_edge(
            "edge_dev_admin",
            EdgeType.CAN_ASSUME,
            "principal:role/dev",
            "principal:role/admin",
            "policy_dev_admin",
        ),
    }
    return make_snapshot("snapshot_order", nodes, [edges[item] for item in edge_order])


def test_edge_insertion_order_does_not_change_walks() -> None:
    rule = assume_chain_rule("rule_order")
    forward = discover_bound_walks(
        _two_hop_snapshot(["edge_alice_dev", "edge_dev_admin"]),
        rule,
        DiscoveryLimits(),
        SystemClock(),
    )
    reverse = discover_bound_walks(
        _two_hop_snapshot(["edge_dev_admin", "edge_alice_dev"]),
        rule,
        DiscoveryLimits(),
        SystemClock(),
    )
    assert [item.walk.edge_ids for item in forward.walks] == [
        item.walk.edge_ids for item in reverse.walks
    ]
    assert forward.walks[0].walk.edge_ids == ("edge_alice_dev", "edge_dev_admin")


def test_paths_are_deduplicated_and_simple() -> None:
    nodes = [
        principal("principal:a", "a", "iam_role"),
        principal("principal:b", "b", "iam_role"),
        principal("principal:c", "c", "iam_role"),
    ]
    edges = [
        make_edge("edge_b_a", EdgeType.CAN_ASSUME, "principal:b", "principal:a", "policy_b_a"),
        make_edge("edge_a_b", EdgeType.CAN_ASSUME, "principal:a", "principal:b", "policy_a_b"),
        make_edge("edge_b_c", EdgeType.CAN_ASSUME, "principal:b", "principal:c", "policy_b_c"),
    ]
    batch = discover_bound_walks(
        make_snapshot("snapshot_cycle_unit", nodes, edges),
        assume_chain_rule("rule_cycle_unit"),
        DiscoveryLimits(),
        SystemClock(),
    )
    keys = [item.walk.edge_ids for item in batch.walks]
    assert len(keys) == len(set(keys))
    assert keys == [("edge_a_b", "edge_b_c")]
    for item in batch.walks:
        assert len(item.walk.node_ids) == len(set(item.walk.node_ids))


def test_max_hops_blocks_a_longer_pattern() -> None:
    batch = discover_bound_walks(
        _two_hop_snapshot(["edge_alice_dev", "edge_dev_admin"]),
        assume_chain_rule("rule_hops"),
        DiscoveryLimits(max_hops=1),
        SystemClock(),
    )
    assert batch.walks == ()
    assert "max_hops" in batch.truncation_reasons


def test_max_paths_keeps_a_stable_subset() -> None:
    nodes = [
        principal("principal:user/alice", "alice", "iam_user"),
        principal("principal:role/one", "one", "iam_role"),
        principal("principal:role/two", "two", "iam_role"),
    ]
    edges = [
        make_edge(
            "edge_b", EdgeType.CAN_ASSUME, "principal:user/alice", "principal:role/two", "policy_b"
        ),
        make_edge(
            "edge_a", EdgeType.CAN_ASSUME, "principal:user/alice", "principal:role/one", "policy_a"
        ),
    ]
    rule = assume_chain_rule("rule_limit").model_copy(
        update={
            "path_pattern": [
                PatternStep(
                    from_role="principal",
                    relationship=EdgeType.CAN_ASSUME,
                    to_role="other",
                )
            ]
        }
    )
    batch = discover_bound_walks(
        make_snapshot("snapshot_limits", nodes, edges),
        rule,
        DiscoveryLimits(max_paths=1),
        SystemClock(),
    )
    assert [item.walk.edge_ids for item in batch.walks] == [("edge_a",)]
    assert "max_paths" in batch.truncation_reasons


def test_max_expansions_stops_the_search() -> None:
    batch = discover_bound_walks(
        _two_hop_snapshot(["edge_alice_dev", "edge_dev_admin"]),
        assume_chain_rule("rule_expansions"),
        DiscoveryLimits(max_expansions=1),
        SystemClock(),
    )
    assert batch.walks == ()
    assert "max_expansions" in batch.truncation_reasons


def test_timeout_stops_before_returning_a_path() -> None:
    batch = discover_bound_walks(
        _two_hop_snapshot(["edge_alice_dev", "edge_dev_admin"]),
        assume_chain_rule("rule_timeout"),
        DiscoveryLimits(timeout_ms=1000),
        ManualClock(),
    )
    assert batch.walks == ()
    assert batch.truncation_reasons == ("timeout",)


def test_explicit_deny_edges_remain_discoverable() -> None:
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
            "policy_deny",
            effect=AuthorizationEffect.deny,
        ),
    ]
    batch = discover_bound_walks(
        make_snapshot("snapshot_deny_discovery", nodes, edges),
        assume_chain_rule("rule_deny_discovery"),
        DiscoveryLimits(),
        SystemClock(),
    )
    assert batch.walks[0].walk.edge_ids == ("edge_alice_dev", "edge_dev_admin")


def test_service_node_is_not_a_principal_start() -> None:
    nodes = [
        make_node("service:lambda.amazonaws.com", NodeType.service, "lambda.amazonaws.com"),
        principal("principal:role/admin", "admin", "iam_role"),
    ]
    edges = [
        make_edge(
            "edge_trust",
            EdgeType.CAN_ASSUME,
            "service:lambda.amazonaws.com",
            "principal:role/admin",
            "policy_trust",
        )
    ]
    rule = assume_chain_rule("rule_service").model_copy(
        update={
            "path_pattern": [
                PatternStep(
                    from_role="principal",
                    relationship=EdgeType.CAN_ASSUME,
                    to_role="other",
                )
            ]
        }
    )
    batch = discover_bound_walks(
        make_snapshot("snapshot_service", nodes, edges),
        rule,
        DiscoveryLimits(),
        SystemClock(),
    )
    assert batch.walks == ()
