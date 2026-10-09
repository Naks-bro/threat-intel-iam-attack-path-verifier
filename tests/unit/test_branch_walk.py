"""Offline branch-walk checks. Adapters are mocks; nothing calls AWS."""

import pytest

from fyp_iam.engine3.branch_walk import (
    BranchHop,
    BranchRequest,
    BranchWalkResult,
    CleanupReport,
    HopExecution,
    WalkStatus,
    walk_branch,
)


class ScriptedAdapter:
    def __init__(self, outcomes: list[HopExecution], cleanup: CleanupReport) -> None:
        self.outcomes = outcomes
        self.cleanup_report = cleanup
        self.executed: list[str] = []
        self.cleaned = False

    def execute(self, hop: BranchHop) -> HopExecution:
        self.executed.append(hop.target)
        return self.outcomes.pop(0)

    def cleanup(self) -> CleanupReport:
        self.cleaned = True
        return self.cleanup_report


def _request(hops: tuple[BranchHop, ...], **overrides: str) -> BranchRequest:
    values = {
        "branch_id": "branch_synthetic_1",
        "hops": hops,
        "goal": "synthetic identity chain",
        "rule_release_id": "release_synthetic",
        "snapshot_id": "snapshot_synthetic",
        "sandbox_manifest_id": "manifest_offline",
        "starting_identity": "UserA",
    }
    values.update(overrides)
    return BranchRequest(**values)


def _ok(**overrides: object) -> CleanupReport:
    return CleanupReport(True, "cleanup_recorded")


def test_missing_binding_stops_before_execution() -> None:
    adapter = ScriptedAdapter([], _ok())
    result = walk_branch(_request((), rule_release_id=""), adapter)
    assert result.status is WalkStatus.incomplete
    assert adapter.executed == []
    assert adapter.cleaned is True
    assert result.cleanup_verified is True


def test_assume_role_chain_is_recorded_not_exploitable() -> None:
    hops = (
        BranchHop("UserA", ("sts:AssumeRole",), "BuildRole"),
        BranchHop("BuildRole", ("sts:AssumeRole",), "AuditRole"),
    )
    adapter = ScriptedAdapter(
        [
            HopExecution("synthetic_mock", next_identity="BuildRole"),
            HopExecution("synthetic_mock", next_identity="AuditRole"),
        ],
        _ok(),
    )
    result = walk_branch(_request(hops), adapter)
    assert result.status is WalkStatus.synthetic_chain_recorded
    assert [item.identity_after for item in result.hops] == ["BuildRole", "AuditRole"]
    assert "exploitable" not in result.status.value
    assert any("not proof" in item for item in result.limitations)


def test_passrole_does_not_become_the_lambda_role() -> None:
    hops = (
        BranchHop("UserA", ("sts:AssumeRole",), "BuildRole"),
        BranchHop(
            "BuildRole",
            ("lambda:CreateFunction", "iam:PassRole"),
            "LambdaExecutionRole",
        ),
        BranchHop("LambdaExecutionRole", ("s3:GetObject",), "SandboxTestObject"),
    )
    adapter = ScriptedAdapter(
        [HopExecution("synthetic_mock", next_identity="BuildRole")],
        _ok(),
    )
    result = walk_branch(_request(hops), adapter)
    assert result.status is WalkStatus.invalid_identity_transition
    assert adapter.executed == ["BuildRole"]
    assert result.hops[-1].target == "LambdaExecutionRole"
    assert result.hops[-1].identity_after == "BuildRole"


def test_simulator_denial_stops_and_is_not_safe() -> None:
    hops = (
        BranchHop("UserA", ("sts:AssumeRole",), "BuildRole"),
        BranchHop("BuildRole", ("sts:AssumeRole",), "AuditRole"),
    )
    adapter = ScriptedAdapter(
        [HopExecution("policy_simulation", denied=True)],
        _ok(),
    )
    result = walk_branch(_request(hops), adapter)
    assert result.status is WalkStatus.policy_denied
    assert adapter.executed == ["BuildRole"]
    assert result.status is not WalkStatus.synthetic_chain_recorded


def test_sandbox_failure_is_distinct_from_policy_denial() -> None:
    hop = BranchHop("UserA", ("sts:AssumeRole",), "BuildRole")
    adapter = ScriptedAdapter([HopExecution("sandbox", failed=True)], _ok())
    result = walk_branch(_request((hop,)), adapter)
    assert result.status is WalkStatus.sandbox_failed


def test_cleanup_failure_overrides_a_recorded_chain() -> None:
    hop = BranchHop("UserA", ("sts:AssumeRole",), "BuildRole")
    adapter = ScriptedAdapter(
        [HopExecution("synthetic_mock", next_identity="BuildRole")],
        CleanupReport(False, "destroy_not_verified"),
    )
    result = walk_branch(_request((hop,)), adapter)
    assert result.status is WalkStatus.cleanup_unverified
    assert adapter.cleaned is True


def test_unknown_action_is_unsupported() -> None:
    hop = BranchHop("UserA", ("iam:CreateUser",), "OtherUser")
    adapter = ScriptedAdapter([], _ok())
    result = walk_branch(_request((hop,)), adapter)
    assert result.status is WalkStatus.unsupported
    assert adapter.executed == []


def test_adapter_cannot_invent_an_identity_change() -> None:
    hop = BranchHop("UserA", ("s3:GetObject",), "SandboxTestObject")
    adapter = ScriptedAdapter(
        [HopExecution("synthetic_mock", next_identity="LambdaExecutionRole", goal_reached=True)],
        _ok(),
    )
    result = walk_branch(_request((hop,)), adapter)
    assert result.status is WalkStatus.invalid_identity_transition


def test_result_keeps_the_three_bindings(result: BranchWalkResult | None = None) -> None:
    hop = BranchHop("UserA", ("sts:AssumeRole",), "BuildRole")
    adapter = ScriptedAdapter(
        [HopExecution("synthetic_mock", next_identity="BuildRole")],
        _ok(),
    )
    result = walk_branch(_request((hop,)), adapter)
    assert result.rule_release_id == "release_synthetic"
    assert result.snapshot_id == "snapshot_synthetic"
    assert result.sandbox_manifest_id == "manifest_offline"
    assert result.status.value not in {"safe", "verified_exploitable"}


def test_cleanup_runs_when_execution_raises() -> None:
    class Exploding:
        def execute(self, hop: BranchHop) -> HopExecution:
            raise RuntimeError("private-arn-must-not-leak")

        def cleanup(self) -> CleanupReport:
            self.cleaned = True
            return CleanupReport(True, "cleanup_recorded")

    adapter = Exploding()
    hop = BranchHop("UserA", ("sts:AssumeRole",), "BuildRole")
    with pytest.raises(RuntimeError, match="private-arn-must-not-leak"):
        walk_branch(_request((hop,)), adapter)
    assert adapter.cleaned is True
