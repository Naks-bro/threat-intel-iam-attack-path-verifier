"""Offline branch walk. No AWS, Terraform, or Pathrunner process is started."""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

_SAFE_WORDS = frozenset({"safe", "verified_exploitable", "secure"})


class BranchWalkRejected(ValueError):
    """Fixed, non-sensitive rejection."""


class HopKind(StrEnum):
    identity_transition = "identity_transition"
    service_delegation = "service_delegation"
    data_plane = "data_plane"


class WalkStatus(StrEnum):
    incomplete = "incomplete"
    unsupported = "unsupported"
    unknown = "unknown"
    identity_mismatch = "identity_mismatch"
    invalid_identity_transition = "invalid_identity_transition"
    policy_denied = "policy_denied"
    sandbox_failed = "sandbox_failed"
    sandbox_not_authorized = "sandbox_not_authorized"
    cleanup_unverified = "cleanup_unverified"
    synthetic_chain_recorded = "synthetic_chain_recorded"


@dataclass(frozen=True)
class HopSpec:
    actions: tuple[str, ...]
    kind: HopKind
    establishes_caller: bool
    pathfinding_path_id: str | None
    pathrunner_module: str
    required_input: str
    resulting_evidence: str
    gap: str


@dataclass(frozen=True)
class BranchHop:
    source: str
    actions: tuple[str, ...]
    target: str


@dataclass(frozen=True)
class BranchRequest:
    branch_id: str
    hops: tuple[BranchHop, ...]
    goal: str
    rule_release_id: str
    snapshot_id: str
    sandbox_manifest_id: str
    starting_identity: str


@dataclass(frozen=True)
class HopExecution:
    evidence_class: str
    denied: bool = False
    failed: bool = False
    next_identity: str | None = None
    goal_reached: bool = False


@dataclass(frozen=True)
class CleanupReport:
    verified: bool
    detail: str


class ExecutionAdapter(Protocol):
    def execute(self, hop: BranchHop) -> HopExecution: ...

    def cleanup(self) -> CleanupReport: ...


@dataclass(frozen=True)
class HopRecord:
    source: str
    actions: tuple[str, ...]
    target: str
    status: str
    evidence_class: str | None
    identity_after: str | None


@dataclass(frozen=True)
class BranchWalkResult:
    branch_id: str
    status: WalkStatus
    rule_release_id: str
    snapshot_id: str
    sandbox_manifest_id: str
    hops: tuple[HopRecord, ...]
    cleanup_verified: bool
    limitations: tuple[str, ...]


# Checked against public pathfinding.cloud / Pathrunner descriptions on 2026-10-09.
# pathrunner_module "unverified" means this checkout did not confirm a registered module.
COMPATIBILITY: dict[tuple[str, ...], HopSpec] = {
    ("sts:AssumeRole",): HopSpec(
        actions=("sts:AssumeRole",),
        kind=HopKind.identity_transition,
        establishes_caller=True,
        pathfinding_path_id="sts-001",
        pathrunner_module="unverified",
        required_input="caller credentials, role name, trust allowing that caller",
        resulting_evidence="new caller identity only if AssumeRole succeeds",
        gap="A lab id such as sts-001-to-admin is not an arbitrary role target.",
    ),
    ("iam:PassRole", "lambda:CreateFunction"): HopSpec(
        actions=("iam:PassRole", "lambda:CreateFunction"),
        kind=HopKind.service_delegation,
        establishes_caller=False,
        pathfinding_path_id=None,
        pathrunner_module="unsupported",
        required_input="create a function and pass a role the Lambda service can assume",
        resulting_evidence="a function that Lambda can run as that role; caller identity unchanged",
        gap="CreateFunction does not make the caller become the function role.",
    ),
    ("s3:GetObject",): HopSpec(
        actions=("s3:GetObject",),
        kind=HopKind.data_plane,
        establishes_caller=False,
        pathfinding_path_id=None,
        pathrunner_module="unsupported",
        required_input="current caller already allowed to read one named object",
        resulting_evidence="object read by the current caller, not a new identity",
        gap="Not a privilege-escalation module and not proof about another account.",
    ),
}

_NOT_EXPLOITABILITY = (
    "A recorded synthetic or sandbox walk is not proof the original AWS project is exploitable."
)
_NOT_SAFE = "Denial, failure, unsupported, incomplete, and unknown are not a safe verdict."


def walk_branch(request: BranchRequest, adapter: ExecutionAdapter) -> BranchWalkResult:
    """Walk hops with a mock or future adapter. Cleanup always runs."""

    limitations = [_NOT_EXPLOITABILITY, _NOT_SAFE]
    if not (request.rule_release_id and request.snapshot_id and request.sandbox_manifest_id):
        report = adapter.cleanup()
        return _result(
            request,
            WalkStatus.incomplete,
            (),
            report.verified,
            (*limitations, "rule release, snapshot, and sandbox manifest are required"),
        )

    identity = request.starting_identity
    records: list[HopRecord] = []
    status = WalkStatus.synthetic_chain_recorded
    classes: list[str] = []
    error: Exception | None = None
    try:
        for hop in request.hops:
            if hop.source != identity:
                records.append(_record(hop, "identity_mismatch", None, identity))
                status = WalkStatus.identity_mismatch
                break
            spec = COMPATIBILITY.get(tuple(sorted(hop.actions)))
            if spec is None:
                records.append(_record(hop, "unsupported", None, identity))
                status = WalkStatus.unsupported
                limitations.append("no checked compatibility entry for this action set")
                break
            if spec.kind is HopKind.service_delegation and hop.target != identity:
                records.append(
                    _record(hop, "invalid_identity_transition", "not_executed", identity)
                )
                status = WalkStatus.invalid_identity_transition
                limitations.append(spec.gap)
                break
            outcome = adapter.execute(hop)
            classes.append(outcome.evidence_class)
            if outcome.evidence_class not in {"synthetic_mock", "policy_simulation", "sandbox"}:
                records.append(_record(hop, "unknown", outcome.evidence_class, identity))
                status = WalkStatus.unknown
                break
            if (
                outcome.evidence_class == "sandbox"
                and request.sandbox_manifest_id == "not_authorized"
            ):
                records.append(_record(hop, "sandbox_not_authorized", "sandbox", identity))
                status = WalkStatus.sandbox_not_authorized
                break
            if outcome.denied:
                if outcome.evidence_class != "policy_simulation":
                    records.append(_record(hop, "sandbox_failed", outcome.evidence_class, identity))
                    status = WalkStatus.sandbox_failed
                else:
                    records.append(_record(hop, "policy_denied", "policy_simulation", identity))
                    status = WalkStatus.policy_denied
                break
            if outcome.failed:
                records.append(_record(hop, "sandbox_failed", outcome.evidence_class, identity))
                status = WalkStatus.sandbox_failed
                break
            if spec.establishes_caller:
                if outcome.next_identity != hop.target:
                    records.append(
                        _record(hop, "identity_mismatch", outcome.evidence_class, identity)
                    )
                    status = WalkStatus.identity_mismatch
                    break
                identity = outcome.next_identity
            elif outcome.next_identity not in {None, identity}:
                records.append(
                    _record(
                        hop,
                        "invalid_identity_transition",
                        outcome.evidence_class,
                        identity,
                    )
                )
                status = WalkStatus.invalid_identity_transition
                limitations.append(
                    "adapter reported an identity change this action cannot establish"
                )
                break
            records.append(
                _record(
                    hop,
                    "goal_recorded" if spec.kind is HopKind.data_plane else "recorded",
                    outcome.evidence_class,
                    identity,
                )
            )
        else:
            if "sandbox" in classes or "policy_simulation" in classes:
                status = WalkStatus.unknown
                limitations.append(
                    "mixed or non-synthetic evidence is not a completed sandbox proof"
                )
    except Exception as exc:
        error = exc
    report = adapter.cleanup()
    if error is not None:
        raise error
    if not report.verified:
        status = WalkStatus.cleanup_unverified
        limitations.append(report.detail)
    if status.value in _SAFE_WORDS:
        raise BranchWalkRejected("status_not_allowed")
    return _result(request, status, tuple(records), report.verified, tuple(limitations))


def _record(
    hop: BranchHop, status: str, evidence_class: str | None, identity_after: str
) -> HopRecord:
    return HopRecord(hop.source, hop.actions, hop.target, status, evidence_class, identity_after)


def _result(
    request: BranchRequest,
    status: WalkStatus,
    hops: Sequence[HopRecord],
    cleanup_verified: bool,
    limitations: Sequence[str],
) -> BranchWalkResult:
    return BranchWalkResult(
        branch_id=request.branch_id,
        status=status,
        rule_release_id=request.rule_release_id,
        snapshot_id=request.snapshot_id,
        sandbox_manifest_id=request.sandbox_manifest_id,
        hops=tuple(hops),
        cleanup_verified=cleanup_verified,
        limitations=tuple(limitations),
    )
