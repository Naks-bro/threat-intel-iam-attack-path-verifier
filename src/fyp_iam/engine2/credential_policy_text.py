"""Read-only policy-text screening for one IAM CreateAccessKey question.

This is a structural observation, not an IAM authorization evaluator. It
never calls AWS, creates a key, emits CAN_* graph edges, or makes a finding.
"""

from fnmatch import fnmatchcase
from typing import Literal

from pydantic import ConfigDict, Field

from fyp_iam.contracts.collection import CoverageState, PolicyLayer
from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import ContractModel, IdStr
from fyp_iam.engine2.identity_observation import (
    IdentityObservation,
    ObservedPolicyStatement,
    observe_identity,
)

_ACTION: Literal["iam:CreateAccessKey"] = "iam:CreateAccessKey"
_MAX_EVIDENCE_ROWS = 10_000
PolicyTextStatus = Literal[
    "policy_text_candidate",
    "recorded_explicit_deny",
    "uncertain_policy_text",
    "no_observed_identity_allow",
    "analysis_bound_exceeded",
]


class PolicyTextEvidence(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    statement_key: str
    policy_key: str
    attachment_relation_id: str
    via_group_key: str | None = None
    effect: Literal["allow", "deny"]
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class CredentialPolicyTextResult(ContractModel):
    """A pinned observation of policy text, never effective AWS permission."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    analyzer_version: Literal["credential-policy-text-0.1"] = "credential-policy-text-0.1"
    snapshot_id: IdStr
    inventory_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    handoff_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    data_kind: Literal["synthetic", "real_account_observed"]
    source_principal_key: str
    target_user_key: str
    action: Literal["iam:CreateAccessKey"] = _ACTION
    status: PolicyTextStatus
    allow_evidence: tuple[PolicyTextEvidence, ...]
    deny_evidence: tuple[PolicyTextEvidence, ...]
    uncertainty_codes: tuple[str, ...]
    coverage_gap_codes: tuple[str, ...]
    authorization_evaluated: Literal[False] = False


def _action_matches(statement: ObservedPolicyStatement) -> bool | None:
    if statement.action_mode != "action":
        return None
    return any(
        fnmatchcase(_ACTION.casefold(), pattern.casefold()) for pattern in statement.action_patterns
    )


def _resource_matches(statement: ObservedPolicyStatement, target_user_key: str) -> bool | None:
    if statement.resource_mode == "all":
        return True
    if statement.resource_mode == "linked_principals":
        return target_user_key in statement.resource_principal_keys
    return None


def inspect_create_access_key_policy_text(
    handoff: CollectionHandoff, source_principal_key: str, target_user_key: str
) -> CredentialPolicyTextResult:
    """Inspect attached identity-policy text for a selected user or role.

    An unconditional Allow is a candidate, not a grant. An unconditional Deny
    is recorded as policy text, not an AWS request outcome. Boundary and other
    policy layers remain limitations even when the identity text matches.
    """

    observation = observe_identity(handoff, source_principal_key)
    sealed = CollectionHandoff.model_validate_json(handoff.model_dump_json())
    target = next(
        (item for item in sealed.inventory.principals if item.principal_key == target_user_key),
        None,
    )
    if target is None:
        raise ValueError("target_not_in_snapshot")
    if target.kind != "iam_user":
        raise ValueError("target_not_iam_user")
    if target_user_key == source_principal_key:
        raise ValueError("self_key_creation_outside_first_pattern")

    statements = {item.statement_key: item for item in observation.statements}
    allow: list[PolicyTextEvidence] = []
    deny: list[PolicyTextEvidence] = []
    uncertainty: set[str] = set()
    if (
        observation.data_kind == "real_account_observed"
        and observation.principal_kind == "iam_user"
        and "user_group_traversal_incomplete" in observation.incomplete_reason_codes
    ):
        uncertainty.add("group_traversal_incomplete")
    for attachment in observation.attachments:
        if attachment.attachment_kind == "permissions_boundary_attachment":
            uncertainty.add("permissions_boundary_not_evaluated")
        if attachment.parse_state != "parsed":
            uncertainty.add("policy_parse_incomplete")
        for statement_key in attachment.statement_keys:
            statement = statements[statement_key]
            action_match = _action_matches(statement)
            resource_match = _resource_matches(statement, target_user_key)
            if action_match is False or resource_match is False:
                continue
            if action_match is None or resource_match is None:
                uncertainty.add("unsupported_action_or_resource_selector")
                continue
            if statement.condition_state != "absent":
                uncertainty.add("condition_not_evaluated")
                continue
            evidence = PolicyTextEvidence(
                statement_key=statement.statement_key,
                policy_key=statement.policy_key,
                attachment_relation_id=attachment.attachment_relation_id,
                via_group_key=attachment.via_group_key,
                effect=statement.effect,
                source_digest=statement.source_digest,
            )
            if attachment.attachment_kind == "permissions_boundary_attachment":
                # A boundary Allow never grants an identity permission. Preserve
                # an explicit Deny separately; the rest is a coverage limitation.
                if statement.effect == "deny":
                    deny.append(evidence)
            elif statement.effect == "deny":
                deny.append(evidence)
            else:
                allow.append(evidence)
            if len(allow) + len(deny) > _MAX_EVIDENCE_ROWS:
                return _result(
                    observation,
                    target_user_key,
                    "analysis_bound_exceeded",
                    (),
                    (),
                    ("evidence_row_limit",),
                )

    identity_coverage = next(
        item for item in sealed.manifest.coverage if item.layer == PolicyLayer.identity_policy
    )
    if sealed.manifest.outcome != "succeeded":
        uncertainty.add("collection_run_incomplete")
    if identity_coverage.state not in {CoverageState.collected, CoverageState.absent}:
        uncertainty.add("identity_policy_coverage_incomplete")
    if identity_coverage.state == CoverageState.absent and any(
        attachment.attachment_kind == "policy_attachment" for attachment in observation.attachments
    ):
        uncertainty.add("coverage_inventory_mismatch")
    status: PolicyTextStatus
    if deny:
        status = "recorded_explicit_deny"
    elif allow and uncertainty - {"permissions_boundary_not_evaluated"}:
        status = "uncertain_policy_text"
    elif allow:
        status = "policy_text_candidate"
    elif uncertainty:
        status = "uncertain_policy_text"
    else:
        status = "no_observed_identity_allow"
    return _result(
        observation,
        target_user_key,
        status,
        tuple(sorted(allow, key=_evidence_key)),
        tuple(sorted(deny, key=_evidence_key)),
        tuple(sorted(uncertainty)),
    )


def _evidence_key(row: PolicyTextEvidence) -> tuple[str, str]:
    return row.statement_key, row.attachment_relation_id


def _result(
    observation: IdentityObservation,
    target_user_key: str,
    status: PolicyTextStatus,
    allow: tuple[PolicyTextEvidence, ...],
    deny: tuple[PolicyTextEvidence, ...],
    uncertainty: tuple[str, ...],
) -> CredentialPolicyTextResult:
    return CredentialPolicyTextResult(
        snapshot_id=observation.snapshot_id,
        inventory_digest=observation.inventory_digest,
        handoff_digest=observation.handoff_digest,
        data_kind=observation.data_kind,
        source_principal_key=observation.principal_key,
        target_user_key=target_user_key,
        status=status,
        allow_evidence=allow,
        deny_evidence=deny,
        uncertainty_codes=uncertainty,
        coverage_gap_codes=observation.incomplete_reason_codes,
    )
