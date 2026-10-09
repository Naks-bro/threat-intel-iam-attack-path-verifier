"""One-principal view of recorded IAM evidence, without an access verdict.

The view is deliberately separate from an Engine 3 analysis. It contains
policy text summaries and lineage, not claims about effective permission.
"""

from typing import Literal

from pydantic import ConfigDict, Field

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import ContractModel, IdStr
from fyp_iam.engine2.observed_graph import project_observed_inventory


class ObservedPolicyAttachment(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_key: str
    attachment_kind: Literal["policy_attachment", "permissions_boundary_attachment"]
    attachment_relation_id: str
    via_group_key: str | None = None
    membership_relation_id: str | None = None
    parse_state: Literal["parsed", "partial", "unsupported"]
    statement_keys: tuple[str, ...]
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ObservedPolicyStatement(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    statement_key: str
    policy_key: str
    effect: Literal["allow", "deny"]
    action_mode: Literal["action", "not_action", "unsupported"]
    action_patterns: tuple[str, ...]
    resource_mode: Literal["all", "linked_principals", "unresolved", "not_resource"]
    resource_principal_keys: tuple[str, ...]
    condition_state: Literal["absent", "unevaluated", "unsupported"]
    condition_keys: tuple[str, ...]
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ObservedTrustStatement(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    statement_key: str
    policy_key: str
    role_key: str
    selected_is_role: bool
    selected_is_linked_trustee: bool
    effect: Literal["allow", "deny"]
    action_mode: Literal["action", "not_action", "unsupported"]
    action_patterns: tuple[str, ...]
    selector_state: Literal["linked", "unresolved"]
    condition_state: Literal["absent", "unevaluated", "unsupported"]
    condition_keys: tuple[str, ...]
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class IdentityObservation(ContractModel):
    """Snapshot-local analyst input; never a security/authorization finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    snapshot_id: IdStr
    inventory_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    handoff_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    data_kind: Literal["synthetic", "real_account_observed"]
    principal_key: str
    principal_kind: Literal["iam_user", "iam_role"]
    display_alias: str
    attachments: tuple[ObservedPolicyAttachment, ...]
    statements: tuple[ObservedPolicyStatement, ...]
    trust_statements: tuple[ObservedTrustStatement, ...]
    source_coverage_complete: bool
    incomplete_reason_codes: tuple[str, ...]
    authorization_evaluated: Literal[False] = False
    assessment: Literal["not_evaluated"] = "not_evaluated"


def observe_identity(handoff: CollectionHandoff, principal_key: str) -> IdentityObservation:
    """Return direct and group-inherited *observed* evidence for one identity.

    Revalidation occurs in the graph projection. This function does not infer
    inheritance of effective permission or resolve trust into AssumeRole access.
    """

    sealed = CollectionHandoff.model_validate_json(handoff.model_dump_json())
    graph = project_observed_inventory(sealed)
    inventory = sealed.inventory
    principals = {item.principal_key: item for item in inventory.principals}
    principal = principals.get(principal_key)
    if principal is None:
        raise ValueError("principal_not_in_snapshot")
    if principal.kind == "iam_group":
        raise ValueError("principal_not_investigable")

    policies = {item.policy_key: item for item in inventory.policies}
    statements_by_policy: dict[str, list[str]] = {}
    for statement in inventory.statements:
        statements_by_policy.setdefault(statement.policy_key, []).append(statement.statement_key)

    groups: dict[str, str] = {}
    for relation in graph.relations:
        if relation.kind == "group_membership" and relation.source_key == principal_key:
            groups[relation.target_key] = relation.relation_id

    attachment_rows: list[ObservedPolicyAttachment] = []
    included_policies: set[str] = set()
    for relation in graph.relations:
        if relation.kind not in {"policy_attachment", "permissions_boundary_attachment"}:
            continue
        is_direct = relation.source_key == principal_key
        if not is_direct and relation.source_key not in groups:
            continue
        policy = policies[relation.target_key]
        included_policies.add(policy.policy_key)
        attachment_rows.append(
            ObservedPolicyAttachment(
                policy_key=policy.policy_key,
                attachment_kind=relation.kind,
                attachment_relation_id=relation.relation_id,
                via_group_key=None if is_direct else relation.source_key,
                membership_relation_id=None if is_direct else groups[relation.source_key],
                parse_state=policy.parse_state,
                statement_keys=tuple(sorted(statements_by_policy.get(policy.policy_key, []))),
                source_digest=relation.source_digest,
            )
        )

    statement_rows = tuple(
        ObservedPolicyStatement(
            statement_key=item.statement_key,
            policy_key=item.policy_key,
            effect=item.effect,
            action_mode=item.action_mode,
            action_patterns=tuple(item.action_patterns),
            resource_mode=item.resource_mode,
            resource_principal_keys=tuple(item.resource_principal_keys),
            condition_state=item.condition_state,
            condition_keys=tuple(item.condition_keys),
            source_digest=item.source_digest,
        )
        for item in sorted(inventory.statements, key=lambda item: item.statement_key)
        if item.policy_key in included_policies
    )
    trust_rows = tuple(
        ObservedTrustStatement(
            statement_key=item.statement_key,
            policy_key=item.policy_key,
            role_key=item.role_key,
            selected_is_role=item.role_key == principal_key,
            selected_is_linked_trustee=principal_key in item.trusted_principal_keys,
            effect=item.effect,
            action_mode=item.action_mode,
            action_patterns=tuple(item.action_patterns),
            selector_state=item.selector_state,
            condition_state=item.condition_state,
            condition_keys=tuple(item.condition_keys),
            source_digest=item.source_digest,
        )
        for item in sorted(inventory.trust_statements, key=lambda item: item.statement_key)
        if item.role_key == principal_key or principal_key in item.trusted_principal_keys
    )
    incomplete = set(graph.incomplete_reason_codes)
    if "user_group_traversal_incomplete" in incomplete:
        traversal = next(
            (item for item in inventory.group_traversals if item.user_key == principal_key), None
        )
        if principal.kind == "iam_role" or (
            traversal is not None and traversal.state == "complete"
        ):
            incomplete.remove("user_group_traversal_incomplete")
    return IdentityObservation(
        snapshot_id=graph.snapshot_id,
        inventory_digest=graph.inventory_digest,
        handoff_digest=graph.handoff_digest,
        data_kind=graph.data_kind,
        principal_key=principal_key,
        principal_kind=principal.kind,
        display_alias=principal.display_alias,
        attachments=tuple(sorted(attachment_rows, key=lambda row: row.attachment_relation_id)),
        statements=statement_rows,
        trust_statements=trust_rows,
        source_coverage_complete=not incomplete,
        incomplete_reason_codes=tuple(sorted(incomplete)),
    )
