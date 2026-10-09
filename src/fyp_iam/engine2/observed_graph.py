"""Project a sealed inventory into observed relationships, never capabilities.

This is deliberately not an IAMGraphSnapshot. An authorization resolver must
evaluate all applicable policy layers before any CAN_* edge can be proposed.
"""

import hashlib
import json
from typing import Literal

from pydantic import ConfigDict, Field

from fyp_iam.contracts.collection import CoverageState
from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.contracts.models import ContractModel, IdStr

NodeKind = Literal["iam_user", "iam_role", "iam_group", "policy", "service"]
RelationKind = Literal[
    "policy_attachment",
    "permissions_boundary_attachment",
    "group_membership",
    "role_trust_policy",
    "trust_selector_reference",
]


class ObservedNode(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(pattern=r"^(p_|pol_|svc_)[0-9a-f]{32}$")
    kind: NodeKind
    display_alias: str | None = None
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class ObservedRelation(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    relation_id: str = Field(pattern=r"^rel_[0-9a-f]{32}$")
    kind: RelationKind
    source_key: str
    target_key: str
    source_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_key: str | None = None
    statement_key: str | None = None
    effect: Literal["allow", "deny"] | None = None
    condition_state: Literal["absent", "unevaluated", "unsupported"] | None = None


class ObservedInventoryGraph(ContractModel):
    """A data-view only; completeness is source coverage, not authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1"] = "0.1"
    snapshot_id: IdStr
    inventory_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    handoff_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    data_kind: Literal["synthetic", "real_account_observed"]
    nodes: tuple[ObservedNode, ...]
    relations: tuple[ObservedRelation, ...]
    source_coverage_complete: bool
    incomplete_reason_codes: tuple[str, ...]
    authorization_evaluated: Literal[False] = False

    def content_digest(self) -> str:
        """Digest the complete ordered projection, including its coverage caveats."""

        canonical = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _key(prefix: str, value: str) -> str:
    return prefix + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _relation_id(*parts: str) -> str:
    return _key("rel_", "\x1f".join(parts))


def project_observed_inventory(handoff: CollectionHandoff) -> ObservedInventoryGraph:
    """Revalidate the seal and derive only directly recorded relationships.

    The returned graph cannot be passed to the fixture verifier and deliberately
    has no effective-permission, exposure, severity, or attack-path fields.
    """

    sealed = CollectionHandoff.model_validate_json(handoff.model_dump_json())
    inventory = sealed.inventory
    nodes: dict[str, ObservedNode] = {}
    relations: dict[str, ObservedRelation] = {}

    for principal in inventory.principals:
        nodes[principal.principal_key] = ObservedNode(
            key=principal.principal_key,
            kind=principal.kind,
            display_alias=principal.display_alias,
            source_digest=principal.source_digest,
        )
    for policy in inventory.policies:
        nodes[policy.policy_key] = ObservedNode(
            key=policy.policy_key, kind="policy", source_digest=policy.source_digest
        )

    def add_relation(
        kind: RelationKind,
        source_key: str,
        target_key: str,
        source_digest: str,
        *,
        policy_key: str | None = None,
        statement_key: str | None = None,
        effect: Literal["allow", "deny"] | None = None,
        condition_state: Literal["absent", "unevaluated", "unsupported"] | None = None,
    ) -> None:
        relation_id = _relation_id(
            kind, source_key, target_key, source_digest, policy_key or "", statement_key or ""
        )
        relations[relation_id] = ObservedRelation(
            relation_id=relation_id,
            kind=kind,
            source_key=source_key,
            target_key=target_key,
            source_digest=source_digest,
            policy_key=policy_key,
            statement_key=statement_key,
            effect=effect,
            condition_state=condition_state,
        )

    for attachment in inventory.attachments:
        add_relation(
            "permissions_boundary_attachment"
            if attachment.kind == "permissions_boundary"
            else "policy_attachment",
            attachment.principal_key,
            attachment.policy_key,
            attachment.source_digest,
            policy_key=attachment.policy_key,
        )
    for membership in inventory.memberships:
        add_relation(
            "group_membership", membership.user_key, membership.group_key, membership.source_digest
        )
    for trust in inventory.trust_statements:
        add_relation(
            "role_trust_policy",
            trust.role_key,
            trust.policy_key,
            trust.source_digest,
            policy_key=trust.policy_key,
            statement_key=trust.statement_key,
            effect=trust.effect,
            condition_state=trust.condition_state,
        )
        for principal_key in trust.trusted_principal_keys:
            add_relation(
                "trust_selector_reference",
                trust.role_key,
                principal_key,
                trust.source_digest,
                policy_key=trust.policy_key,
                statement_key=trust.statement_key,
                effect=trust.effect,
                condition_state=trust.condition_state,
            )
        for service in trust.service_principals:
            service_key = _key("svc_", service)
            nodes[service_key] = ObservedNode(
                key=service_key, kind="service", source_digest=sealed.manifest.snapshot_digest
            )
            add_relation(
                "trust_selector_reference",
                trust.role_key,
                service_key,
                trust.source_digest,
                policy_key=trust.policy_key,
                statement_key=trust.statement_key,
                effect=trust.effect,
                condition_state=trust.condition_state,
            )

    incomplete: set[str] = set()
    if sealed.manifest.outcome != "succeeded":
        incomplete.add("collection_run_incomplete")
    if sealed.manifest.data_kind == "real_account_observed":
        traversals = {item.user_key: item for item in inventory.group_traversals}
        if any(
            traversals.get(principal.principal_key) is None
            or traversals[principal.principal_key].state != "complete"
            for principal in inventory.principals
            if principal.kind == "iam_user"
        ):
            incomplete.add("user_group_traversal_incomplete")
    for coverage in sealed.manifest.coverage:
        if coverage.state not in {CoverageState.collected, CoverageState.absent}:
            incomplete.add("layer_" + coverage.layer.value + "_incomplete")
    if any(policy.parse_state != "parsed" for policy in inventory.policies):
        incomplete.add("policy_parse_incomplete")
    if any(
        statement.action_mode != "action"
        or statement.resource_mode in {"unresolved", "not_resource"}
        or statement.condition_state != "absent"
        for statement in inventory.statements
    ):
        incomplete.add("identity_statement_unresolved")
    if any(
        trust.action_mode != "action"
        or trust.selector_state != "linked"
        or trust.condition_state != "absent"
        for trust in inventory.trust_statements
    ):
        incomplete.add("trust_statement_unresolved")

    return ObservedInventoryGraph(
        snapshot_id=inventory.snapshot_id,
        inventory_digest=sealed.manifest.snapshot_digest,
        handoff_digest=sealed.content_digest(),
        data_kind=sealed.manifest.data_kind,
        nodes=tuple(nodes[key] for key in sorted(nodes)),
        relations=tuple(relations[key] for key in sorted(relations)),
        source_coverage_complete=not incomplete,
        incomplete_reason_codes=tuple(sorted(incomplete)),
    )
