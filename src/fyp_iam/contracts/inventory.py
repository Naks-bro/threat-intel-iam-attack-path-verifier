"""Proposed redacted AWS inventory handoff, before graph derivation.

This is normalized evidence, not raw AWS JSON or an authorization verdict.
The collector must pseudonymize identifiers before constructing these models.
"""

import hashlib
import json
import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from fyp_iam.contracts.collection import CollectionManifest
from fyp_iam.contracts.models import ContractModel, IdStr, reject_sensitive_text

PrincipalKey = Annotated[str, Field(pattern=r"^p_[0-9a-f]{32}$")]
PolicyKey = Annotated[str, Field(pattern=r"^pol_[0-9a-f]{32}$")]
StatementKey = Annotated[str, Field(pattern=r"^st_[0-9a-f]{32}$")]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Fingerprint = Annotated[str, Field(pattern=r"^hmac-sha256:[0-9a-f]{64}$")]
_ACTION = r"^(\*|[A-Za-z0-9*]+:[A-Za-z0-9*]+)$"
_CONDITION_KEY = r"^[A-Za-z0-9_:./-]{1,128}$"
_SERVICE = r"^[a-z0-9][a-z0-9.-]{0,126}\.amazonaws\.com$"


def _safe_condition_key(value: str) -> bool:
    return (
        re.fullmatch(_CONDITION_KEY, value) is not None
        and re.search(r"\b\d{12}\b", value) is None
        and reject_sensitive_text(value) == value
    )


class InventoryPrincipal(ContractModel):
    principal_key: PrincipalKey
    principal_fingerprint: Fingerprint
    kind: Literal["iam_user", "iam_role", "iam_group"]
    display_alias: str = Field(pattern=r"^(user|role|group)-[0-9a-f]{8}$")
    source_digest: Digest

    @model_validator(mode="after")
    def alias_matches_kind(self) -> "InventoryPrincipal":
        if not self.display_alias.startswith(self.kind.removeprefix("iam_") + "-"):
            raise ValueError("display alias does not match principal kind")
        return self


class InventoryPolicy(ContractModel):
    policy_key: PolicyKey
    kind: Literal["managed", "inline", "trust"]
    version_label: str | None = Field(default=None, pattern=r"^v[1-9][0-9]{0,4}$")
    is_default: bool = False
    parse_state: Literal["parsed", "partial", "unsupported"]
    source_digest: Digest

    @model_validator(mode="after")
    def version_is_scoped(self) -> "InventoryPolicy":
        if self.kind == "managed" and self.version_label is None:
            raise ValueError("managed policy requires a version label")
        if self.kind != "managed" and (self.version_label is not None or self.is_default):
            raise ValueError("inline and trust policies have no managed-policy version")
        return self


class PolicyStatementEvidence(ContractModel):
    statement_key: StatementKey
    policy_key: PolicyKey
    effect: Literal["allow", "deny"]
    action_mode: Literal["action", "not_action", "unsupported"]
    action_patterns: list[str] = Field(default_factory=list, max_length=100)
    resource_mode: Literal["all", "linked_principals", "unresolved", "not_resource"]
    resource_principal_keys: list[PrincipalKey] = Field(default_factory=list, max_length=100)
    condition_state: Literal["absent", "unevaluated", "unsupported"]
    condition_keys: list[str] = Field(default_factory=list, max_length=50)
    source_digest: Digest

    @field_validator("action_patterns")
    @classmethod
    def safe_actions(cls, value: list[str]) -> list[str]:
        if any(re.fullmatch(_ACTION, item) is None for item in value):
            raise ValueError("invalid action pattern")
        return value

    @field_validator("condition_keys")
    @classmethod
    def safe_condition_keys(cls, value: list[str]) -> list[str]:
        if any(not _safe_condition_key(item) for item in value):
            raise ValueError("invalid condition key")
        return value

    @model_validator(mode="after")
    def bounded_semantics(self) -> "PolicyStatementEvidence":
        if (self.action_mode == "unsupported") != (not self.action_patterns):
            raise ValueError("unsupported action mode must omit action patterns")
        if self.resource_mode == "linked_principals" and not self.resource_principal_keys:
            raise ValueError("linked resource mode needs principal keys")
        if self.resource_mode != "linked_principals" and self.resource_principal_keys:
            raise ValueError("only linked resource mode may name principal keys")
        if self.condition_state == "absent" and self.condition_keys:
            raise ValueError("absent conditions cannot name keys")
        if self.condition_state == "unevaluated" and not self.condition_keys:
            raise ValueError("unevaluated conditions need keys")
        return self


class InventoryAttachment(ContractModel):
    principal_key: PrincipalKey
    policy_key: PolicyKey
    kind: Literal["managed", "inline", "permissions_boundary"]
    source_digest: Digest


class InventoryMembership(ContractModel):
    user_key: PrincipalKey
    group_key: PrincipalKey
    source_digest: Digest


class UserGroupTraversal(ContractModel):
    """Collector-declared per-user group traversal; not authorization proof."""

    user_key: PrincipalKey
    state: Literal["complete", "partial", "not_collected", "unavailable"]
    membership_count: int | None = Field(default=None, ge=0, le=5000)
    evidence_digest: Digest | None = None
    reason_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$")

    @model_validator(mode="after")
    def consistent_traversal(self) -> "UserGroupTraversal":
        if self.state == "complete":
            if self.membership_count is None or self.evidence_digest is None or self.reason_code:
                raise ValueError("complete group traversal needs count and evidence digest")
        elif self.reason_code is None:
            raise ValueError("incomplete group traversal needs a reason code")
        if self.state in {"not_collected", "unavailable"} and (
            self.membership_count is not None or self.evidence_digest is not None
        ):
            raise ValueError("unread group traversal cannot claim observations")
        return self


class TrustStatementEvidence(ContractModel):
    statement_key: StatementKey
    policy_key: PolicyKey
    role_key: PrincipalKey
    effect: Literal["allow", "deny"]
    action_mode: Literal["action", "not_action", "unsupported"]
    action_patterns: list[str] = Field(default_factory=list, max_length=50)
    trusted_principal_keys: list[PrincipalKey] = Field(default_factory=list, max_length=100)
    service_principals: list[str] = Field(default_factory=list, max_length=50)
    selector_state: Literal["linked", "unresolved"]
    condition_state: Literal["absent", "unevaluated", "unsupported"]
    condition_keys: list[str] = Field(default_factory=list, max_length=50)
    source_digest: Digest

    @field_validator("action_patterns")
    @classmethod
    def safe_actions(cls, value: list[str]) -> list[str]:
        if any(re.fullmatch(_ACTION, item) is None for item in value):
            raise ValueError("invalid trust action")
        return value

    @field_validator("service_principals")
    @classmethod
    def safe_services(cls, value: list[str]) -> list[str]:
        if any(re.fullmatch(_SERVICE, item) is None for item in value):
            raise ValueError("invalid service principal")
        return value

    @field_validator("condition_keys")
    @classmethod
    def safe_condition_keys(cls, value: list[str]) -> list[str]:
        if any(not _safe_condition_key(item) for item in value):
            raise ValueError("invalid trust condition key")
        return value

    @model_validator(mode="after")
    def selector_is_honest(self) -> "TrustStatementEvidence":
        if (self.action_mode == "unsupported") != (not self.action_patterns):
            raise ValueError("unsupported trust action mode must omit action patterns")
        if self.selector_state == "linked" and not (
            self.trusted_principal_keys or self.service_principals
        ):
            raise ValueError("linked trust selector needs a target")
        if self.selector_state == "unresolved" and (
            self.trusted_principal_keys or self.service_principals
        ):
            raise ValueError("unresolved trust selector cannot claim linked targets")
        if self.condition_state == "absent" and self.condition_keys:
            raise ValueError("absent trust conditions cannot name keys")
        if self.condition_state == "unevaluated" and not self.condition_keys:
            raise ValueError("unevaluated trust conditions need keys")
        return self


class InventorySnapshot(ContractModel):
    schema_version: Literal["0.1"] = "0.1"
    snapshot_id: IdStr
    principals: list[InventoryPrincipal] = Field(default_factory=list, max_length=500)
    policies: list[InventoryPolicy] = Field(default_factory=list, max_length=1000)
    statements: list[PolicyStatementEvidence] = Field(default_factory=list, max_length=5000)
    attachments: list[InventoryAttachment] = Field(default_factory=list, max_length=5000)
    memberships: list[InventoryMembership] = Field(default_factory=list, max_length=5000)
    group_traversals: list[UserGroupTraversal] = Field(default_factory=list, max_length=500)
    trust_statements: list[TrustStatementEvidence] = Field(default_factory=list, max_length=2000)

    @field_validator("snapshot_id")
    @classmethod
    def opaque_snapshot_id(cls, value: str) -> str:
        if re.search(r"\b\d{12}\b", value):
            raise ValueError("raw account identifier is not allowed")
        return reject_sensitive_text(value)

    @model_validator(mode="after")
    def references_stay_within_snapshot(self) -> "InventorySnapshot":
        principals = {item.principal_key: item for item in self.principals}
        policies = {item.policy_key: item for item in self.policies}
        if len(principals) != len(self.principals) or len(policies) != len(self.policies):
            raise ValueError("duplicate principal or policy key")
        if len({item.principal_fingerprint for item in self.principals}) != len(self.principals):
            raise ValueError("duplicate principal fingerprint")
        statement_keys = [entry.statement_key for entry in self.statements]
        statement_keys.extend(entry.statement_key for entry in self.trust_statements)
        if len(statement_keys) != len(set(statement_keys)):
            raise ValueError("duplicate statement key")
        for statement in self.statements:
            policy = policies.get(statement.policy_key)
            if policy is None or policy.kind == "trust":
                raise ValueError("identity statement needs a local non-trust policy")
            if policy.parse_state == "unsupported":
                raise ValueError("unsupported policy cannot claim parsed statements")
            if any(key not in principals for key in statement.resource_principal_keys):
                raise ValueError("statement resource references an unknown principal")
        attachment_keys: set[tuple[str, str, str]] = set()
        for attachment in self.attachments:
            principal = principals.get(attachment.principal_key)
            policy = policies.get(attachment.policy_key)
            if principal is None or policy is None or policy.kind == "trust":
                raise ValueError("attachment references an unknown or trust record")
            if attachment.kind == "inline" and policy.kind != "inline":
                raise ValueError("inline attachment needs an inline policy")
            if attachment.kind != "inline" and policy.kind != "managed":
                raise ValueError("managed or boundary attachment needs a managed policy")
            if attachment.kind != "inline" and not policy.is_default:
                raise ValueError("managed attachment needs the default policy version")
            if attachment.kind == "permissions_boundary" and principal.kind == "iam_group":
                raise ValueError("group cannot have a permissions boundary")
            attachment_key = (attachment.principal_key, attachment.policy_key, attachment.kind)
            if attachment_key in attachment_keys:
                raise ValueError("duplicate policy attachment")
            attachment_keys.add(attachment_key)
        membership_keys: set[tuple[str, str]] = set()
        for membership in self.memberships:
            user = principals.get(membership.user_key)
            group = principals.get(membership.group_key)
            if (
                user is None
                or user.kind != "iam_user"
                or group is None
                or group.kind != "iam_group"
            ):
                raise ValueError("membership needs a local user and group")
            membership_key = (membership.user_key, membership.group_key)
            if membership_key in membership_keys:
                raise ValueError("duplicate group membership")
            membership_keys.add(membership_key)
        traversal_keys: set[str] = set()
        for traversal in self.group_traversals:
            user = principals.get(traversal.user_key)
            if user is None or user.kind != "iam_user" or traversal.user_key in traversal_keys:
                raise ValueError("group traversal needs a unique local user")
            traversal_keys.add(traversal.user_key)
            if traversal.state == "complete" and traversal.membership_count != sum(
                membership.user_key == traversal.user_key for membership in self.memberships
            ):
                raise ValueError("complete group traversal count disagrees with memberships")
        for trust in self.trust_statements:
            role = principals.get(trust.role_key)
            policy = policies.get(trust.policy_key)
            if role is None or role.kind != "iam_role" or policy is None or policy.kind != "trust":
                raise ValueError("trust statement needs a local role and trust policy")
            if policy.parse_state == "unsupported":
                raise ValueError("unsupported trust policy cannot claim parsed statements")
            if any(key not in principals for key in trust.trusted_principal_keys):
                raise ValueError("trust selector references an unknown principal")
        return self

    def content_digest(self) -> str:
        data = self.model_dump(mode="json")
        if not self.group_traversals:
            # Preserve the existing 0.1 digest for older sealed handoffs that
            # cannot contain this additive field. Nonempty evidence is pinned.
            data.pop("group_traversals")
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CollectionHandoff(ContractModel):
    manifest: CollectionManifest
    inventory: InventorySnapshot

    @model_validator(mode="after")
    def sealed_binding(self) -> "CollectionHandoff":
        if self.manifest.snapshot_id != self.inventory.snapshot_id:
            raise ValueError("manifest and inventory snapshot IDs differ")
        if self.manifest.snapshot_digest != self.inventory.content_digest():
            raise ValueError("inventory digest does not match sealed manifest")
        if self.manifest.data_kind == "real_account_observed":
            for traversal in self.inventory.group_traversals:
                if traversal.state != "complete":
                    continue
                matching_tasks = [
                    task
                    for task in self.manifest.tasks
                    if task.operation == "iam:ListGroupsForUser"
                    and task.subject_principal_key == traversal.user_key
                    and task.outcome == "succeeded"
                    and task.pagination_complete
                    and task.item_count == traversal.membership_count
                    and task.response_digest == traversal.evidence_digest
                ]
                if len(matching_tasks) != 1:
                    raise ValueError("complete group traversal needs one matching read task")
        if len(self.model_dump_json().encode("utf-8")) > 2_000_000:
            raise ValueError("inventory handoff exceeds size bound")
        return self

    def content_digest(self) -> str:
        """Pin inventory plus run/coverage metadata; integrity, not provenance."""

        data = self.model_dump(mode="json")
        if not self.inventory.group_traversals:
            data["inventory"].pop("group_traversals")
        for task in data["manifest"]["tasks"]:
            if task["subject_principal_key"] is None:
                task.pop("subject_principal_key")
            if task["subject_policy_fingerprint"] is None:
                task.pop("subject_policy_fingerprint")
            if task["response_digest"] is None:
                task.pop("response_digest")
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
