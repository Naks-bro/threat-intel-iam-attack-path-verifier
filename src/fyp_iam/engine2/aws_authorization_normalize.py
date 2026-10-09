"""Conservative redaction of IAM authorization-details pages into handoff 0.1.

Pure and in-memory: no AWS calls, persistence, raw identifiers in output, or
effective-permission inference. Unrepresented policy forms become coverage gaps.
"""

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from fyp_iam.contracts.collection import PolicyLayer
from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
from fyp_iam.engine2.aws_authorization_read import AuthorizationRead

_ACCOUNT = re.compile(r"^[0-9]{12}$")
_VERSION = re.compile(r"^v[1-9][0-9]{0,4}$")
_ACTION = re.compile(r"^(\*|[A-Za-z0-9*]+:[A-Za-z0-9*]+)$")
_CONDITION = re.compile(r"^[A-Za-z0-9_:./-]{1,128}$")
_SERVICE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,126}\.amazonaws\.com$")


class NormalizationRejected(ValueError):
    """Fixed code, never a raw AWS value or document."""


@dataclass(frozen=True)
class NormalizationResult:
    handoff: CollectionHandoff
    uncertainty_codes: tuple[str, ...]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _hmac(secret: bytes, value: str) -> str:
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _key(secret: bytes, prefix: str, value: str) -> str:
    return prefix + _hmac(secret, value)[:32]


def _document(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or len(value) > 131072:
        return None
    try:
        decoded = json.loads(value if value.lstrip().startswith("{") else unquote(value))
    except (UnicodeError, ValueError, TypeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _list(value: Any, *, cap: int) -> list[Any] | None:
    result = value if isinstance(value, list) else [value]
    return result if len(result) <= cap else None


def _actions(statement: dict[str, Any], *, cap: int) -> tuple[str, list[str]]:
    keys = [name for name in ("Action", "NotAction") if name in statement]
    if len(keys) != 1:
        return "unsupported", []
    raw = _list(statement[keys[0]], cap=cap)
    if (
        raw is None
        or not raw
        or any(not isinstance(v, str) or not _ACTION.fullmatch(v) for v in raw)
    ):
        return "unsupported", []
    return ("action" if keys[0] == "Action" else "not_action"), raw


def _conditions(statement: dict[str, Any]) -> tuple[str, list[str]]:
    condition = statement.get("Condition")
    if condition is None:
        return "absent", []
    if not isinstance(condition, dict):
        return "unsupported", []
    keys: list[str] = []
    for operator_values in condition.values():
        if not isinstance(operator_values, dict):
            return "unsupported", []
        keys.extend(operator_values.keys())
    keys = list(dict.fromkeys(keys))
    if not keys or len(keys) > 50 or any(not _CONDITION.fullmatch(key) for key in keys):
        return "unsupported", []
    return "unevaluated", keys


def _statements(document: dict[str, Any]) -> list[dict[str, Any]] | None:
    if "Statement" not in document:
        return None
    raw = document["Statement"]
    statements = _list(raw, cap=5000)
    if statements is None or any(not isinstance(item, dict) for item in statements):
        return None
    return statements


def normalize_authorization_details(
    read: AuthorizationRead,
    *,
    account_id: str,
    hmac_secret: bytes,
    started_at: datetime,
    sealed_at: datetime,
) -> NormalizationResult:
    """Redact complete pages; never interpret Allow as effective authorization."""

    if not _ACCOUNT.fullmatch(account_id) or len(hmac_secret) < 32:
        raise NormalizationRejected("private_configuration_invalid")
    if started_at.tzinfo is None or sealed_at.tzinfo is None or sealed_at < started_at:
        raise NormalizationRejected("collection_time_invalid")
    if read.page_count < 1 or read.page_count != len(read.pages):
        raise NormalizationRejected("read_pages_invalid")
    raw: dict[str, list[dict[str, Any]]] = {
        name: [] for name in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")
    }
    for page in read.pages:
        for name in raw:
            records = page.get(name, [])
            if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
                raise NormalizationRejected("read_shape_invalid")
            raw[name].extend(records)
    if sum(map(len, raw.values())) > 1500:
        raise NormalizationRejected("read_scope_too_large")

    uncertainty: set[str] = set()
    principals: list[dict[str, Any]] = []
    arn_to_principal: dict[str, str] = {}
    groups_by_name: dict[str, str] = {}
    users: list[tuple[dict[str, Any], str]] = []
    owners: list[tuple[dict[str, Any], str, str]] = []
    for source, kind, name_field in (
        ("UserDetailList", "iam_user", "UserName"),
        ("RoleDetailList", "iam_role", "RoleName"),
        ("GroupDetailList", "iam_group", "GroupName"),
    ):
        for item in raw[source]:
            principal_arn, principal_name = item.get("Arn"), item.get(name_field)
            if (
                not isinstance(principal_arn, str)
                or not principal_arn.startswith(
                    f"arn:aws:iam::{account_id}:{kind.removeprefix('iam_')}/"
                )
                or not isinstance(principal_name, str)
                or principal_arn in arn_to_principal
            ):
                raise NormalizationRejected("principal_identity_invalid")
            key = _key(hmac_secret, "p_", principal_arn)
            fingerprint = "hmac-sha256:" + _hmac(hmac_secret, principal_arn)
            principals.append(
                {
                    "principal_key": key,
                    "principal_fingerprint": fingerprint,
                    "kind": kind,
                    "display_alias": kind.removeprefix("iam_") + "-" + fingerprint[-8:],
                    "source_digest": _digest(item),
                }
            )
            arn_to_principal[principal_arn] = key
            owners.append((item, key, principal_arn))
            if kind == "iam_group":
                if principal_name in groups_by_name:
                    raise NormalizationRejected("duplicate_group_name")
                groups_by_name[principal_name] = key
            if kind == "iam_user":
                users.append((item, key))

    policies: list[dict[str, Any]] = []
    policy_by_arn: dict[str, str] = {}
    attachments: list[dict[str, Any]] = []
    statements: list[dict[str, Any]] = []
    trust_statements: list[dict[str, Any]] = []
    identity_gaps: set[str] = set()
    trust_gaps: set[str] = set()

    def add_policy(
        identifier: str, kind: str, version: str | None, document_value: Any
    ) -> tuple[str, dict[str, Any] | None]:
        key = _key(hmac_secret, "pol_", identifier)
        document = _document(document_value)
        policies.append(
            {
                "policy_key": key,
                "kind": kind,
                "version_label": version,
                "is_default": kind == "managed",
                "parse_state": (
                    "parsed"
                    if document is not None and _statements(document) is not None
                    else "partial"
                ),
                "source_digest": _digest(document_value),
            }
        )
        return key, document

    def parse_identity(document: dict[str, Any] | None, policy_key: str) -> None:
        if document is None:
            identity_gaps.add("identity_policy_document_unreadable")
            return
        entries = _statements(document)
        if entries is None:
            identity_gaps.add("identity_policy_statement_unreadable")
            return
        for index, entry in enumerate(entries):
            if entry.get("Effect") not in ("Allow", "Deny"):
                identity_gaps.add("identity_policy_effect_unsupported")
                continue
            action_mode, actions = _actions(entry, cap=100)
            condition_state, condition_keys = _conditions(entry)
            linked: list[str]
            if "NotResource" in entry:
                resource_mode, linked = "not_resource", []
            elif entry.get("Resource") == "*":
                resource_mode, linked = "all", []
            else:
                resources = _list(entry.get("Resource"), cap=100)
                if resources and all(
                    isinstance(v, str) and v in arn_to_principal for v in resources
                ):
                    resource_mode = "linked_principals"
                    linked = [arn_to_principal[v] for v in resources]
                else:
                    resource_mode, linked = "unresolved", []
            statements.append(
                {
                    "statement_key": _key(hmac_secret, "st_", f"{policy_key}:{index}"),
                    "policy_key": policy_key,
                    "effect": entry["Effect"].lower(),
                    "action_mode": action_mode,
                    "action_patterns": actions,
                    "resource_mode": resource_mode,
                    "resource_principal_keys": linked,
                    "condition_state": condition_state,
                    "condition_keys": condition_keys,
                    "source_digest": _digest(entry),
                }
            )
            if (
                action_mode != "action"
                or resource_mode in ("unresolved", "not_resource")
                or condition_state != "absent"
            ):
                uncertainty.add("identity_statement_not_evaluated")

    for item in raw["Policies"]:
        arn = item.get("Arn")
        version = item.get("DefaultVersionId")
        if not isinstance(arn, str) or not arn.startswith(f"arn:aws:iam::{account_id}:policy/"):
            raise NormalizationRejected("managed_policy_identity_invalid")
        if arn in policy_by_arn or not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise NormalizationRejected("managed_policy_version_invalid")
        versions = item.get("PolicyVersionList", [])
        if not isinstance(versions, list):
            raise NormalizationRejected("managed_policy_version_invalid")
        selected = [v for v in versions if isinstance(v, dict) and v.get("VersionId") == version]
        document_value = selected[0].get("Document") if len(selected) == 1 else None
        key, document = add_policy(arn, "managed", version, document_value)
        policy_by_arn[arn] = key
        parse_identity(document, key)

    referenced_aws: set[str] = set()
    for owner, _, _ in owners:
        for attached in owner.get("AttachedManagedPolicies", []):
            if isinstance(attached, dict):
                arn = attached.get("PolicyArn")
                if isinstance(arn, str) and arn.startswith("arn:aws:iam::aws:policy/"):
                    referenced_aws.add(arn)
        boundary = owner.get("PermissionsBoundary")
        if isinstance(boundary, dict):
            arn = boundary.get("PermissionsBoundaryArn")
            if isinstance(arn, str) and arn.startswith("arn:aws:iam::aws:policy/"):
                referenced_aws.add(arn)
    reads_by_policy = {item.policy_arn: item for item in read.managed_policy_reads}
    if (
        len(reads_by_policy) != len(read.managed_policy_reads)
        or set(reads_by_policy) - referenced_aws
    ):
        raise NormalizationRejected("managed_policy_read_binding_invalid")
    policy_tasks: list[dict[str, Any]] = []
    for arn in sorted(referenced_aws):
        policy_read = reads_by_policy.get(arn)
        if policy_read is None:
            identity_gaps.add("managed_policy_unfetched")
            continue
        policy_task_start = len(policy_tasks)
        if policy_read.status == "succeeded":
            if (
                len(policy_read.response_digests) != 2
                or not isinstance(policy_read.default_version, str)
                or not _VERSION.fullmatch(policy_read.default_version)
                or arn in policy_by_arn
            ):
                raise NormalizationRejected("managed_policy_read_binding_invalid")
            key, document = add_policy(
                arn, "managed", policy_read.default_version, policy_read.document
            )
            policy_by_arn[arn] = key
            parse_identity(document, key)
            for operation, digest in zip(
                ("iam:GetPolicy", "iam:GetPolicyVersion"),
                policy_read.response_digests,
                strict=True,
            ):
                policy_tasks.append(
                    {
                        "operation": operation,
                        "attempt": 1,
                        "outcome": "succeeded",
                        "page_count": 1,
                        "item_count": 1,
                        "pagination_complete": True,
                        "response_digest": digest,
                    }
                )
        else:
            reason = policy_read.error_code or "managed_policy_unfetched"
            identity_gaps.add(reason)
            if policy_read.status != "not_collected":
                if policy_read.response_digests:
                    policy_tasks.append(
                        {
                            "operation": "iam:GetPolicy",
                            "attempt": 1,
                            "outcome": "succeeded",
                            "page_count": 1,
                            "item_count": 1,
                            "pagination_complete": True,
                            "response_digest": policy_read.response_digests[0],
                        }
                    )
                policy_tasks.append(
                    {
                        "operation": (
                            "iam:GetPolicyVersion"
                            if policy_read.response_digests
                            else "iam:GetPolicy"
                        ),
                        "attempt": 1,
                        "outcome": "partial",
                        "page_count": 0,
                        "item_count": 0,
                        "pagination_complete": False,
                        "error_code": reason,
                    }
                )

        for task in policy_tasks[policy_task_start:]:
            task["subject_policy_fingerprint"] = "hmac-sha256:" + _hmac(
                hmac_secret, "managed-policy:" + arn
            )

    for owner, principal_key, owner_arn in owners:
        for attached in owner.get("AttachedManagedPolicies", []):
            if not isinstance(attached, dict) or not isinstance(attached.get("PolicyArn"), str):
                identity_gaps.add("managed_attachment_unreadable")
                continue
            attached_policy_key = policy_by_arn.get(attached["PolicyArn"])
            if attached_policy_key is None:
                identity_gaps.add("managed_policy_unfetched")
                continue
            attachments.append(
                {
                    "principal_key": principal_key,
                    "policy_key": attached_policy_key,
                    "kind": "managed",
                    "source_digest": _digest(attached),
                }
            )
        field = {
            "iam_user": "UserPolicyList",
            "iam_role": "RolePolicyList",
            "iam_group": "GroupPolicyList",
        }[next(p["kind"] for p in principals if p["principal_key"] == principal_key)]
        inline = owner.get(field, [])
        if not isinstance(inline, list):
            identity_gaps.add("inline_policy_list_unreadable")
            continue
        for entry in inline:
            if not isinstance(entry, dict) or not isinstance(entry.get("PolicyName"), str):
                identity_gaps.add("inline_policy_unreadable")
                continue
            key, document = add_policy(
                owner_arn + "/inline/" + entry["PolicyName"],
                "inline",
                None,
                entry.get("PolicyDocument"),
            )
            attachments.append(
                {
                    "principal_key": principal_key,
                    "policy_key": key,
                    "kind": "inline",
                    "source_digest": _digest(entry),
                }
            )
            parse_identity(document, key)
        if owner.get("PermissionsBoundary") is not None:
            uncertainty.add("permissions_boundary_not_resolved")

    for role, role_key, role_arn in (x for x in owners if x[0].get("RoleName") is not None):
        key, document = add_policy(
            role_arn + "/trust", "trust", None, role.get("AssumeRolePolicyDocument")
        )
        if document is None:
            trust_gaps.add("trust_document_unreadable")
            continue
        entries = _statements(document)
        if entries is None:
            trust_gaps.add("trust_statement_unreadable")
            continue
        for index, entry in enumerate(entries):
            if entry.get("Effect") not in ("Allow", "Deny"):
                trust_gaps.add("trust_effect_unsupported")
                continue
            action_mode, actions = _actions(entry, cap=50)
            condition_state, condition_keys = _conditions(entry)
            principal = entry.get("Principal")
            linked: list[str] = []
            services: list[str] = []
            unresolved = not isinstance(principal, dict)
            if isinstance(principal, dict):
                for category, selectors in principal.items():
                    values = _list(selectors, cap=100)
                    if values is None:
                        unresolved = True
                        continue
                    for selector in values:
                        if (
                            category == "AWS"
                            and isinstance(selector, str)
                            and selector in arn_to_principal
                        ):
                            linked.append(arn_to_principal[selector])
                        elif (
                            category == "Service"
                            and isinstance(selector, str)
                            and _SERVICE.fullmatch(selector)
                        ):
                            services.append(selector)
                        else:
                            unresolved = True
            if unresolved or not (linked or services) or len(services) > 50:
                linked, services = [], []
                selector_state = "unresolved"
                trust_gaps.add("trust_selector_unresolved")
            else:
                selector_state = "linked"
            trust_statements.append(
                {
                    "statement_key": _key(hmac_secret, "st_", f"{key}:{index}"),
                    "policy_key": key,
                    "role_key": role_key,
                    "effect": entry["Effect"].lower(),
                    "action_mode": action_mode,
                    "action_patterns": actions,
                    "trusted_principal_keys": list(dict.fromkeys(linked)),
                    "service_principals": list(dict.fromkeys(services)),
                    "selector_state": selector_state,
                    "condition_state": condition_state,
                    "condition_keys": condition_keys,
                    "source_digest": _digest(entry),
                }
            )
            if action_mode != "action" or condition_state != "absent":
                uncertainty.add("trust_statement_not_evaluated")

    memberships: list[dict[str, Any]] = []
    for user, user_key in users:
        group_names = user.get("GroupList", [])
        if not isinstance(group_names, list):
            identity_gaps.add("group_membership_unreadable")
            continue
        for group_name in group_names:
            group_key = groups_by_name.get(group_name) if isinstance(group_name, str) else None
            if group_key is None:
                identity_gaps.add("group_detail_missing")
                continue
            memberships.append(
                {
                    "user_key": user_key,
                    "group_key": group_key,
                    "source_digest": _digest([user.get("Arn"), group_name]),
                }
            )

    reads_by_arn = {item.user_arn: item for item in read.group_traversals}
    if len(reads_by_arn) != len(read.group_traversals):
        raise NormalizationRejected("duplicate_group_read")
    group_tasks: list[dict[str, Any]] = []
    group_traversals: list[dict[str, Any]] = []
    for user, user_key in users:
        user_arn = user.get("Arn")
        if not isinstance(user_arn, str):
            raise NormalizationRejected("group_read_binding_invalid")
        group_read = reads_by_arn.get(user_arn)
        if group_read is None:
            group_traversals.append(
                {
                    "user_key": user_key,
                    "state": "not_collected",
                    "reason_code": "list_groups_for_user_not_run",
                }
            )
            identity_gaps.add("group_traversal_not_independently_read")
            continue
        if group_read.user_name != user.get("UserName"):
            raise NormalizationRejected("group_read_binding_invalid")
        if group_read.status == "succeeded":
            observed_names = [
                group["GroupName"]
                for group in group_read.groups
                if isinstance(group.get("GroupName"), str)
            ]
            declared_names = user.get("GroupList", [])
            membership_count = sum(item["user_key"] == user_key for item in memberships)
            consistent = (
                isinstance(declared_names, list)
                and all(isinstance(name, str) for name in declared_names)
                and len(observed_names) == len(group_read.groups)
                and sorted(observed_names) == sorted(declared_names)
                and len(observed_names) == membership_count
                and group_read.response_digest is not None
            )
            if consistent:
                group_traversals.append(
                    {
                        "user_key": user_key,
                        "state": "complete",
                        "membership_count": membership_count,
                        "evidence_digest": group_read.response_digest,
                    }
                )
            else:
                group_traversals.append(
                    {
                        "user_key": user_key,
                        "state": "partial",
                        "reason_code": "group_lists_disagree",
                    }
                )
                identity_gaps.add("group_lists_disagree")
            group_tasks.append(
                {
                    "operation": "iam:ListGroupsForUser",
                    "subject_principal_key": user_key,
                    "attempt": 1,
                    "outcome": "succeeded",
                    "page_count": group_read.page_count,
                    "item_count": len(group_read.groups),
                    "pagination_complete": True,
                    "response_digest": group_read.response_digest,
                }
            )
        else:
            reason = group_read.error_code or "group_read_incomplete"
            group_traversals.append(
                {
                    "user_key": user_key,
                    "state": "not_collected" if group_read.status == "not_collected" else "partial",
                    "reason_code": reason,
                }
            )
            identity_gaps.add(reason)
            if group_read.status != "not_collected":
                group_tasks.append(
                    {
                        "operation": "iam:ListGroupsForUser",
                        "subject_principal_key": user_key,
                        "attempt": 1,
                        "outcome": "partial",
                        "page_count": group_read.page_count,
                        "item_count": 0,
                        "pagination_complete": False,
                        "error_code": reason,
                    }
                )
    if set(reads_by_arn) - {user.get("Arn") for user, _ in users}:
        raise NormalizationRejected("group_read_subject_unknown")

    inventory_data = {
        "snapshot_id": "snapshot_" + secrets.token_hex(16),
        "principals": principals,
        "policies": policies,
        "statements": statements,
        "attachments": attachments,
        "memberships": memberships,
        "group_traversals": group_traversals,
        "trust_statements": trust_statements,
    }
    try:
        inventory = InventorySnapshot.model_validate(inventory_data)
    except ValueError:
        raise NormalizationRejected("normalized_inventory_invalid") from None

    def coverage(layer: PolicyLayer, gaps: set[str], count: int) -> dict[str, Any]:
        if gaps:
            return {
                "layer": layer,
                "state": "partial",
                "object_count": count,
                "reason_code": sorted(gaps)[0],
            }
        return {"layer": layer, "state": "collected" if count else "absent", "object_count": count}

    layers = [
        coverage(PolicyLayer.identity_policy, identity_gaps, len(statements)),
        coverage(PolicyLayer.trust_policy, trust_gaps, len(trust_statements)),
    ]
    layers.extend(
        {"layer": layer, "state": "not_collected", "reason_code": "outside_current_read_scope"}
        for layer in PolicyLayer
        if layer not in {PolicyLayer.identity_policy, PolicyLayer.trust_policy}
    )
    uncertainty.update(identity_gaps)
    uncertainty.update(trust_gaps)
    run_id = "run_" + secrets.token_hex(16)
    response_digest = _digest(read.pages)
    manifest = {
        "data_kind": "real_account_observed",
        "run_id": run_id,
        "snapshot_id": inventory.snapshot_id,
        "account_alias": "fyp-project",
        "account_fingerprint": "hmac-sha256:" + _hmac(hmac_secret, account_id),
        "collector_version": "aws_authz_0.1",
        "started_at": started_at.astimezone(UTC),
        "sealed_at": sealed_at.astimezone(UTC),
        "outcome": "partial"
        if any(task["outcome"] != "succeeded" for task in [*group_tasks, *policy_tasks])
        else "succeeded",
        "snapshot_digest": inventory.content_digest(),
        "tasks": [
            {
                "operation": "iam:GetAccountAuthorizationDetails",
                "attempt": 1,
                "outcome": "succeeded",
                "page_count": read.page_count,
                "item_count": sum(map(len, raw.values())),
                "pagination_complete": True,
                "response_digest": response_digest,
            },
            *group_tasks,
            *policy_tasks,
        ],
        "coverage": layers,
    }
    try:
        handoff = CollectionHandoff.model_validate(
            {"manifest": manifest, "inventory": inventory.model_dump(mode="json")}
        )
    except ValueError:
        raise NormalizationRejected("normalized_handoff_invalid") from None
    return NormalizationResult(handoff, tuple(sorted(uncertainty)))
