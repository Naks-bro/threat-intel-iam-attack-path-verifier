"""Pure normalized inventory-to-0010 row mapper; no database or AWS access."""

from dataclasses import dataclass
from typing import Any

from fyp_iam.contracts.inventory import CollectionHandoff
from fyp_iam.engine2.shell_import import (
    ShellImportPlan,
    ShellImportRejected,
    prepare_shell_import,
)


@dataclass(frozen=True)
class InventoryImportPlan:
    principals: tuple[dict[str, Any], ...]
    policies: tuple[dict[str, Any], ...]
    identity_statements: tuple[dict[str, Any], ...]
    statement_resource_refs: tuple[dict[str, Any], ...]
    attachments: tuple[dict[str, Any], ...]
    memberships: tuple[dict[str, Any], ...]
    group_traversals: tuple[dict[str, Any], ...]
    trust_statements: tuple[dict[str, Any], ...]
    trust_principal_refs: tuple[dict[str, Any], ...]


def prepare_inventory_import(
    handoff: CollectionHandoff, shell: ShellImportPlan
) -> InventoryImportPlan:
    """Bind exact handoff bytes to a shell plan and map normalized records.

    The eventual writer must insert shell and inventory rows in one transaction,
    verify row counts/digests, then commit. These objects are not a seal, source
    attestation, permission evaluation, or authorization to retain account data.
    """

    try:
        sealed = CollectionHandoff.model_validate(handoff.model_dump(mode="json"))
    except (ValueError, TypeError) as exc:
        raise ShellImportRejected("handoff_invalid") from exc
    inventory = sealed.inventory
    snapshot_id = inventory.snapshot_id
    rebuilt = prepare_shell_import(
        sealed,
        connection_id=shell.run["connection_id"],
        expected_account_fingerprint=sealed.manifest.account_fingerprint,
        request_id=shell.run["request_id"],
        attempt=shell.run["attempt"],
        retry_of=shell.run["retry_of"],
    )
    if shell != rebuilt:
        raise ShellImportRejected("shell_inventory_binding_mismatch")

    if any(len(pattern) > 128 for item in inventory.statements for pattern in item.action_patterns):
        raise ShellImportRejected("statement_action_too_long")
    if any(
        len(pattern) > 128
        for item in inventory.trust_statements
        for pattern in item.action_patterns
    ):
        raise ShellImportRejected("trust_action_too_long")
    if any(
        len(set(item.resource_principal_keys)) != len(item.resource_principal_keys)
        for item in inventory.statements
    ):
        raise ShellImportRejected("duplicate_statement_resource")
    if any(
        len(set(item.trusted_principal_keys)) != len(item.trusted_principal_keys)
        for item in inventory.trust_statements
    ):
        raise ShellImportRejected("duplicate_trust_principal")

    task_by_group_read: dict[tuple[str, int, str], list[str]] = {}
    principal_fingerprints = {
        principal.principal_key: principal.principal_fingerprint
        for principal in inventory.principals
    }
    for task in shell.tasks:
        if task["api_name"] != "iam:ListGroupsForUser" or task["status"] != "succeeded":
            continue
        task_by_group_read.setdefault(
            (task["scope_key"], task["item_count"], task["response_digest"]), []
        ).append(task["task_id"])

    traversals: list[dict[str, Any]] = []
    for sequence_no, traversal in enumerate(inventory.group_traversals):
        task_id = None
        if traversal.state == "complete":
            if traversal.membership_count is None or traversal.evidence_digest is None:
                raise ShellImportRejected("complete_group_traversal_invalid")
            matching_tasks = task_by_group_read.get(
                (
                    principal_fingerprints[traversal.user_key],
                    traversal.membership_count,
                    traversal.evidence_digest,
                ),
                [],
            )
            if len(matching_tasks) != 1:
                raise ShellImportRejected("complete_group_traversal_task_ambiguous")
            task_id = matching_tasks[0]
        traversals.append(
            {
                "snapshot_id": snapshot_id,
                "sequence_no": sequence_no,
                "collection_run_id": sealed.manifest.run_id,
                "user_key": traversal.user_key,
                "task_id": task_id,
                "state": traversal.state,
                "membership_count": traversal.membership_count,
                "evidence_digest": traversal.evidence_digest,
                "reason_code": traversal.reason_code,
            }
        )

    return InventoryImportPlan(
        principals=tuple(
            {
                "snapshot_id": snapshot_id,
                "sequence_no": sequence_no,
                "principal_key": item.principal_key,
                "principal_fingerprint": item.principal_fingerprint,
                "kind": item.kind,
                "display_alias": item.display_alias,
                "source_digest": item.source_digest,
            }
            for sequence_no, item in enumerate(inventory.principals)
        ),
        policies=tuple(
            {
                "snapshot_id": snapshot_id,
                "sequence_no": sequence_no,
                "policy_key": item.policy_key,
                "kind": item.kind,
                "version_label": item.version_label,
                "is_default": item.is_default,
                "parse_state": item.parse_state,
                "source_digest": item.source_digest,
            }
            for sequence_no, item in enumerate(inventory.policies)
        ),
        identity_statements=tuple(
            {
                "snapshot_id": snapshot_id,
                "sequence_no": sequence_no,
                "statement_key": item.statement_key,
                "policy_key": item.policy_key,
                "effect": item.effect,
                "action_mode": item.action_mode,
                "action_patterns": item.action_patterns,
                "resource_mode": item.resource_mode,
                "condition_state": item.condition_state,
                "condition_keys": item.condition_keys,
                "source_digest": item.source_digest,
            }
            for sequence_no, item in enumerate(inventory.statements)
        ),
        statement_resource_refs=tuple(
            {
                "snapshot_id": snapshot_id,
                "statement_key": item.statement_key,
                "principal_key": key,
                "sequence_no": sequence_no,
            }
            for item in inventory.statements
            for sequence_no, key in enumerate(item.resource_principal_keys)
        ),
        attachments=tuple(
            {
                "snapshot_id": snapshot_id,
                "sequence_no": sequence_no,
                "principal_key": item.principal_key,
                "policy_key": item.policy_key,
                "kind": item.kind,
                "source_digest": item.source_digest,
            }
            for sequence_no, item in enumerate(inventory.attachments)
        ),
        memberships=tuple(
            {
                "snapshot_id": snapshot_id,
                "sequence_no": sequence_no,
                "user_key": item.user_key,
                "group_key": item.group_key,
                "source_digest": item.source_digest,
            }
            for sequence_no, item in enumerate(inventory.memberships)
        ),
        group_traversals=tuple(traversals),
        trust_statements=tuple(
            {
                "snapshot_id": snapshot_id,
                "sequence_no": sequence_no,
                "statement_key": item.statement_key,
                "policy_key": item.policy_key,
                "role_key": item.role_key,
                "effect": item.effect,
                "action_mode": item.action_mode,
                "action_patterns": item.action_patterns,
                "selector_state": item.selector_state,
                "service_principals": item.service_principals,
                "condition_state": item.condition_state,
                "condition_keys": item.condition_keys,
                "source_digest": item.source_digest,
            }
            for sequence_no, item in enumerate(inventory.trust_statements)
        ),
        trust_principal_refs=tuple(
            {
                "snapshot_id": snapshot_id,
                "statement_key": item.statement_key,
                "principal_key": key,
                "sequence_no": sequence_no,
            }
            for item in inventory.trust_statements
            for sequence_no, key in enumerate(item.trusted_principal_keys)
        ),
    )
