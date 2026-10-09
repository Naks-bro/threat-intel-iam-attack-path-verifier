"""Normalized IAM records must fit proposed 0010 without cross-snapshot drift."""

from datetime import UTC, datetime, timedelta

import pytest

from fyp_iam.contracts.collection import PolicyLayer
from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
from fyp_iam.engine2.inventory_import import prepare_inventory_import
from fyp_iam.engine2.schema import metadata
from fyp_iam.engine2.shell_import import ShellImportRejected, prepare_shell_import

USER = "p_" + "a" * 32
ROLE = "p_" + "b" * 32
GROUP = "p_" + "c" * 32
POLICY = "pol_" + "d" * 32
TRUST = "pol_" + "e" * 32
STATEMENT = "st_" + "f" * 32
TRUST_STATEMENT = "st_" + "1" * 32
DIGEST = "sha256:" + "2" * 64
ACCOUNT_HMAC = "hmac-sha256:" + "3" * 64
USER_HMAC = "hmac-sha256:" + "4" * 64


def _handoff(*, group_task: bool = True) -> CollectionHandoff:
    inventory = InventorySnapshot.model_validate(
        {
            "snapshot_id": "inventory_import_test",
            "principals": [
                {
                    "principal_key": key,
                    "principal_fingerprint": fingerprint,
                    "kind": kind,
                    "display_alias": alias,
                    "source_digest": DIGEST,
                }
                for key, fingerprint, kind, alias in (
                    (USER, USER_HMAC, "iam_user", "user-00000001"),
                    (ROLE, "hmac-sha256:" + "5" * 64, "iam_role", "role-00000002"),
                    (GROUP, "hmac-sha256:" + "6" * 64, "iam_group", "group-00000003"),
                )
            ],
            "policies": [
                {
                    "policy_key": POLICY,
                    "kind": "managed",
                    "version_label": "v1",
                    "is_default": True,
                    "parse_state": "parsed",
                    "source_digest": DIGEST,
                },
                {
                    "policy_key": TRUST,
                    "kind": "trust",
                    "parse_state": "parsed",
                    "source_digest": DIGEST,
                },
            ],
            "statements": [
                {
                    "statement_key": STATEMENT,
                    "policy_key": POLICY,
                    "effect": "allow",
                    "action_mode": "action",
                    "action_patterns": ["iam:CreateAccessKey"],
                    "resource_mode": "linked_principals",
                    "resource_principal_keys": [ROLE],
                    "condition_state": "absent",
                    "source_digest": DIGEST,
                }
            ],
            "attachments": [
                {
                    "principal_key": USER,
                    "policy_key": POLICY,
                    "kind": "managed",
                    "source_digest": DIGEST,
                }
            ],
            "memberships": [{"user_key": USER, "group_key": GROUP, "source_digest": DIGEST}],
            "group_traversals": [
                {
                    "user_key": USER,
                    "state": "complete",
                    "membership_count": 1,
                    "evidence_digest": DIGEST,
                }
            ],
            "trust_statements": [
                {
                    "statement_key": TRUST_STATEMENT,
                    "policy_key": TRUST,
                    "role_key": ROLE,
                    "effect": "allow",
                    "action_mode": "action",
                    "action_patterns": ["sts:AssumeRole"],
                    "trusted_principal_keys": [USER],
                    "selector_state": "linked",
                    "condition_state": "absent",
                    "source_digest": DIGEST,
                }
            ],
        }
    )
    tasks: list[dict[str, object]] = [
        {
            "operation": "iam:ListUsers",
            "attempt": 1,
            "outcome": "succeeded",
            "page_count": 1,
            "item_count": 1,
            "pagination_complete": True,
            "response_digest": DIGEST,
        }
    ]
    if group_task:
        tasks.append(
            {
                "operation": "iam:ListGroupsForUser",
                "subject_principal_key": USER,
                "attempt": 1,
                "outcome": "succeeded",
                "page_count": 1,
                "item_count": 1,
                "pagination_complete": True,
                "response_digest": DIGEST,
            }
        )
    return CollectionHandoff.model_validate(
        {
            "manifest": {
                "data_kind": "synthetic",
                "run_id": "inventory_import_run",
                "snapshot_id": inventory.snapshot_id,
                "account_alias": "synthetic-lab",
                "account_fingerprint": ACCOUNT_HMAC,
                "collector_version": "test-1",
                "started_at": datetime(2026, 10, 9, tzinfo=UTC),
                "sealed_at": datetime(2026, 10, 9, tzinfo=UTC) + timedelta(seconds=1),
                "outcome": "succeeded",
                "snapshot_digest": inventory.content_digest(),
                "tasks": tasks,
                "coverage": [
                    {"layer": layer, "state": "not_collected", "reason_code": "outside_scope"}
                    for layer in PolicyLayer
                ],
            },
            "inventory": inventory.model_dump(mode="json"),
        }
    )


def _shell(handoff: CollectionHandoff):  # type: ignore[no-untyped-def]
    return prepare_shell_import(
        handoff,
        connection_id="inventory_import_connection",
        expected_account_fingerprint=ACCOUNT_HMAC,
        request_id="inventory_import_request",
    )


def test_all_normalized_records_fit_0010_columns_and_scoped_refs() -> None:
    handoff = _handoff()
    plan = prepare_inventory_import(handoff, _shell(handoff))
    rows = {
        "iam_principals": plan.principals,
        "iam_policies": plan.policies,
        "iam_identity_statements": plan.identity_statements,
        "iam_statement_resource_refs": plan.statement_resource_refs,
        "iam_attachments": plan.attachments,
        "iam_memberships": plan.memberships,
        "iam_group_traversals": plan.group_traversals,
        "iam_trust_statements": plan.trust_statements,
        "iam_trust_principal_refs": plan.trust_principal_refs,
    }
    assert all(rows.values())
    for table_name, records in rows.items():
        columns = set(metadata.tables[f"foundry.{table_name}"].columns.keys())
        assert all(set(record) == columns for record in records)
        assert all(record["snapshot_id"] == handoff.inventory.snapshot_id for record in records)
    assert plan.group_traversals[0]["task_id"] == _shell(handoff).tasks[1]["task_id"]
    assert plan.statement_resource_refs[0]["principal_key"] == ROLE
    assert plan.trust_principal_refs[0]["principal_key"] == USER


def test_changed_shell_plan_cannot_bind_same_inventory() -> None:
    handoff = _handoff()
    shell = _shell(handoff)
    shell.tasks[0]["item_count"] = 2
    with pytest.raises(ShellImportRejected, match="^shell_inventory_binding_mismatch$"):
        prepare_inventory_import(handoff, shell)


def test_complete_group_traversal_requires_exact_read_task() -> None:
    handoff = _handoff(group_task=False)
    with pytest.raises(ShellImportRejected, match="^complete_group_traversal_task_ambiguous$"):
        prepare_inventory_import(handoff, _shell(handoff))


def test_oversized_action_is_rejected_before_database() -> None:
    handoff = _handoff()
    handoff.inventory.statements[0].action_patterns = ["iam:" + "A" * 125]
    handoff.manifest.snapshot_digest = handoff.inventory.content_digest()
    with pytest.raises(ShellImportRejected, match="^statement_action_too_long$"):
        prepare_inventory_import(handoff, _shell(handoff))
