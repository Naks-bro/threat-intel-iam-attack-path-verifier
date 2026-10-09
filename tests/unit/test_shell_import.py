"""Proposed handoff-to-0009 compatibility, with no database or AWS access."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from fyp_iam.contracts.collection import CollectionOutcome, PolicyLayer, TaskOutcome
from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
from fyp_iam.engine2.schema import metadata
from fyp_iam.engine2.shell_import import (
    ShellImportPlan,
    ShellImportRejected,
    prepare_shell_import,
)

USER = "p_" + "a" * 32
ACCOUNT_HMAC = "hmac-sha256:" + "b" * 64
USER_HMAC = "hmac-sha256:" + "c" * 64
DIGEST = "sha256:" + "d" * 64


def _handoff(*, real: bool = False) -> CollectionHandoff:
    inventory = InventorySnapshot.model_validate(
        {
            "snapshot_id": "snapshot_1",
            "principals": [
                {
                    "principal_key": USER,
                    "principal_fingerprint": USER_HMAC,
                    "kind": "iam_user",
                    "display_alias": "user-00000001",
                    "source_digest": DIGEST,
                }
            ],
        }
    )
    return CollectionHandoff.model_validate(
        {
            "manifest": {
                "data_kind": "real_account_observed" if real else "synthetic",
                "run_id": "run_1",
                "snapshot_id": inventory.snapshot_id,
                "account_alias": "sandbox",
                "account_fingerprint": ACCOUNT_HMAC,
                "collector_version": "test-1",
                "started_at": datetime(2026, 10, 9, tzinfo=UTC),
                "sealed_at": datetime(2026, 10, 9, tzinfo=UTC) + timedelta(seconds=1),
                "outcome": "succeeded",
                "snapshot_digest": inventory.content_digest(),
                "tasks": [
                    {
                        "operation": "iam:ListUsers",
                        "subject_principal_key": USER,
                        "attempt": 1,
                        "outcome": "succeeded",
                        "page_count": 1,
                        "item_count": 1,
                        "pagination_complete": True,
                        "response_digest": DIGEST,
                    }
                ],
                "coverage": [
                    {"layer": layer, "state": "absent", "object_count": 0} for layer in PolicyLayer
                ],
            },
            "inventory": inventory.model_dump(mode="json"),
        }
    )


def _prepare(handoff: CollectionHandoff, **overrides: Any) -> ShellImportPlan:
    kwargs: dict[str, Any] = {
        "connection_id": "connection_1",
        "expected_account_fingerprint": ACCOUNT_HMAC,
        "request_id": "request_1",
    }
    kwargs.update(overrides)
    return prepare_shell_import(handoff, **kwargs)


def test_synthetic_plan_maps_to_exact_0009_columns_without_policy_content() -> None:
    handoff = _handoff()
    plan = _prepare(handoff)
    assert plan.snapshot["seal_status"] == "complete"
    assert plan.snapshot["content_hash"] == handoff.manifest.snapshot_digest
    assert plan.snapshot["handoff_hash"] == handoff.content_digest()
    assert plan.tasks[0]["scope_key"] == USER_HMAC
    assert plan.tasks[0]["sequence_no"] == 0
    assert len(plan.coverage) == len(PolicyLayer)
    assert {row["layer"] for row in plan.coverage} == {layer.value for layer in PolicyLayer}
    assert all(row["authorization_evaluated"] is False for row in plan.coverage)
    assert plan.gaps == ()
    for table_name, row in (
        ("collection_runs", plan.run),
        ("collection_tasks", plan.tasks[0]),
        ("account_snapshots", plan.snapshot),
        ("collection_layer_coverage", plan.coverage[0]),
    ):
        assert set(row) == set(metadata.tables[f"foundry.{table_name}"].columns.keys())
        assert not {"policy_body", "raw_arn", "account_id", "secret"} & set(row)


def test_real_user_without_group_traversal_is_partial_not_clean() -> None:
    plan = _prepare(_handoff(real=True))
    assert plan.snapshot["seal_status"] == "partial"
    assert plan.snapshot["retention_expires_at"] - plan.snapshot["sealed_at"] == timedelta(days=90)
    assert len(plan.gaps) == 1
    assert plan.gaps[0]["reason_code"] == "group_traversal_missing"
    assert plan.gaps[0]["scope_key"] == USER_HMAC


def test_successful_task_without_digest_is_not_importable() -> None:
    handoff = _handoff()
    handoff.manifest.tasks[0].response_digest = None
    with pytest.raises(ShellImportRejected, match="^successful_task_digest_missing$"):
        _prepare(handoff)


def test_duplicated_task_attempt_is_not_importable() -> None:
    handoff = _handoff()
    handoff.manifest.tasks.append(handoff.manifest.tasks[0].model_copy(deep=True))
    with pytest.raises(ShellImportRejected, match="^duplicate_task_attempt$"):
        _prepare(handoff)


def test_distinct_managed_policy_reads_have_distinct_task_scopes() -> None:
    handoff = _handoff()
    for fingerprint in ("hmac-sha256:" + "1" * 64, "hmac-sha256:" + "2" * 64):
        task = handoff.manifest.tasks[0].model_copy(deep=True)
        task.operation = "iam:GetPolicy"
        task.subject_principal_key = None
        task.subject_policy_fingerprint = fingerprint
        handoff.manifest.tasks.append(task)
    plan = _prepare(handoff)
    assert [task["scope_key"] for task in plan.tasks[1:]] == [
        "hmac-sha256:" + "1" * 64,
        "hmac-sha256:" + "2" * 64,
    ]


def test_unknown_task_subject_is_not_importable() -> None:
    handoff = _handoff()
    handoff.manifest.tasks[0].subject_principal_key = "p_" + "f" * 32
    with pytest.raises(ShellImportRejected, match="^task_subject_unknown$"):
        _prepare(handoff)


def test_unauthorized_connection_fingerprint_is_rejected() -> None:
    with pytest.raises(ShellImportRejected, match="^account_fingerprint_mismatch$"):
        _prepare(_handoff(), expected_account_fingerprint="hmac-sha256:" + "0" * 64)


def test_request_id_cannot_hold_credential_shaped_text() -> None:
    with pytest.raises(ShellImportRejected, match="^identifier_not_storable$"):
        _prepare(_handoff(), request_id="AKIA" + "A" * 16)


def test_mutated_handoff_binding_is_revalidated() -> None:
    handoff = _handoff()
    handoff.inventory.principals[0].display_alias = "user-00000002"
    with pytest.raises(ShellImportRejected, match="^handoff_invalid$"):
        _prepare(handoff)


def test_partial_run_requires_coverage_gap() -> None:
    handoff = _handoff()
    task = handoff.manifest.tasks[0]
    task.outcome = TaskOutcome.failed
    task.error_code = "read_failed"
    handoff.manifest.outcome = CollectionOutcome.partial
    with pytest.raises(ShellImportRejected, match="^partial_run_without_coverage_gap$"):
        _prepare(handoff)
