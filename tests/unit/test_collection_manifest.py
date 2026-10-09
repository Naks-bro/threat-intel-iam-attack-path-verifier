"""Sealed collection metadata is strict, redacted, and honest about gaps."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from fyp_iam.contracts.collection import CollectionManifest, PolicyLayer


def _manifest() -> dict[str, object]:
    return {
        "data_kind": "synthetic",
        "run_id": "run_01",
        "snapshot_id": "snapshot_01",
        "account_alias": "lab-account",
        "account_fingerprint": "hmac-sha256:" + "a" * 64,
        "collector_version": "test-1",
        "started_at": datetime(2026, 10, 9, tzinfo=UTC),
        "sealed_at": datetime(2026, 10, 9, tzinfo=UTC) + timedelta(seconds=1),
        "outcome": "succeeded",
        "snapshot_digest": "sha256:" + "b" * 64,
        "tasks": [
            {
                "operation": "iam:ListUsers",
                "attempt": 1,
                "outcome": "succeeded",
                "page_count": 1,
                "item_count": 0,
                "pagination_complete": True,
            }
        ],
        "coverage": [
            {
                "layer": layer,
                "state": "absent" if layer == PolicyLayer.identity_policy else "not_collected",
                "object_count": 0 if layer == PolicyLayer.identity_policy else None,
                "reason_code": None if layer == PolicyLayer.identity_policy else "outside_scope",
            }
            for layer in PolicyLayer
        ],
    }


def test_valid_manifest_separates_run_success_from_authorization_coverage() -> None:
    manifest = CollectionManifest.model_validate(_manifest())
    assert manifest.outcome == "succeeded"
    assert len(manifest.coverage) == len(PolicyLayer)
    assert manifest.coverage[1].state == "not_collected"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_alias", "123456789012"),
        ("account_alias", "arn:aws:iam::123456789012:user/admin"),
        ("run_id", "123456789012"),
        ("account_fingerprint", "123456789012"),
        ("snapshot_digest", "not-a-digest"),
    ],
)
def test_identifiers_and_unbound_digests_are_rejected(field: str, value: str) -> None:
    data = _manifest()
    data[field] = value
    with pytest.raises(ValidationError):
        CollectionManifest.model_validate(data)


def test_duplicate_layer_or_missing_layer_is_rejected() -> None:
    data = _manifest()
    coverage = data["coverage"]
    assert isinstance(coverage, list)
    coverage[1]["layer"] = PolicyLayer.identity_policy
    with pytest.raises(ValidationError):
        CollectionManifest.model_validate(data)


def test_success_requires_complete_pagination() -> None:
    data = _manifest()
    tasks = data["tasks"]
    assert isinstance(tasks, list)
    tasks[0]["pagination_complete"] = False
    with pytest.raises(ValidationError):
        CollectionManifest.model_validate(data)


def test_partial_run_names_failure_and_does_not_erase_coverage() -> None:
    data = _manifest()
    data["outcome"] = "partial"
    tasks = data["tasks"]
    assert isinstance(tasks, list)
    tasks[0]["outcome"] = "throttled"
    tasks[0]["pagination_complete"] = False
    tasks[0]["error_code"] = "rate_limited"
    manifest = CollectionManifest.model_validate(data)
    assert manifest.outcome == "partial"
    assert manifest.tasks[0].error_code == "rate_limited"


def test_absent_requires_observed_zero_count() -> None:
    data = _manifest()
    coverage = data["coverage"]
    assert isinstance(coverage, list)
    coverage[0]["object_count"] = None
    with pytest.raises(ValidationError):
        CollectionManifest.model_validate(data)


def test_collection_cannot_claim_authorization_evaluation() -> None:
    data = _manifest()
    coverage = data["coverage"]
    assert isinstance(coverage, list)
    coverage[0]["authorization_evaluated"] = True
    with pytest.raises(ValidationError):
        CollectionManifest.model_validate(data)
