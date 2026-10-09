"""Offline structural what-if checks; no AWS or database access."""

from datetime import UTC, datetime

import pytest

from fyp_iam.contracts.models import DiscoveryLimits
from fyp_iam.engine3.what_if import LIMITATION, preview_edge_removal
from fyp_iam.fixtures.loader import load_fixture


def test_credential_edge_removal_only_changes_the_hypothetical(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "credential_creation")
    original_bytes = case.snapshot.model_dump_json()
    result = preview_edge_removal(
        case.rules,
        case.snapshot,
        "edge_developer_create_key",
        evaluated_at=case.evaluated_at,
    )

    assert len(result.baseline.findings) == 1
    assert result.hypothetical.findings == []
    assert result.disappeared_candidate_paths == 1
    assert result.appeared_candidate_paths == 0
    assert result.comparison_complete is True
    assert result.hypothetical_snapshot_id != result.original_snapshot_id
    assert result.hypothetical.snapshot_id == result.hypothetical_snapshot_id
    assert result.limitation == LIMITATION
    assert case.snapshot.model_dump_json() == original_bytes


def test_unknown_edge_is_rejected(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "credential_creation")
    with pytest.raises(ValueError, match="edge_id is not present"):
        preview_edge_removal(case.rules, case.snapshot, "missing", evaluated_at=case.evaluated_at)


def test_non_synthetic_snapshot_is_rejected(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "credential_creation")
    collection = case.snapshot.collection.model_copy(
        update={"permissions_profile": "aws-read-only"}
    )
    snapshot = case.snapshot.model_copy(update={"collection": collection})
    with pytest.raises(ValueError, match="explicitly synthetic"):
        preview_edge_removal(
            case.rules, snapshot, "edge_developer_create_key", evaluated_at=case.evaluated_at
        )


def test_bounded_search_does_not_claim_complete_comparison(fixture_dir) -> None:
    case = load_fixture(fixture_dir, "credential_creation")
    result = preview_edge_removal(
        case.rules,
        case.snapshot,
        "edge_developer_create_key",
        evaluated_at=datetime(2026, 10, 2, tzinfo=UTC),
        limits=DiscoveryLimits(max_expansions=0),
    )
    assert result.comparison_complete is False
    assert "max_expansions" in result.baseline.truncation_reasons
