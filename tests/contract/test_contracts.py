from pathlib import Path

import pytest
from pydantic import ValidationError

from fyp_iam.contracts.models import ApprovedRule, EdgeType, IAMGraphSnapshot
from fyp_iam.fixtures.builders import assume_chain_rule, make_snapshot, principal
from fyp_iam.fixtures.cases import all_cases
from fyp_iam.fixtures.loader import load_fixture


def test_checked_in_fixtures_match_builders(fixture_dir: Path) -> None:
    for case in all_cases():
        loaded = load_fixture(fixture_dir, case.case_id)
        assert loaded.model_dump(mode="json", by_alias=True) == case.model_dump(
            mode="json", by_alias=True
        )


def test_path_pattern_uses_contract_field_names() -> None:
    payload = assume_chain_rule("rule_names").model_dump(mode="json", by_alias=True)
    assert payload["path_pattern"][0]["from"] == "principal"
    assert payload["path_pattern"][0]["relationship"] == "CAN_ASSUME"


def test_unknown_relationship_is_rejected() -> None:
    payload = assume_chain_rule("rule_bad_relationship").model_dump(mode="json", by_alias=True)
    payload["path_pattern"][0]["relationship"] = "DETACH DELETE"
    with pytest.raises(ValidationError):
        ApprovedRule.model_validate(payload)


def test_account_id_is_rejected() -> None:
    nodes = [principal("principal:user/alice", "alice", "iam_user")]
    snapshot = make_snapshot("snapshot_alias", nodes, []).model_dump(mode="json")
    snapshot["scope"]["account_alias"] = "123456789012"
    with pytest.raises(ValidationError):
        IAMGraphSnapshot.model_validate(snapshot)


def test_dangling_edge_is_rejected() -> None:
    nodes = [principal("principal:user/alice", "alice", "iam_user")]
    snapshot = make_snapshot("snapshot_dangling", nodes, []).model_dump(mode="json")
    snapshot["edges"] = [
        {
            "edge_id": "edge_missing",
            "edge_type": EdgeType.CAN_ASSUME.value,
            "source_id": "principal:user/alice",
            "target_id": "principal:role/missing",
            "derivation": "policy_analysis",
            "policy_refs": ["policy_missing"],
            "condition_summary": {},
            "confidence": "deterministic",
            "effect": "allow",
        }
    ]
    with pytest.raises(ValidationError):
        IAMGraphSnapshot.model_validate(snapshot)


def test_raw_arn_text_is_rejected() -> None:
    payload = assume_chain_rule("rule_arn").model_dump(mode="json", by_alias=True)
    payload["description"] = "arn:aws:iam::123456789012:role/admin"
    with pytest.raises(ValidationError):
        ApprovedRule.model_validate(payload)


def test_naive_timestamp_is_rejected() -> None:
    payload = assume_chain_rule("rule_naive").model_dump(mode="json", by_alias=True)
    payload["created_at"] = "2026-10-02T12:00:00"
    with pytest.raises(ValidationError):
        ApprovedRule.model_validate(payload)


def test_remediation_cannot_skip_human_review() -> None:
    from fyp_iam.contracts.models import RemediationProposal

    with pytest.raises(ValidationError):
        RemediationProposal(proposal="Remove the edge.", requires_human_review=False)
