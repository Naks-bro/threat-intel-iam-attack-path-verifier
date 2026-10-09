"""Replay a synthetic redacted handoff with no network and no live identifiers."""

import ast
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from tests.unit.test_inventory_handoff import (
    DIGEST,
    USER,
    _credential_handoff,
    _handoff,
    _paired_credential_handoff,
)

from fyp_iam.api.app import create_app
from fyp_iam.contracts.inventory import CollectionHandoff, InventorySnapshot
from fyp_iam.engine2 import paired_observation, recorded_pair
from fyp_iam.engine2.recorded_pair import observe_recorded_user_pair
from fyp_iam.engine2.redacted_seal import (
    RedactedSealRejected,
    assert_redacted_text,
    read_redacted_seal,
    write_redacted_seal,
)

_TARGET = "p_" + "9" * 32
_ACCOUNT = re.compile(r"\b\d{12}\b")


def _two_user_handoff(*, complete_groups: bool) -> CollectionHandoff:
    payload = _credential_handoff()
    payload["manifest"]["data_kind"] = "real_account_observed"
    if complete_groups:
        counts = {USER: 1, _TARGET: 0}
        payload["inventory"]["group_traversals"] = [
            {
                "user_key": key,
                "state": "complete",
                "membership_count": counts[key],
                "evidence_digest": DIGEST,
            }
            for key in (USER, _TARGET)
        ]
        payload["manifest"]["tasks"].extend(
            {
                "operation": "iam:ListGroupsForUser",
                "subject_principal_key": key,
                "attempt": 1,
                "outcome": "succeeded",
                "page_count": 1,
                "item_count": counts[key],
                "pagination_complete": True,
                "response_digest": DIGEST,
            }
            for key in (USER, _TARGET)
        )
    payload["manifest"]["snapshot_digest"] = InventorySnapshot.model_validate(
        payload["inventory"]
    ).content_digest()
    return CollectionHandoff.model_validate(payload)


def test_two_observed_users_are_paired_without_exposed_or_control_labels() -> None:
    handoff = _two_user_handoff(complete_groups=True)
    report = observe_recorded_user_pair(handoff)
    by_key = {
        report.first.principal_key: report.first,
        report.second.principal_key: report.second,
    }
    assert set(by_key) == {USER, _TARGET}
    assert by_key[USER].label == "candidate_from_policy_text"
    assert by_key[_TARGET].label == "no_matching_statement"
    assert report.authorization_evaluated is False
    assert report.data_kind == "real_account_observed"
    assert report.snapshot_digest == handoff.manifest.snapshot_digest
    dumped = report.model_dump_json()
    assert "supported_by_fixture" not in dumped
    assert "exposed" not in report.first.display_alias
    assert "exposed" not in report.second.display_alias
    assert "control" not in report.first.display_alias
    assert "control" not in report.second.display_alias
    assert "secure" not in dumped
    assert "arn:aws" not in dumped


def test_missing_group_traversal_on_two_users_stays_unknown() -> None:
    report = observe_recorded_user_pair(_two_user_handoff(complete_groups=False))
    assert report.first.label == "unknown"
    assert report.second.label == "unknown"
    assert report.authorization_evaluated is False
    assert "group_traversal_incomplete" in report.first.unknowns
    assert "group_traversal_incomplete" in report.second.unknowns


def test_other_user_counts_are_refused() -> None:
    one = _handoff()
    one["manifest"]["data_kind"] = "real_account_observed"
    with pytest.raises(ValueError, match="^starting_user_count_unsupported$"):
        observe_recorded_user_pair(CollectionHandoff.model_validate(one))
    three = _paired_credential_handoff().model_dump(mode="json")
    three["manifest"]["data_kind"] = "real_account_observed"
    with pytest.raises(ValueError, match="^starting_user_count_unsupported$"):
        observe_recorded_user_pair(CollectionHandoff.model_validate(three))


def test_pair_modules_do_not_call_fixture_analysis_or_branch_walk() -> None:
    for module in (paired_observation, recorded_pair):
        source = Path(module.__file__).read_text(encoding="utf-8")
        imported: list[str] = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.append(node.module)
        assert imported
        assert all("engine3" not in name and "branch_walk" not in name for name in imported)


def test_redacted_seal_roundtrip_rejects_account_identifiers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / ".aws-safety" / "redacted-handoff.json"
    monkeypatch.setattr("fyp_iam.engine2.redacted_seal.seal_path", lambda: path)
    handoff = _two_user_handoff(complete_groups=True)
    write_redacted_seal(handoff)
    stored = path.read_text(encoding="utf-8")
    assert "arn:aws" not in stored
    assert _ACCOUNT.search(stored) is None
    assert read_redacted_seal().manifest.snapshot_digest == handoff.manifest.snapshot_digest
    with pytest.raises(RedactedSealRejected, match="^redacted_seal_rejected$"):
        assert_redacted_text("arn:aws:iam::123456789012:user/Example")
    with pytest.raises(RedactedSealRejected, match="^redacted_seal_rejected$"):
        assert_redacted_text("account 123456789012")


def test_loopback_route_serves_the_pair_and_refuses_other_hosts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "redacted-handoff.json"
    monkeypatch.setattr("fyp_iam.api.sealed_observation_api.seal_path", lambda: path)
    app = create_app(database_url=None)
    monkeypatch.setattr("fyp_iam.engine2.redacted_seal.seal_path", lambda: path)
    poison = "arn:aws:iam::123456789012:user/Example"
    with TestClient(app, base_url="http://127.0.0.1:8765", client=("192.0.2.1", 1234)) as client:
        refused = client.get("/v1/observations/real-account-pair", params={"q": poison})
    assert refused.status_code == 403
    assert refused.json() == {"detail": "sealed_observation_boundary_required"}
    assert "arn:aws" not in refused.text
    assert "123456789012" not in refused.text

    with TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 1234)) as client:
        absent = client.get("/v1/observations/real-account-pair")
        assert absent.status_code == 404
        assert absent.json() == {"detail": "sealed_observation_absent"}
        path.write_text(poison, encoding="utf-8")
        rejected = client.get("/v1/observations/real-account-pair")
        assert rejected.status_code == 422
        assert rejected.json() == {"detail": "sealed_observation_rejected"}
        assert poison not in rejected.text
        write_redacted_seal(_two_user_handoff(complete_groups=True))
        loaded = client.get(
            "/v1/observations/real-account-pair",
            headers={"Origin": "http://127.0.0.1:5173"},
        )
    assert loaded.status_code == 200
    body = loaded.json()
    assert body["authorization_evaluated"] is False
    assert body["data_kind"] == "real_account_observed"
    assert len(body["identities"]) == 2
    assert {item["outcome"] for item in body["identities"]} == {
        "candidate_from_policy_text",
        "no_matching_statement",
    }
    assert "supported_by_fixture" not in loaded.text
    assert "secure" not in loaded.text
    assert "exposed" not in loaded.text
    assert "arn:aws" not in loaded.text
    assert _ACCOUNT.search(loaded.text) is None
