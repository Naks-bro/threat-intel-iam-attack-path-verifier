"""Version-bound quality artifacts must preserve uncertainty and contradictory results."""

import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fyp_iam.api.app import create_app
from fyp_iam.api.schemas import FoundryRuleResponse
from fyp_iam.engine1.foundry.pipeline import build_foundry
from fyp_iam.engine1.foundry.quality import QualityReport, QualityStage, build_quality_report


def _inputs() -> tuple[dict[str, object], list[dict[str, object]]]:
    result = build_foundry(persisted=False, storage="not_written")
    candidate = result["candidate"]
    validations = result["validations"]
    assert isinstance(candidate, dict)
    assert isinstance(validations, list)
    return candidate, validations


def test_report_is_bound_reproducible_and_separates_unavailable_tools() -> None:
    candidate, rows = _inputs()
    first = build_quality_report(candidate, rows)
    second = build_quality_report(candidate, list(reversed(rows)))
    assert first == second
    assert first.rule_version_id == candidate["version_id"]
    assert first.rule_semantic_hash == candidate["semantic_hash"]
    assert first.evidence_snapshot_hash == candidate["evidence_snapshot_hash"]
    assert first.status == "pass"
    assert first.required_passed == first.required_total == 10
    assert first.optional_unavailable == 4
    assert all(stage.duration_ms is None for stage in first.stages)
    assert (
        len(next(stage for stage in first.stages if stage.stage_id == "scenario_corpus").scenarios)
        == 6
    )


@pytest.mark.parametrize(
    "status,expected",
    [("fail", "fail"), ("error", "fail"), ("unavailable", "incomplete"), ("skipped", "incomplete")],
)
def test_required_nonpass_is_not_quality_success(status: str, expected: str) -> None:
    candidate, rows = _inputs()
    rows[0]["result"] = status
    assert build_quality_report(candidate, rows).status == expected


def test_missing_required_check_is_explicitly_skipped() -> None:
    candidate, rows = _inputs()
    rows = [row for row in rows if row["validator_name"] != "ontology"]
    report = build_quality_report(candidate, rows)
    stage = next(stage for stage in report.stages if stage.stage_id == "ontology")
    assert stage.status == "skipped"
    assert stage.required is True
    assert stage.findings[0].code == "missing_required_check"
    assert report.status == "incomplete"


def test_optional_disagreement_is_retained_without_becoming_required() -> None:
    candidate, rows = _inputs()
    tool = next(row for row in rows if row["validator_name"] == "parliament")
    tool.update(result="fail", findings=["Independent validator disagrees"])
    report = build_quality_report(candidate, rows)
    assert report.required_passed == 10
    assert report.status == "needs_review"
    stage = next(stage for stage in report.stages if stage.stage_id == "parliament")
    assert not stage.required
    assert stage.findings[0].message == "Independent validator disagrees"


def test_pass_with_failed_scenario_is_rejected_as_contradictory() -> None:
    candidate, rows = _inputs()
    corpus = next(row for row in rows if row["validator_name"] == "scenario_corpus")
    corpus["findings"][0]["result"] = "fail"  # type: ignore[index]
    report = build_quality_report(candidate, rows)
    stage = next(stage for stage in report.stages if stage.stage_id == "scenario_corpus")
    assert stage.status == "fail"
    assert stage.findings[-1].code == "contradictory_scenario_result"
    assert report.status == "fail"


def test_duration_is_observation_not_semantic_identity() -> None:
    candidate, rows = _inputs()
    first = build_quality_report(candidate, rows)
    rows[0]["duration_ms"] = 23
    observed = build_quality_report(candidate, rows)
    assert observed.report_hash == first.report_hash
    assert observed.report_id == first.report_id
    assert any(stage.duration_ms == 23 for stage in observed.stages)


def test_evidence_change_invalidates_report_identity() -> None:
    candidate, rows = _inputs()
    first = build_quality_report(candidate, rows)
    candidate["evidence_snapshot_hash"] = "sha256:" + "1" * 64
    assert build_quality_report(candidate, rows).report_hash != first.report_hash


def test_report_contract_rejects_forged_status_hash_and_missing_binding() -> None:
    candidate, rows = _inputs()
    body = build_quality_report(candidate, rows).model_dump(mode="json")
    for change in (
        {"status": "fail"},
        {"report_hash": "sha256:" + "0" * 64},
        {"rule_version_id": ""},
        {"required_passed": 100},
    ):
        malformed = deepcopy(body)
        malformed.update(change)
        with pytest.raises(ValidationError):
            QualityReport.model_validate(malformed)


def test_duplicate_validation_rows_do_not_overwrite_disagreement() -> None:
    candidate, rows = _inputs()
    duplicate = dict(rows[0])
    duplicate["result"] = "fail"
    with pytest.raises(ValueError, match="duplicate"):
        build_quality_report(candidate, [*rows, duplicate])


def test_preview_api_exposes_the_report_with_exact_candidate_binding() -> None:
    with TestClient(create_app(database_url=None, foundry_preview=True)) as client:
        overview = client.get("/v1/foundry/overview").json()
        version = overview["candidates"][0]["version_id"]
        response = client.get(f"/v1/foundry/rules/{version}")
        assert response.status_code == 200
        body = response.json()
        report = QualityReport.model_validate(body["quality_report"])
        assert report.rule_version_id == version
        assert report.rule_semantic_hash == body["semantic_hash"]
        assert body["publication"] is None


def test_rule_response_rejects_a_report_bound_to_another_version() -> None:
    with TestClient(create_app(database_url=None, foundry_preview=True)) as client:
        version = client.get("/v1/foundry/overview").json()["candidates"][0]["version_id"]
        body = client.get(f"/v1/foundry/rules/{version}").json()
    body["version_id"] = "version_other"
    with pytest.raises(ValidationError, match="binding"):
        FoundryRuleResponse.model_validate(body)


@pytest.mark.parametrize("extra", [[], ["--fixture"]])
def test_checked_in_consumer_types_match_the_provider_schema(extra: list[str]) -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "quality_contract_types.py"), "--check", *extra],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("duration", [-1, True, "12"])
def test_unmeasured_timing_cannot_be_replaced_by_invalid_duration(duration: object) -> None:
    candidate, rows = _inputs()
    rows[0]["duration_ms"] = duration
    with pytest.raises(ValidationError):
        build_quality_report(candidate, rows)


def test_unknown_status_is_rejected_instead_of_treated_as_success() -> None:
    candidate, rows = _inputs()
    rows[0]["result"] = "approved"
    with pytest.raises(ValidationError):
        build_quality_report(candidate, rows)


def test_empty_passing_corpus_becomes_failure() -> None:
    candidate, rows = _inputs()
    corpus = next(row for row in rows if row["validator_name"] == "scenario_corpus")
    corpus["findings"] = []
    assert build_quality_report(candidate, rows).status == "fail"


def test_stage_contract_rejects_a_passing_corpus_without_cases() -> None:
    with pytest.raises(ValidationError, match="corpus"):
        QualityStage.model_validate(
            {
                "stage_id": "scenario_corpus",
                "validator_version": "test",
                "status": "pass",
                "required": True,
                "scenarios": [],
            }
        )


def test_rule_response_without_a_report_remains_compatible_but_not_passing() -> None:
    with TestClient(create_app(database_url=None, foundry_preview=True)) as client:
        version = client.get("/v1/foundry/overview").json()["candidates"][0]["version_id"]
        body = client.get(f"/v1/foundry/rules/{version}").json()
    body.pop("quality_report")
    assert FoundryRuleResponse.model_validate(body).quality_report is None
