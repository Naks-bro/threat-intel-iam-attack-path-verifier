import re
from pathlib import Path

from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app
from fyp_iam.engine4.manifest import build_local_fixture_manifest, dataset_sha256


def test_local_fixture_manifest_is_stable(fixture_dir: Path) -> None:
    first = build_local_fixture_manifest(fixture_dir)
    second = build_local_fixture_manifest(fixture_dir)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.dataset_sha256 == dataset_sha256(fixture_dir)
    assert first.research_question == "RQ3"
    assert first.model == "not_used"
    assert first.prompt_sha256 == "not_used"
    assert first.random_seed == "not_used"
    assert first.simulator_status == "not_run"
    assert first.sandbox_status == "not_mapped"
    assert first.supported_by_fixture == 3
    assert first.denied_by_fixture == 1
    assert first.inconclusive == 1
    assert first.no_finding == 1
    assert first.metric_version == "local-fixture-counts-v2"
    scored = {item.case_id: item for item in first.edge_agreements}
    assert scored["positive"].precision == 1
    assert scored["positive"].recall == 1
    assert scored["explicit_deny"].precision == 1
    assert scored["hard_negative"].comparable is False
    assert scored["hard_negative"].precision is None
    assert {item.case_id: item.status for item in first.verdicts}["hard_negative"] == "none"
    assert {item.case_id: item.status for item in first.verdicts}["positive"] == (
        "supported_by_fixture"
    )


def test_manifest_export_has_no_account_identifier(fixture_dir: Path) -> None:
    payload = build_local_fixture_manifest(fixture_dir).model_dump_json()
    assert "arn:aws:" not in payload
    assert "AKIA" not in payload
    assert re.search(r"\b\d{12}\b", payload) is None


def test_experiment_endpoint_matches_the_page(fixture_dir: Path) -> None:
    client = TestClient(create_app(fixture_dir))
    response = client.get("/v1/experiments/local-fixtures")
    assert response.status_code == 200
    body = response.json()
    page = client.get("/reviews/experiment")
    assert page.status_code == 200
    assert body["result_sha256"] in page.text
    assert "No LLM was used." in page.text
    assert "not scored" in page.text
    assert "verified_in_mapped_sandbox" not in page.text
    assert "Experiment manifest" in client.get("/reviews").text
