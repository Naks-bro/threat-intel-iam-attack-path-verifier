from pathlib import Path

from fastapi.testclient import TestClient

from fyp_iam.api.app import create_app
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.engine4.review_page import escape_review_text, render_review_detail
from fyp_iam.fixtures.cases import positive_case


def _client(fixture_dir: Path) -> TestClient:
    return TestClient(create_app(fixture_dir))


def test_review_text_is_escaped() -> None:
    assert (
        escape_review_text("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    )
    case = positive_case()
    snapshot = case.snapshot.model_copy(
        update={
            "collection": case.snapshot.collection.model_copy(
                update={"warnings": ["<script>alert(1)</script>"]}
            )
        }
    )
    report = analyze(case.rules, snapshot, evaluated_at=case.evaluated_at)
    page = render_review_detail(case.case_id, case.rules, snapshot, report)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_review_index_lists_fixture_statuses(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/reviews")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    page = response.text
    assert "supported_by_fixture" in page
    assert "denied_by_fixture" in page
    assert "inconclusive" in page
    assert "data-status='none'" in page
    assert "The baseline score is not verification." in page
    assert "AWS is not connected." in page


def test_positive_review_shows_gaps_and_coverage(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/reviews/fixtures/positive")
    assert response.status_code == 200
    page = response.text
    assert 'id="coverage"' in page
    assert 'Simulator: <span class="badge">not_run</span>' in page
    assert 'Sandbox: <span class="badge">not_mapped</span>' in page
    assert "supported_by_fixture" in page
    assert "policies=policy_alice_dev" in page
    assert "Human review required: true" in page
    assert "verified_in_mapped_sandbox" not in page
    assert "supported_by_policy_simulation" not in page


def test_missing_context_review_names_the_gap(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/reviews/fixtures/missing_context")
    assert response.status_code == 200
    page = response.text
    assert "inconclusive" in page
    assert "edge_dev_admin:aws:MultiFactorAuthPresent" in page
    assert "Collection complete: false" in page


def test_hard_negative_review_has_no_finding(fixture_dir: Path) -> None:
    response = _client(fixture_dir).get("/reviews/fixtures/hard_negative")
    assert response.status_code == 200
    assert "No candidate path matched." in response.text


def test_review_rejects_fixture_escape(fixture_dir: Path) -> None:
    client = _client(fixture_dir)
    assert client.get("/reviews/fixtures/NotAllowed").status_code == 400
    assert client.get("/reviews/fixtures/not_a_case").status_code == 404


def test_rule_review_shows_evidence_and_stays_pending(fixture_dir: Path) -> None:
    client = _client(fixture_dir)
    index = client.get("/reviews")
    assert "Rule review" in index.text
    page = client.get("/reviews/rules/attack-t1548-assume-chain")
    assert page.status_code == 200
    text = page.text
    assert "Opening this page does not approve the rule." in text
    assert "No model wrote this rule." in text
    assert "Status proposed." in text
    assert "Approval pending." in text
    assert "The reference was not fetched." in text
    assert "sha256:" in text
    script = text.split("<script>", maxsplit=1)[1]
    assert "Local curated pin" not in script
    unmapped = client.get("/reviews/rules/attack-t9999-unmapped")
    assert unmapped.status_code == 200
    assert "This record cannot be approved." in unmapped.text
    assert "rule-decision" not in unmapped.text
    assert client.get("/reviews/rules/not-a-pin").status_code == 404


def test_cloud_dataset_page_lists_rows_as_not_rules(fixture_dir: Path) -> None:
    client = _client(fixture_dir)
    index = client.get("/reviews")
    assert "Cloud technique dataset" in index.text
    page = client.get("/reviews/datasets/cloud-techniques")
    assert page.status_code == 200
    text = page.text
    assert "T1020.001" in text
    assert "Traffic Duplication" in text
    assert "no_rule_yet" in text
    assert "50 rows." in text
    assert "Mapped: 0." in text
    assert "is not a rule" in text
    assert text.count("data-rule-status='no_rule_yet'") == 50
    script = text.split("<script>", maxsplit=1)[1]
    assert "Traffic Duplication" not in script


def test_opportunity_page_shows_strength_without_approving(fixture_dir: Path) -> None:
    client = _client(fixture_dir)
    index = client.get("/reviews")
    assert "Source catalog" in index.text
    page = client.get("/reviews/datasets/opportunities")
    assert page.status_code == 200
    text = page.text
    assert "T1078" in text
    assert "Valid Accounts" in text
    assert "not a verification result" in text
    assert "model checker has not run" in text
    assert "AWS Threat Technique Catalog is not ingested." in text
    assert "matched 0 rows" in text
    assert "Combined: 12." in text
    assert text.count("data-attachment='combined'") == 12
    assert text.count("data-attachment='individual'") == 54
    assert text.count("data-kind='technique'") == 50
    assert text.count("data-kind='weakness'") == 10
    assert text.count("data-kind='vulnerability'") == 5
    assert text.count("data-kind='catalog'") == 1
    assert "no_rule_yet" in text
    script = text.split("<script>", maxsplit=1)[1]
    assert "Valid Accounts" not in script
