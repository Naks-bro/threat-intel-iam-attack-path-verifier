"""Portable corpus and conservative missing-context behavior."""

import pytest
from pydantic import ValidationError

from fyp_iam.engine1.foundry.corpus import ScenarioCorpus, load_corpus, scenario_verdict
from fyp_iam.engine1.foundry.pipeline import build_foundry


def test_pinned_corpus_covers_all_required_case_classes() -> None:
    corpus = load_corpus()
    assert len(corpus.cases) == 6
    assert {case.case_class for case in corpus.cases} == {
        "positive",
        "near_negative",
        "missing_context",
        "adversarial",
    }
    outcomes = {
        case.scenario_id: scenario_verdict("iam:CreateAccessKey", case) for case in corpus.cases
    }
    assert all(outcomes[case.scenario_id] == case.expected_verdict for case in corpus.cases)


def test_duplicate_cases_and_missing_evidence_are_rejected() -> None:
    document = load_corpus().model_dump()
    document["cases"].append(document["cases"][0])
    with pytest.raises(ValidationError, match="scenario ids must be unique"):
        ScenarioCorpus.model_validate(document)
    document["cases"].pop()
    document["cases"][0]["evidence_refs"] = []
    with pytest.raises(ValidationError, match="evidence_refs"):
        ScenarioCorpus.model_validate(document)


def test_foundry_reports_counts_from_cases() -> None:
    overview = build_foundry(persisted=False, storage="not_written")
    evaluation = overview["evaluation"]
    assert isinstance(evaluation, dict)
    assert evaluation["confusion_matrix"] == {"tp": 1, "fp": 0, "fn": 0, "tn": 3}
    assert evaluation["labeled_missing_context"] == 1
    assert evaluation["labeled_adversarial"] == 1
    validations = overview["validations"]
    assert isinstance(validations, list)
    corpus = next(item for item in validations if item["validator_name"] == "scenario_corpus")
    assert len(corpus["findings"]) == 6
