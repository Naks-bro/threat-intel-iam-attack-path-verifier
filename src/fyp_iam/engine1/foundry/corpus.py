"""Portable, pinned evaluation cases for a single rule family."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fyp_iam.engine1.foundry.pins import load_pins

_PATH = Path(__file__).resolve().parent / "corpus" / "additional-credentials-0.2.json"


class ScenarioCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,79}$")
    case_class: Literal["positive", "near_negative", "missing_context", "adversarial"]
    expected_verdict: Literal["match", "no_match", "inconclusive"]
    allow: list[str]
    deny: list[str]
    target_context: Literal["confirmed", "absent", "unknown"]
    evidence_refs: list[str] = Field(min_length=1)
    rationale: str = Field(min_length=1)


class ScenarioCorpus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"]
    dataset_version: str = Field(pattern=r"^iam-corpus-\d+\.\d+$")
    family: Literal["additional_cloud_credentials"]
    source_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    labeling_method: Literal["project_curated"]
    cases: list[ScenarioCase] = Field(min_length=1)

    @model_validator(mode="after")
    def distinct_cases(self) -> ScenarioCorpus:
        ids = [case.scenario_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("scenario ids must be unique")
        return self


def load_corpus() -> ScenarioCorpus:
    corpus = ScenarioCorpus.model_validate(json.loads(_PATH.read_text(encoding="utf-8")))
    if corpus.source_hash != "sha256:" + load_pins().bundle_hash:
        raise RuntimeError("scenario corpus source hash does not match pinned evidence")
    return corpus


def scenario_verdict(action: str, case: ScenarioCase) -> str:
    """Conservative local verdict; unsupported wildcard or context is inconclusive."""

    if case.target_context == "unknown" or any("*" in item or "?" in item for item in case.allow):
        return "inconclusive"
    if case.target_context == "absent":
        return "no_match"
    return "match" if action in case.allow and action not in case.deny else "no_match"
