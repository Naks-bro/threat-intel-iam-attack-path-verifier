"""Version-bound deterministic quality artifacts; no approval or publication authority.

Timing is an observation and is excluded from semantic identity. Missing timings
remain null. Evidence references scope the inputs, not independent entailment proof.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from fyp_iam.contracts.models import ContractModel

QUALITY_VERSION: Literal["foundry-quality-0.1"] = "foundry-quality-0.1"
REQUIRED_CHECKS = frozenset(
    {
        "schema",
        "ontology",
        "aws_action_resource",
        "condition_keys",
        "provenance",
        "evidence_sufficiency",
        "contradiction",
        "scenario_corpus",
        "determinism",
        "engine3_not_approved",
    }
)
OPTIONAL_CHECKS = frozenset({"access_analyzer", "parliament", "cloudsplaining", "pmapper"})
_HASH = r"^sha256:[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$"

StageStatus = Literal["pass", "fail", "unavailable", "error", "skipped"]
ReportStatus = Literal["pass", "fail", "needs_review", "incomplete"]


class QualityFinding(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    code: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    message: str = Field(min_length=1, max_length=2000)
    severity: Literal["info", "warning", "error"]
    evidence_refs: tuple[str, ...] = ()


class QualityScenario(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    scenario_id: str = Field(pattern=_ID)
    case_class: Literal["positive", "near_negative", "missing_context", "adversarial"] | None = None
    expect: Literal["match", "no_match", "inconclusive"]
    actual: Literal["match", "no_match", "inconclusive"]
    result: Literal["pass", "fail"]


class QualityStage(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    stage_id: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    validator_version: str = Field(min_length=1, max_length=128)
    corpus_version: str | None = Field(default=None, min_length=1, max_length=128)
    status: StageStatus
    required: bool = Field(strict=True)
    duration_ms: int | None = Field(default=None, ge=0, strict=True)
    findings: tuple[QualityFinding, ...] = ()
    scenarios: tuple[QualityScenario, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def consistent_findings(self) -> QualityStage:
        if self.stage_id == "scenario_corpus" and self.status == "pass" and not self.scenarios:
            raise ValueError("passing corpus must contain scenario outcomes")
        if self.status == "pass" and (
            any(item.severity == "error" for item in self.findings)
            or any(item.result != "pass" or item.expect != item.actual for item in self.scenarios)
        ):
            raise ValueError("passing stage contains contradictory findings")
        if self.stage_id in REQUIRED_CHECKS and not self.required:
            raise ValueError("required check cannot become optional")
        if len({item.scenario_id for item in self.scenarios}) != len(self.scenarios):
            raise ValueError("duplicate scenario")
        return self


def _summary(stages: tuple[QualityStage, ...]) -> tuple[ReportStatus, int, int, int]:
    required = [stage for stage in stages if stage.required]
    passed = sum(stage.status == "pass" for stage in required)
    unavailable = sum(not stage.required and stage.status == "unavailable" for stage in stages)
    if any(stage.status in {"fail", "error"} for stage in required):
        status: ReportStatus = "fail"
    elif not required or passed != len(required):
        status = "incomplete"
    elif any(stage.status in {"fail", "error"} for stage in stages):
        status = "needs_review"
    else:
        status = "pass"
    return status, passed, len(required), unavailable


def _digest(body: dict[str, object]) -> str:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class QualityReport(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["0.1"] = "0.1"
    report_version: Literal["foundry-quality-0.1"] = QUALITY_VERSION
    report_id: str = Field(pattern=r"^quality_[0-9a-f]{32}$")
    report_hash: str = Field(pattern=_HASH)
    rule_version_id: str = Field(pattern=_ID)
    rule_semantic_hash: str = Field(pattern=_HASH)
    evidence_snapshot_hash: str = Field(pattern=_HASH)
    status: ReportStatus
    required_passed: int = Field(ge=0, strict=True)
    required_total: int = Field(ge=0, strict=True)
    optional_unavailable: int = Field(ge=0, strict=True)
    stages: tuple[QualityStage, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def verify_summary_and_identity(self) -> QualityReport:
        ids = [stage.stage_id for stage in self.stages]
        if ids != sorted(set(ids)) or not REQUIRED_CHECKS.issubset(ids):
            raise ValueError("quality stages must be unique, ordered, and complete")
        if _summary(self.stages) != (
            self.status,
            self.required_passed,
            self.required_total,
            self.optional_unavailable,
        ):
            raise ValueError("quality summary contradicts stages")
        body = self.model_dump(mode="json", exclude={"report_id", "report_hash"})
        for stage in body["stages"]:
            stage.pop("duration_ms")
        digest = _digest(body)
        if self.report_hash != digest or self.report_id != "quality_" + digest[7:39]:
            raise ValueError("quality identity does not match semantic content")
        return self


def build_quality_report(
    candidate: dict[str, object], validations: list[dict[str, object]]
) -> QualityReport:
    """Aggregate one version's checks, retaining absence and tool disagreement."""
    evidence = candidate.get("evidence_ids", [])
    if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
        raise ValueError("candidate evidence must be a list of IDs")
    refs = tuple(sorted(set(evidence)))
    stages: dict[str, QualityStage] = {}
    for row in validations:
        name = row.get("validator_name")
        if not isinstance(name, str):
            raise ValueError("validator name missing")
        if name in stages:
            raise ValueError("duplicate validation stage")
        stages[name] = _stage(row, refs)
    for name in REQUIRED_CHECKS - stages.keys():
        stages[name] = QualityStage(
            stage_id=name,
            validator_version="not-recorded",
            status="skipped",
            required=True,
            findings=(
                QualityFinding(
                    code="missing_required_check",
                    message="No result was recorded for this required check.",
                    severity="warning",
                ),
            ),
        )
    ordered = tuple(stages[name] for name in sorted(stages))
    status, passed, total, unavailable = _summary(ordered)
    body = {
        "schema_version": "0.1",
        "report_version": QUALITY_VERSION,
        "rule_version_id": candidate["version_id"],
        "rule_semantic_hash": candidate["semantic_hash"],
        "evidence_snapshot_hash": candidate["evidence_snapshot_hash"],
        "status": status,
        "required_passed": passed,
        "required_total": total,
        "optional_unavailable": unavailable,
        "stages": [stage.model_dump(mode="json", exclude={"duration_ms"}) for stage in ordered],
    }
    digest = _digest(body)
    body.update(report_hash=digest, report_id="quality_" + digest[7:39])
    body["stages"] = [stage.model_dump(mode="json") for stage in ordered]
    return QualityReport.model_validate(body)


def _stage(row: dict[str, object], refs: tuple[str, ...]) -> QualityStage:
    name = row["validator_name"]
    status = row["result"]
    raw = row.get("findings", [])
    if not isinstance(raw, list):
        raise ValueError("validator findings must be a list")
    findings: list[QualityFinding] = []
    scenarios: list[QualityScenario] = []
    for item in raw:
        if isinstance(item, str):
            findings.append(
                QualityFinding(
                    code="validator_finding",
                    message=item,
                    severity="error" if status in {"fail", "error"} else "info",
                    evidence_refs=refs,
                )
            )
        elif isinstance(item, dict) and name == "scenario_corpus":
            scenarios.append(QualityScenario.model_validate(item))
        else:
            raise ValueError("unrecognized validator finding")
    if (
        name == "scenario_corpus"
        and status == "pass"
        and (
            not scenarios
            or any(item.result != "pass" or item.expect != item.actual for item in scenarios)
        )
    ):
        status = "fail"
        findings.append(
            QualityFinding(
                code="contradictory_scenario_result",
                message="A passing corpus result contains missing or failing scenario outcomes.",
                severity="error",
                evidence_refs=refs,
            )
        )
    optional = row.get("optional", name in OPTIONAL_CHECKS)
    if not isinstance(optional, bool):
        raise ValueError("validator optional flag must be boolean")
    return QualityStage.model_validate(
        {
            "stage_id": name,
            "validator_version": row["validator_version"],
            "corpus_version": row.get("corpus_version"),
            "status": status,
            "required": name in REQUIRED_CHECKS or not optional,
            "duration_ms": row.get("duration_ms"),
            "findings": findings,
            "scenarios": sorted(scenarios, key=lambda item: item.scenario_id),
            "evidence_refs": refs,
        }
    )
