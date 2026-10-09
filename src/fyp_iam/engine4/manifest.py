"""Reproducible record of the local fixture run.

This is an Engine 4 export for RQ3. It does not call AWS or a model.
"""

import sys
from datetime import datetime
from pathlib import Path

from pydantic import Field

from fyp_iam import __version__
from fyp_iam.contracts.models import ContractModel, DiscoveryLimits, IdStr, ensure_utc
from fyp_iam.core.ids import sha256_key, stable_id
from fyp_iam.engine2.agreement import EdgeAgreement, graph_edge_agreement
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.fixtures.loader import list_fixture_ids, load_fixture

_DEVIATIONS = (
    "No LLM was used.",
    "IAM Policy Simulator was not run.",
    "No sandbox scenario was mapped.",
    "Live AWS collection was not performed.",
    "Timestamps are the fixture evaluation times, not a wall clock.",
)


class RuleVersionRef(ContractModel):
    rule_id: IdStr
    rule_version: int = Field(ge=1)


class FixtureVerdict(ContractModel):
    case_id: str = Field(pattern=r"^[a-z0-9_]+$")
    snapshot_id: IdStr
    rule_id: IdStr
    rule_version: int = Field(ge=1)
    status: str = Field(pattern=r"^(supported_by_fixture|denied_by_fixture|inconclusive|none)$")
    finding_id: str = Field(pattern=r"^(none|[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127})$")


class LocalFixtureManifest(ContractModel):
    schema_version: str = Field(pattern=r"^0\.1$")
    experiment_id: IdStr
    research_question: str = Field(pattern=r"^RQ3$")
    code_revision: str = Field(pattern=r"^0\.1\.0$")
    dataset_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    schema_version_set: list[str] = Field(min_length=1, max_length=5)
    rule_versions: list[RuleVersionRef] = Field(min_length=1, max_length=20)
    snapshot_ids: list[IdStr] = Field(min_length=1, max_length=20)
    python_version: str = Field(min_length=1, max_length=32)
    model: str = Field(pattern=r"^not_used$")
    prompt_sha256: str = Field(pattern=r"^not_used$")
    limits: DiscoveryLimits
    random_seed: str = Field(pattern=r"^not_used$")
    started_at: datetime
    finished_at: datetime
    result_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    metric_version: str = Field(pattern=r"^local-fixture-counts-v2$")
    simulator_status: str = Field(pattern=r"^not_run$")
    sandbox_status: str = Field(pattern=r"^not_mapped$")
    supported_by_fixture: int = Field(ge=0)
    denied_by_fixture: int = Field(ge=0)
    inconclusive: int = Field(ge=0)
    no_finding: int = Field(ge=0)
    verdicts: list[FixtureVerdict] = Field(min_length=1, max_length=20)
    edge_agreements: list[EdgeAgreement] = Field(min_length=1, max_length=20)
    deviations: list[str] = Field(min_length=1, max_length=10)


def dataset_sha256(directory: Path) -> str:
    parts: list[str] = []
    root = directory.resolve()
    for case_id in list_fixture_ids(root):
        parts.append(case_id)
        parts.append((root / f"{case_id}.json").read_text(encoding="utf-8"))
    if not parts:
        raise ValueError("fixture directory has no cases")
    return sha256_key(*parts)


def build_local_fixture_manifest(directory: Path) -> LocalFixtureManifest:
    root = directory.resolve()
    verdicts: list[FixtureVerdict] = []
    times: list[datetime] = []
    for case_id in list_fixture_ids(root):
        case = load_fixture(root, case_id)
        report = analyze(
            case.rules,
            case.snapshot,
            condition_resolutions=case.condition_resolutions,
            evaluated_at=case.evaluated_at,
        )
        for item in report.verifications:
            if item.policy_simulation.status != "not_run" or item.sandbox.status != "not_mapped":
                raise RuntimeError("local manifest saw a non-fixture verification status")
        status = report.verifications[0].status.value if report.verifications else "none"
        finding_id = report.findings[0].finding_id if report.findings else "none"
        rule = case.rules[0]
        verdicts.append(
            FixtureVerdict(
                case_id=case.case_id,
                snapshot_id=case.snapshot.snapshot_id,
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                status=status,
                finding_id=finding_id,
            )
        )
        times.append(ensure_utc(case.evaluated_at))
    if not verdicts:
        raise ValueError("fixture directory has no cases")
    digest = dataset_sha256(root)
    edge_agreements = graph_edge_agreement()
    result = sha256_key(
        *(
            "|".join(
                (
                    verdict.case_id,
                    verdict.snapshot_id,
                    verdict.rule_id,
                    str(verdict.rule_version),
                    verdict.status,
                    verdict.finding_id,
                )
            )
            for verdict in verdicts
        ),
        *(
            "|".join(
                (
                    score.case_id,
                    str(score.comparable),
                    "none" if score.precision is None else str(score.precision),
                    "none" if score.recall is None else str(score.recall),
                )
            )
            for score in edge_agreements
        ),
    )
    counts = {name: 0 for name in ("supported_by_fixture", "denied_by_fixture", "inconclusive")}
    no_finding = 0
    for verdict in verdicts:
        if verdict.status == "none":
            no_finding += 1
        else:
            counts[verdict.status] += 1
    return LocalFixtureManifest(
        schema_version="0.1",
        experiment_id=stable_id("experiment", "RQ3", digest, result),
        research_question="RQ3",
        code_revision=__version__,
        dataset_sha256=digest,
        schema_version_set=["0.1"],
        rule_versions=[
            RuleVersionRef(rule_id=verdict.rule_id, rule_version=verdict.rule_version)
            for verdict in verdicts
        ],
        snapshot_ids=[verdict.snapshot_id for verdict in verdicts],
        python_version=sys.version.split()[0],
        model="not_used",
        prompt_sha256="not_used",
        limits=DiscoveryLimits(),
        random_seed="not_used",
        started_at=min(times),
        finished_at=max(times),
        result_sha256=result,
        metric_version="local-fixture-counts-v2",
        edge_agreements=edge_agreements,
        simulator_status="not_run",
        sandbox_status="not_mapped",
        supported_by_fixture=counts["supported_by_fixture"],
        denied_by_fixture=counts["denied_by_fixture"],
        inconclusive=counts["inconclusive"],
        no_finding=no_finding,
        verdicts=verdicts,
        deviations=list(_DEVIATIONS),
    )
