"""FastAPI application for local fixture analysis."""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from fyp_iam import __version__
from fyp_iam.api.schemas import (
    AnalyzeRequest,
    ApprovalRequest,
    ApprovalResponse,
    IntakeRequest,
    IntakeResponse,
    SyntheticAnalyzeRequest,
    SyntheticAnalyzeResponse,
)
from fyp_iam.contracts.models import ApprovalDecision, ApprovedRule
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine1.catalog import SystemCatalog, load_system_catalog
from fyp_iam.engine1.dataset import CloudTechniqueDataset, load_cloud_technique_dataset
from fyp_iam.engine1.errors import IntakeError
from fyp_iam.engine1.intake import (
    decide_candidate,
    explain_proposal,
    load_artifact,
    normalize_technique,
    propose_rule,
    validate_candidate,
)
from fyp_iam.engine1.opportunities import OpportunityDataset, build_opportunities
from fyp_iam.engine2.normalize import normalize_with_coverage
from fyp_iam.engine3.pipeline import analyze
from fyp_iam.engine4.manifest import LocalFixtureManifest, build_local_fixture_manifest
from fyp_iam.engine4.review_page import (
    render_cloud_dataset,
    render_experiment_page,
    render_opportunities,
    render_review_detail,
    render_review_index,
    render_rule_review,
)
from fyp_iam.fixtures.loader import (
    FixtureLoadError,
    default_fixture_dir,
    list_fixture_ids,
    load_fixture,
)


def create_app(fixture_dir: Path | None = None) -> FastAPI:
    application = FastAPI(
        title="FYP IAM local verification",
        version=__version__,
        description=(
            "Local fixture pipeline. It does not connect to AWS, Neo4j, Redis, or an LLM."
        ),
    )
    directory = fixture_dir or default_fixture_dir()
    application.state.fixture_dir = directory

    @application.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "mode": "local_fixtures",
            "aws": "not_connected",
            "engine1": "local_intake",
            "engine2": "synthetic_normalizer",
            "neo4j": "not_connected",
            "version": __version__,
        }

    @application.post("/v1/analyses", response_model=AnalysisReport)
    def create_analysis(request: AnalyzeRequest) -> AnalysisReport:
        return analyze(
            request.rules,
            request.snapshot,
            limits=request.limits,
            condition_resolutions=request.condition_resolutions,
            evaluated_at=request.evaluated_at,
        )

    @application.get("/v1/fixtures")
    def fixtures() -> dict[str, list[str]]:
        return {"fixtures": list_fixture_ids(directory)}

    @application.post("/v1/analyses/fixtures/{case_id}", response_model=AnalysisReport)
    def analyze_fixture(case_id: str) -> AnalysisReport:
        try:
            case = load_fixture(directory, case_id)
        except FixtureLoadError as exc:
            status_code = 400 if "not allowed" in str(exc) else 404
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        return analyze(
            case.rules,
            case.snapshot,
            condition_resolutions=case.condition_resolutions,
            evaluated_at=case.evaluated_at,
        )

    @application.post("/v1/rules/intake", response_model=IntakeResponse)
    def intake_rule(request: IntakeRequest) -> IntakeResponse:
        try:
            artifact, digest = load_artifact(request.artifact_id)
            record = normalize_technique(artifact, digest)
            candidate = propose_rule(record)
        except IntakeError as exc:
            status_code = 404 if exc.code == "unknown_artifact" else 400
            raise HTTPException(status_code=status_code, detail=exc.code) from exc
        return IntakeResponse(schema_version="0.1", record=record, candidate=candidate)

    @application.get("/v1/datasets/cloud-techniques", response_model=CloudTechniqueDataset)
    def cloud_techniques() -> CloudTechniqueDataset:
        try:
            return load_cloud_technique_dataset()
        except IntakeError as exc:
            raise HTTPException(status_code=400, detail=exc.code) from exc

    @application.post("/v1/rules/approval", response_model=ApprovalResponse)
    def approve_rule(request: ApprovalRequest) -> ApprovalResponse:
        try:
            event, exported = decide_candidate(
                request.artifact_id,
                decision=ApprovalDecision(request.decision),
                reviewer_id=request.reviewer_id,
                decided_at=request.decided_at,
                comment=request.comment,
            )
        except IntakeError as exc:
            status_code = 404 if exc.code == "unknown_artifact" else 400
            raise HTTPException(status_code=status_code, detail=exc.code) from exc
        return ApprovalResponse(schema_version="0.1", event=event, exported_rule=exported)

    @application.get("/reviews/rules/{artifact_id}", response_class=HTMLResponse)
    def review_rule(artifact_id: str) -> HTMLResponse:
        try:
            artifact, digest = load_artifact(artifact_id)
        except IntakeError as exc:
            status_code = 404 if exc.code == "unknown_artifact" else 400
            raise HTTPException(status_code=status_code, detail=exc.code) from exc
        record = normalize_technique(artifact, digest)
        candidate: ApprovedRule | None = None
        explanation = ""
        try:
            candidate = propose_rule(record)
            validate_candidate(candidate, record)
            explanation = explain_proposal(record, candidate)
        except IntakeError as exc:
            if exc.code != "unsupported_technique":
                raise HTTPException(status_code=400, detail=exc.code) from exc
        return HTMLResponse(render_rule_review(artifact_id, record, candidate, explanation))

    @application.get("/v1/datasets/opportunities", response_model=OpportunityDataset)
    def source_opportunities() -> OpportunityDataset:
        try:
            return build_opportunities()
        except IntakeError as exc:
            raise HTTPException(status_code=400, detail=exc.code) from exc

    @application.get("/reviews/datasets/cloud-techniques", response_class=HTMLResponse)
    def review_cloud_dataset() -> HTMLResponse:
        try:
            dataset = load_cloud_technique_dataset()
        except IntakeError as exc:
            raise HTTPException(status_code=400, detail=exc.code) from exc
        return HTMLResponse(render_cloud_dataset(dataset))

    @application.get("/v1/datasets/source-catalog", response_model=SystemCatalog)
    def source_catalog() -> SystemCatalog:
        try:
            return load_system_catalog()
        except IntakeError as exc:
            raise HTTPException(status_code=400, detail=exc.code) from exc

    @application.get("/reviews/datasets/opportunities", response_class=HTMLResponse)
    def review_opportunities_page() -> HTMLResponse:
        try:
            catalog = load_system_catalog()
        except IntakeError as exc:
            raise HTTPException(status_code=400, detail=exc.code) from exc
        return HTMLResponse(render_opportunities(catalog))

    @application.post("/v1/analyses/synthetic", response_model=SyntheticAnalyzeResponse)
    def analyze_synthetic(request: SyntheticAnalyzeRequest) -> SyntheticAnalyzeResponse:
        snapshot, coverage = normalize_with_coverage(request.account)
        report = analyze(
            request.rules,
            snapshot,
            limits=request.limits,
            condition_resolutions=request.condition_resolutions,
            evaluated_at=request.evaluated_at,
        )
        return SyntheticAnalyzeResponse(
            schema_version="0.1",
            snapshot=snapshot,
            coverage=coverage,
            report=report,
        )

    @application.get("/v1/experiments/local-fixtures")
    def local_fixture_experiment() -> LocalFixtureManifest:
        return build_local_fixture_manifest(directory)

    @application.get("/reviews/experiment", response_class=HTMLResponse)
    def review_experiment() -> HTMLResponse:
        manifest = build_local_fixture_manifest(directory)
        return HTMLResponse(render_experiment_page(manifest))

    @application.get("/reviews", response_class=HTMLResponse)
    def review_index() -> HTMLResponse:
        rows: list[tuple[str, str, str, str]] = []
        for case_id in list_fixture_ids(directory):
            case = load_fixture(directory, case_id)
            report = analyze(
                case.rules,
                case.snapshot,
                condition_resolutions=case.condition_resolutions,
                evaluated_at=case.evaluated_at,
            )
            if report.findings:
                finding = report.findings[0]
                rows.append(
                    (
                        case_id,
                        report.verifications[0].status.value,
                        finding.priority.value,
                        str(finding.priority_model.score),
                    )
                )
            else:
                rows.append((case_id, "none", "none", "none"))
        return HTMLResponse(render_review_index(rows))

    @application.get("/reviews/fixtures/{case_id}", response_class=HTMLResponse)
    def review_fixture(case_id: str) -> HTMLResponse:
        try:
            case = load_fixture(directory, case_id)
        except FixtureLoadError as exc:
            status_code = 400 if "not allowed" in str(exc) else 404
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        report = analyze(
            case.rules,
            case.snapshot,
            condition_resolutions=case.condition_resolutions,
            evaluated_at=case.evaluated_at,
        )
        page = render_review_detail(case.case_id, case.rules, case.snapshot, report)
        return HTMLResponse(page)

    return application


app = create_app()
