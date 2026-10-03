"""FastAPI application for local fixture analysis."""

import json
import logging
import re
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.base import RequestResponseEndpoint

from fyp_iam import __version__
from fyp_iam.api.schemas import (
    AnalyzeRequest,
    ApprovalRequest,
    ApprovalResponse,
    FoundryOverviewResponse,
    FoundryRuleResponse,
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
from fyp_iam.engine1.foundry.preview import preview_overview, preview_rule
from fyp_iam.engine1.foundry.store import (
    FoundryRunInProgress,
    persist_foundry,
    read_registry,
    read_rule,
)
from fyp_iam.engine1.intake import (
    decide_candidate,
    explain_proposal,
    load_artifact,
    normalize_technique,
    propose_rule,
    validate_candidate,
)
from fyp_iam.engine1.opportunities import OpportunityDataset, build_opportunities
from fyp_iam.engine1.workbench.config import database_url_from_env
from fyp_iam.engine1.workbench.db import PostgresWorkbenchStore, database_status
from fyp_iam.engine1.workbench.domain import WorkbenchView
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable
from fyp_iam.engine1.workbench.services import build_snapshot, view_from_snapshot
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
from fyp_iam.persistence.redact import install_redaction
from fyp_iam.persistence.urls import prepare_url

_UNSET = object()
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_LOGGER = logging.getLogger("uvicorn.error.fyp_iam")


def _log_event(level: int, event: str, **fields: object) -> None:
    _LOGGER.log(level, "%s", json.dumps({"event": event, **fields}, sort_keys=True))


def _unavailable_registry(state: str, detail: str) -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "database": state,
        "database_detail": detail,
        "storage": "not_written",
        "registry": "unavailable",
        "sources": [],
        "run": None,
        "primitives": [],
        "relations": [],
        "candidates": [],
    }


def create_app(
    fixture_dir: Path | None = None,
    *,
    database_url: str | None | object = _UNSET,
    foundry_preview: bool = False,
) -> FastAPI:
    application = FastAPI(
        title="FYP IAM local verification",
        version=__version__,
        description=(
            "Local fixture pipeline. It does not connect to AWS, Neo4j, Redis, or an LLM."
        ),
    )
    install_redaction()
    directory = fixture_dir or default_fixture_dir()
    application.state.fixture_dir = directory
    if foundry_preview:
        raw_url = None
    elif database_url is _UNSET:
        raw_url = database_url_from_env()
    elif isinstance(database_url, str):
        raw_url = database_url
    else:
        raw_url = None
    if raw_url:
        prepared_url, prepare_error = prepare_url(raw_url)
        resolved_url = raw_url if prepare_error else prepared_url
    else:
        resolved_url = None

    @application.middleware("http")
    async def observe_request(request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _REQUEST_ID.fullmatch(supplied) else uuid4().hex
        request.state.request_id = request_id
        started = perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            _log_event(
                logging.ERROR,
                "http_request_failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                error_type=type(exc).__name__,
                duration_ms=round((perf_counter() - started) * 1000, 2),
            )
            raise
        duration_ms = round((perf_counter() - started) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["Server-Timing"] = f"app;dur={duration_ms}"
        _log_event(
            logging.INFO,
            "http_request_completed",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        return response

    @application.get("/health")
    def health() -> dict[str, str]:
        state, detail = (
            ("not_connected", "offline_preview")
            if foundry_preview
            else database_status(resolved_url)
        )
        return {
            "status": "ok",
            "mode": "foundry_preview" if foundry_preview else "local_fixtures",
            "aws": "not_connected",
            "engine1": "local_intake",
            "engine2": "synthetic_normalizer",
            "neo4j": "not_connected",
            "database": state,
            "database_detail": detail,
            "version": __version__,
        }

    @application.get("/v1/workbench/fixtures/{pin_id}", response_model=WorkbenchView)
    def workbench_fixture(pin_id: str) -> WorkbenchView:
        try:
            snapshot = build_snapshot(pin_id)
        except IntakeError as exc:
            status_code = 404 if exc.code == "unknown_artifact" else 400
            raise HTTPException(status_code=status_code, detail=exc.code) from exc
        return view_from_snapshot(snapshot, persisted=False)

    @application.post("/v1/workbench/imports/{pin_id}", response_model=WorkbenchView)
    def import_workbench_pin(pin_id: str) -> WorkbenchView:
        state, _detail = database_status(resolved_url)
        if state != "available" or resolved_url is None:
            raise HTTPException(status_code=503, detail="database_unavailable")
        try:
            snapshot = build_snapshot(pin_id)
        except IntakeError as exc:
            status_code = 404 if exc.code == "unknown_artifact" else 400
            raise HTTPException(status_code=status_code, detail=exc.code) from exc
        store = PostgresWorkbenchStore(resolved_url)
        try:
            store.save_import(snapshot)
            stored = store.get_import(pin_id)
        except DatabaseUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.code) from exc
        finally:
            store.dispose()
        if stored is None:
            raise HTTPException(status_code=503, detail="database_unavailable")
        return view_from_snapshot(stored, persisted=True)

    @application.get("/v1/foundry/overview", response_model=FoundryOverviewResponse)
    def foundry_overview() -> dict[str, object]:
        if foundry_preview:
            return preview_overview()
        if not isinstance(resolved_url, str):
            return _unavailable_registry("not_configured", "not_configured")
        try:
            return read_registry(resolved_url)
        except (DatabaseUnavailable, SQLAlchemyError):
            return _unavailable_registry("unavailable", "unreachable")

    @application.get("/v1/foundry/rules/{version_id}", response_model=FoundryRuleResponse)
    def foundry_rule(version_id: str) -> dict[str, object]:
        if foundry_preview:
            rule = preview_rule(version_id)
            if rule is None:
                raise HTTPException(status_code=404, detail="rule_not_found")
            return rule
        if not isinstance(resolved_url, str):
            raise HTTPException(status_code=503, detail="database_unavailable")
        try:
            rule = read_rule(resolved_url, version_id)
        except (DatabaseUnavailable, SQLAlchemyError) as exc:
            raise HTTPException(status_code=503, detail="database_unavailable") from exc
        if rule is None:
            raise HTTPException(status_code=404, detail="rule_not_found")
        return rule

    @application.post("/v1/foundry/runs", response_model=FoundryOverviewResponse)
    def foundry_run(request: Request) -> dict[str, object]:
        request_id = str(getattr(request.state, "request_id", "unknown"))
        if foundry_preview:
            _log_event(logging.INFO, "foundry_preview_recomputed", request_id=request_id)
            return preview_overview()
        if not isinstance(resolved_url, str):
            _log_event(
                logging.WARNING,
                "foundry_pipeline_rejected",
                request_id=request_id,
                reason="database_unavailable",
            )
            raise HTTPException(status_code=503, detail="database_unavailable")
        started = perf_counter()
        _log_event(logging.INFO, "foundry_pipeline_started", request_id=request_id)
        try:
            persist_foundry(resolved_url)
            registry = read_registry(resolved_url)
        except FoundryRunInProgress as exc:
            _log_event(
                logging.WARNING,
                "foundry_pipeline_rejected",
                request_id=request_id,
                reason="run_in_progress",
            )
            raise HTTPException(status_code=409, detail="foundry_run_in_progress") from exc
        except (DatabaseUnavailable, SQLAlchemyError) as exc:
            _log_event(
                logging.ERROR,
                "foundry_pipeline_failed",
                request_id=request_id,
                error_type=type(exc).__name__,
                duration_ms=round((perf_counter() - started) * 1000, 2),
            )
            raise HTTPException(status_code=503, detail="database_unavailable") from exc
        sources = registry.get("sources", [])
        candidates = registry.get("candidates", [])
        _log_event(
            logging.INFO,
            "foundry_pipeline_completed",
            request_id=request_id,
            duration_ms=round((perf_counter() - started) * 1000, 2),
            registry=str(registry.get("registry", "unknown")),
            source_count=len(sources) if isinstance(sources, list) else 0,
            candidate_count=len(candidates) if isinstance(candidates, list) else 0,
        )
        return registry

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
