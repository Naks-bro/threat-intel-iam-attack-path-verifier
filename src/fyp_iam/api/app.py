"""FastAPI application for local fixture analysis."""

from pathlib import Path

from fastapi import FastAPI, HTTPException

from fyp_iam import __version__
from fyp_iam.api.schemas import AnalyzeRequest
from fyp_iam.core.report import AnalysisReport
from fyp_iam.engine3.pipeline import analyze
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

    return application


app = create_app()
