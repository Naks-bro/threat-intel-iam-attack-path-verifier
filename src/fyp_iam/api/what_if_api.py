"""Offline, synthetic-only structural what-if endpoint."""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from fyp_iam.engine3.what_if import preview_edge_removal
from fyp_iam.fixtures.loader import FixtureLoadError, load_fixture


class EdgeRemovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edge_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")


class EdgeRemovalResponse(BaseModel):
    original_snapshot_id: str
    hypothetical_snapshot_id: str
    removed_edge_id: str
    baseline_candidate_paths: int
    hypothetical_candidate_paths: int
    disappeared_candidate_paths: int
    appeared_candidate_paths: int
    comparison_complete: bool
    limitation: str


def install_what_if_api(application: FastAPI, directory: Path) -> None:
    @application.post(
        "/v1/analyses/fixtures/{case_id}/what-if",
        response_model=EdgeRemovalResponse,
    )
    def remove_fixture_edge(case_id: str, request: EdgeRemovalRequest) -> EdgeRemovalResponse:
        try:
            case = load_fixture(directory, case_id)
        except FixtureLoadError as exc:
            status_code = 400 if "not allowed" in str(exc) else 404
            raise HTTPException(status_code=status_code, detail=str(exc)) from exc
        try:
            result = preview_edge_removal(
                case.rules,
                case.snapshot,
                request.edge_id,
                evaluated_at=case.evaluated_at,
                condition_resolutions=case.condition_resolutions,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="what_if_input_unsupported") from exc
        return EdgeRemovalResponse(
            original_snapshot_id=result.original_snapshot_id,
            hypothetical_snapshot_id=result.hypothetical_snapshot_id,
            removed_edge_id=result.removed_edge_id,
            baseline_candidate_paths=len(result.baseline.attack_paths),
            hypothetical_candidate_paths=len(result.hypothetical.attack_paths),
            disappeared_candidate_paths=result.disappeared_candidate_paths,
            appeared_candidate_paths=result.appeared_candidate_paths,
            comparison_complete=result.comparison_complete,
            limitation=result.limitation,
        )
