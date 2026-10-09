"""Opt-in loopback review API; operator alias is not shared authentication."""

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from fyp_iam.api.handoff_api import handoff_route
from fyp_iam.contracts.models import reject_sensitive_text
from fyp_iam.contracts.releases import ReleaseScope, StableReleaseCommand, StableRuleRelease
from fyp_iam.engine1.foundry.publication import Channel, PublicationAssessment
from fyp_iam.engine1.foundry.publication_store import publication_assessment
from fyp_iam.engine1.foundry.release_store import (
    ReleaseConflict,
    ReleaseNotFound,
    export_release,
    record_release,
)
from fyp_iam.engine1.foundry.review import ReviewCommand, ReviewRecord, ReviewScope, ReviewState
from fyp_iam.engine1.foundry.review_store import (
    ReviewConflict,
    ReviewInProgress,
    ReviewNotFound,
    record_review,
    review_state,
)
from fyp_iam.engine1.workbench.errors import DatabaseUnavailable

_POST = "/v1/foundry/reviews"
_GET = re.compile(r"^/v1/foundry/rules/[^/]+/review$")
_ASSESS = re.compile(r"^/v1/foundry/rules/[^/]+/publication-assessment$")
_RELEASE_EXPORT = re.compile(r"^/v1/foundry/releases/[^/]+/export$")
_RELEASE_POST = "/v1/foundry/releases"
_ORIGINS = {
    f"http://{host}:{port}" for host in ("127.0.0.1", "localhost", "[::1]") for port in (5173, 8765)
}


class ReviewAPIError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detail: Literal[
        "review_conflict",
        "foundry_run_in_progress",
        "database_unavailable",
        "rule_not_found",
        "review_request_invalid",
        "local_review_disabled",
        "local_review_boundary_required",
        "release_conflict",
        "release_not_found",
    ]


_ERRORS: dict[int | str, dict[str, Any]] = {
    code: {"model": ReviewAPIError} for code in (403, 404, 409, 422, 503)
}


def install_review_api(app: FastAPI, url: str | None, alias: str | None, *, preview: bool) -> None:
    if alias is not None:
        try:
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", alias) is None:
                raise ValueError
            reject_sensitive_text(alias)
        except ValueError:
            raise ValueError("Invalid local review operator alias") from None

    def local_operator(request: Request) -> None:
        if alias is None or preview:
            raise HTTPException(status_code=503, detail="local_review_disabled")
        if (
            request.client is None
            or request.client.host not in ("127.0.0.1", "::1")
            or request.url.hostname not in ("127.0.0.1", "localhost", "::1")
            or any(
                key in request.headers
                for key in ("forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto")
            )
            or ("origin" in request.headers and request.headers["origin"] not in _ORIGINS)
        ):
            raise HTTPException(status_code=403, detail="local_review_boundary_required")
        if url is None:
            raise HTTPException(status_code=503, detail="database_unavailable")

    # Do not echo unsafe comments, identities or submitted digests in validation errors.
    @app.exception_handler(RequestValidationError)
    async def safe_review_validation(request: Request, exc: RequestValidationError) -> Response:
        if (
            request.url.path == _POST
            or _GET.fullmatch(request.url.path)
            or _ASSESS.fullmatch(request.url.path)
            or request.url.path == _RELEASE_POST
            or _RELEASE_EXPORT.fullmatch(request.url.path)
            or handoff_route(request.url.path)
        ):
            return JSONResponse(status_code=422, content={"detail": "review_request_invalid"})
        return await request_validation_exception_handler(request, exc)

    router = APIRouter(dependencies=[Depends(local_operator)])

    @router.post(_POST, response_model=ReviewRecord, responses=_ERRORS)
    def review(command: ReviewCommand) -> ReviewRecord:
        assert url is not None and alias is not None
        try:
            return record_review(url, command, alias)
        except ReviewConflict:
            raise HTTPException(status_code=409, detail="review_conflict") from None
        except ReviewInProgress:
            raise HTTPException(status_code=409, detail="foundry_run_in_progress") from None
        except DatabaseUnavailable:
            raise HTTPException(status_code=503, detail="database_unavailable") from None

    @router.get(
        "/v1/foundry/rules/{version_id}/review", response_model=ReviewState, responses=_ERRORS
    )
    def latest(version_id: str, scope: ReviewScope) -> ReviewState:
        assert url is not None
        try:
            record = review_state(url, version_id, scope)
        except ReviewNotFound:
            raise HTTPException(status_code=404, detail="rule_not_found") from None
        except DatabaseUnavailable:
            raise HTTPException(status_code=503, detail="database_unavailable") from None
        return ReviewState(rule_version_id=version_id, scope=scope, latest=record)

    @router.get(
        "/v1/foundry/rules/{version_id}/publication-assessment",
        response_model=PublicationAssessment,
        responses=_ERRORS,
    )
    def assessment(
        version_id: str,
        scope: ReviewScope,
        channel: Channel = "stable",
        allow_experimental: bool = False,
    ) -> PublicationAssessment:
        assert url is not None
        try:
            return publication_assessment(
                url,
                version_id,
                scope,
                channel,
                allow_experimental=allow_experimental,
            )
        except ReviewNotFound:
            raise HTTPException(status_code=404, detail="rule_not_found") from None
        except ReviewInProgress:
            raise HTTPException(status_code=409, detail="foundry_run_in_progress") from None
        except DatabaseUnavailable:
            raise HTTPException(status_code=503, detail="database_unavailable") from None

    @router.post(_RELEASE_POST, response_model=StableRuleRelease, responses=_ERRORS)
    def publish(command: StableReleaseCommand) -> StableRuleRelease:
        assert url is not None and alias is not None
        try:
            return record_release(url, command, alias)
        except ReleaseConflict:
            raise HTTPException(status_code=409, detail="release_conflict") from None
        except ReviewNotFound:
            raise HTTPException(status_code=404, detail="rule_not_found") from None
        except ReviewInProgress:
            raise HTTPException(status_code=409, detail="foundry_run_in_progress") from None
        except DatabaseUnavailable:
            raise HTTPException(status_code=503, detail="database_unavailable") from None

    @router.get(
        "/v1/foundry/releases/{release_id}/export",
        response_model=StableRuleRelease,
        responses=_ERRORS,
    )
    def export(release_id: str, scope: ReleaseScope) -> StableRuleRelease:
        assert url is not None
        try:
            return export_release(url, release_id, scope)
        except ReleaseConflict:
            raise HTTPException(status_code=409, detail="release_conflict") from None
        except (ReleaseNotFound, ReviewNotFound):
            raise HTTPException(status_code=404, detail="release_not_found") from None
        except ReviewInProgress:
            raise HTTPException(status_code=409, detail="foundry_run_in_progress") from None
        except DatabaseUnavailable:
            raise HTTPException(status_code=503, detail="database_unavailable") from None

    app.include_router(router)
