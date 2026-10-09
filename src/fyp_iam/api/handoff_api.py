"""Loopback-only route for a redacted paired-observation handoff.

The operator alias is process configuration. It is not Supabase Auth, email,
or public approval. A non-loopback caller receives a fixed refusal.
"""

import re
from json import JSONDecodeError
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import ValidationError

from fyp_iam.contracts.models import ContractModel, reject_sensitive_text
from fyp_iam.engine2.paired_observation import PairedObservationReport
from fyp_iam.engine4.handoff_report import (
    HandoffDecision,
    HandoffReviewLedger,
    HandoffReviewReceipt,
    HandoffReviewRejected,
    RedactedHandoffExport,
)

_ORIGINS = {
    f"http://{host}:{port}" for host in ("127.0.0.1", "localhost", "[::1]") for port in (5173, 8765)
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECORD = "/v1/handoff/reviews"
_EXPORT = re.compile(r"^/v1/handoff/reviews/sha256:[0-9a-f]{64}/export$")


class HandoffReviewCommand(ContractModel):
    report: PairedObservationReport
    decision: HandoffDecision


def install_handoff_api(app: FastAPI, alias: str | None, *, preview: bool) -> None:
    """Install the in-memory handoff review routes. No database is required."""

    if alias is not None:
        try:
            if re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", alias) is None:
                raise ValueError
            reject_sensitive_text(alias)
        except ValueError:
            raise ValueError("Invalid local review operator alias") from None
    ledger = HandoffReviewLedger()

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

    router = APIRouter(dependencies=[Depends(local_operator)])

    @router.post(_RECORD, response_model=HandoffReviewReceipt)
    async def record(request: Request) -> HandoffReviewReceipt:
        assert alias is not None
        command = _command(await _payload(request))
        try:
            return ledger.record(command.report, command.decision, alias)
        except HandoffReviewRejected as exc:
            raise HTTPException(status_code=409, detail=exc.code) from None

    @router.get(
        "/v1/handoff/reviews/{report_digest}/export",
        response_model=RedactedHandoffExport,
    )
    def export(report_digest: str) -> RedactedHandoffExport:
        if _DIGEST.fullmatch(report_digest) is None:
            raise HTTPException(status_code=422, detail="review_request_invalid")
        try:
            return ledger.export(report_digest)
        except HandoffReviewRejected as exc:
            raise HTTPException(status_code=409, detail=exc.code) from None

    app.include_router(router)


async def _payload(request: Request) -> Any:
    try:
        return await request.json()
    except (JSONDecodeError, UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=422, detail="review_request_invalid") from None


def _command(payload: Any) -> HandoffReviewCommand:
    try:
        return HandoffReviewCommand.model_validate(payload)
    except ValidationError:
        raise HTTPException(status_code=422, detail="review_request_invalid") from None


def handoff_route(path: str) -> bool:
    """True when a validation failure on this path must not echo the body."""

    return path == _RECORD or _EXPORT.fullmatch(path) is not None
