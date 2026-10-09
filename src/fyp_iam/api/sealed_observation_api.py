"""Loopback route for one redacted real-account pair.

The route reads the gitignored seal and returns the paired observation. It does
not write a database, call AWS, or open the route when ``FYP_ALLOW_PUBLIC_RUNS``
is set. A non-loopback caller receives a fixed refusal and no seal contents.
"""

from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from pydantic import ConfigDict, Field

from fyp_iam.contracts.models import ContractModel
from fyp_iam.engine2.paired_observation import ObservationLabel
from fyp_iam.engine2.recorded_pair import observe_recorded_user_pair
from fyp_iam.engine2.redacted_seal import RedactedSealRejected, read_redacted_seal, seal_path

_ORIGINS = {
    f"http://{host}:{port}" for host in ("127.0.0.1", "localhost", "[::1]") for port in (5173, 8765)
}
_PUBLIC_CODES = {"starting_user_count_unsupported", "real_account_data_kind_required"}


class SealedIdentityView(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(min_length=1, max_length=128)
    label: str = Field(min_length=1, max_length=128)
    outcome: ObservationLabel


class SealedPairView(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    data_kind: Literal["real_account_observed"]
    snapshot_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    rule_version: int = Field(ge=1, le=1000)
    rule_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    authorization_evaluated: Literal[False] = False
    identities: tuple[SealedIdentityView, SealedIdentityView]


def install_sealed_observation_api(app: FastAPI) -> None:
    """Serve the local redacted pair. Non-loopback hosts are refused."""

    def local_only(request: Request) -> None:
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
            raise HTTPException(status_code=403, detail="sealed_observation_boundary_required")

    router = APIRouter(dependencies=[Depends(local_only)])

    @router.get("/v1/observations/real-account-pair", response_model=SealedPairView)
    def read_pair() -> SealedPairView:
        try:
            handoff = read_redacted_seal(seal_path())
            report = observe_recorded_user_pair(handoff)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="sealed_observation_absent") from None
        except RedactedSealRejected:
            raise HTTPException(status_code=422, detail="sealed_observation_rejected") from None
        except ValueError as exc:
            code = exc.args[0] if exc.args else ""
            if code in _PUBLIC_CODES:
                raise HTTPException(status_code=409, detail=code) from None
            raise HTTPException(status_code=422, detail="sealed_observation_rejected") from None
        return SealedPairView(
            data_kind=report.data_kind,
            snapshot_digest=report.snapshot_digest,
            rule_version=report.rule_version,
            rule_digest=report.rule_digest,
            authorization_evaluated=False,
            identities=(
                SealedIdentityView(
                    key=report.first.principal_key,
                    label=report.first.display_alias,
                    outcome=report.first.label,
                ),
                SealedIdentityView(
                    key=report.second.principal_key,
                    label=report.second.display_alias,
                    outcome=report.second.label,
                ),
            ),
        )

    app.include_router(router)
