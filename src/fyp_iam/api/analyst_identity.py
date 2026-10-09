"""Backend-only Supabase Auth identity resolution; never an authorization grant.

No route uses this yet. A verified session must later be mapped to an active
application-controlled analyst actor and role before a decision or IT export.
"""

import json
import re
from dataclasses import dataclass
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

_PROJECT_URL = re.compile(r"^https://[a-z0-9][a-z0-9-]{2,62}[a-z0-9]\.supabase\.co$")
_API_KEY = re.compile(r"^sb_publishable_[A-Za-z0-9_-]{16,256}$")
_JWT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_MAX_RESPONSE_BYTES = 65_536


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, request: Request, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> None:
        return None


@dataclass(frozen=True)
class VerifiedSupabaseIdentity:
    """An authenticated provider subject, not a reviewer role or actor record."""

    issuer: str
    subject: str


@dataclass(frozen=True)
class IdentityResolution:
    status: Literal["authenticated", "rejected", "unavailable"]
    code: Literal[
        "auth_user_verified",
        "auth_not_configured",
        "invalid_auth_input",
        "auth_user_rejected",
        "anonymous_user_rejected",
        "auth_service_unavailable",
        "invalid_auth_response",
    ]
    identity: VerifiedSupabaseIdentity | None = None


def resolve_supabase_identity(
    project_url: str | None, publishable_key: str | None, access_token: str | None
) -> IdentityResolution:
    """Ask this project's Auth server to verify a JWT; return no user metadata.

    This is deliberately a network verification instead of decoding an untrusted
    browser session. It supports projects with legacy symmetric signing keys.
    """

    if not project_url or not publishable_key:
        return IdentityResolution("unavailable", "auth_not_configured")
    if (
        _PROJECT_URL.fullmatch(project_url) is None
        or _API_KEY.fullmatch(publishable_key) is None
        or access_token is None
        or len(access_token) > 8192
        or _JWT.fullmatch(access_token) is None
    ):
        return IdentityResolution("rejected", "invalid_auth_input")
    request = Request(
        f"{project_url}/auth/v1/user",
        headers={
            "apikey": publishable_key,
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=5) as response:
            if response.status != 200:
                return IdentityResolution("unavailable", "auth_service_unavailable")
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if error.code in (401, 403):
            return IdentityResolution("rejected", "auth_user_rejected")
        return IdentityResolution("unavailable", "auth_service_unavailable")
    except (URLError, OSError, TimeoutError, ValueError):
        return IdentityResolution("unavailable", "auth_service_unavailable")
    if len(body) > _MAX_RESPONSE_BYTES:
        return IdentityResolution("rejected", "invalid_auth_response")
    try:
        user = json.loads(body)
        if not isinstance(user, dict):
            raise ValueError("not an object")
        subject = user.get("id")
        if not isinstance(subject, str) or str(UUID(subject)) != subject:
            raise ValueError("invalid subject")
        if user.get("is_anonymous") is True:
            return IdentityResolution("rejected", "anonymous_user_rejected")
        if user.get("is_anonymous") is not False:
            raise ValueError("anonymous state missing")
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return IdentityResolution("rejected", "invalid_auth_response")
    return IdentityResolution(
        "authenticated",
        "auth_user_verified",
        VerifiedSupabaseIdentity(issuer=f"{project_url}/auth/v1", subject=subject),
    )
