"""Supabase Auth identity resolution is fail-closed and does not grant a role."""

import json
from dataclasses import asdict
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from fyp_iam.api import analyst_identity

PROJECT = "https://abcdefghijklmnopqrst.supabase.co"
KEY = "sb_publishable_test_12345678901234567890"
TOKEN = "header.payload.signature"
SUBJECT = "c42b1d08-6e10-4e44-a26a-141179813719"


class FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def read(self, _limit: int) -> bytes:
        return self.body


class FakeOpener:
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response
        self.requests: list[Request] = []

    def open(self, request: Request, *, timeout: int) -> FakeResponse:
        self.requests.append(request)
        assert timeout == 5
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _install(monkeypatch: pytest.MonkeyPatch, response: FakeResponse | Exception) -> FakeOpener:
    opener = FakeOpener(response)
    monkeypatch.setattr(analyst_identity, "build_opener", lambda *_args: opener)
    return opener


def test_auth_server_identity_is_not_an_application_role(monkeypatch: pytest.MonkeyPatch) -> None:
    opener = _install(
        monkeypatch,
        FakeResponse(
            json.dumps(
                {
                    "id": SUBJECT,
                    "is_anonymous": False,
                    "email": "private@example.invalid",
                    "user_metadata": {"role": "admin"},
                }
            ).encode()
        ),
    )
    result = analyst_identity.resolve_supabase_identity(PROJECT, KEY, TOKEN)
    assert result.status == "authenticated"
    assert result.identity == analyst_identity.VerifiedSupabaseIdentity(
        issuer=f"{PROJECT}/auth/v1", subject=SUBJECT
    )
    assert "role" not in asdict(result)
    assert "private@example.invalid" not in str(result)
    assert TOKEN not in str(result)
    assert opener.requests[0].full_url == f"{PROJECT}/auth/v1/user"
    assert opener.requests[0].get_method() == "GET"


@pytest.mark.parametrize(
    ("project", "key", "token", "expected"),
    [
        (None, KEY, TOKEN, "auth_not_configured"),
        (PROJECT, None, TOKEN, "auth_not_configured"),
        ("http://abcdefghijklmnopqrst.supabase.co", KEY, TOKEN, "invalid_auth_input"),
        ("https://evil.example", KEY, TOKEN, "invalid_auth_input"),
        (PROJECT + "/redirect", KEY, TOKEN, "invalid_auth_input"),
        (PROJECT, "sb_secret_12345678901234567890", TOKEN, "invalid_auth_input"),
        (PROJECT, KEY, "header\r\npayload", "invalid_auth_input"),
        (PROJECT, KEY, "not-a-jwt", "invalid_auth_input"),
    ],
)
def test_missing_or_unsafe_input_never_calls_network(
    monkeypatch: pytest.MonkeyPatch,
    project: str | None,
    key: str | None,
    token: str,
    expected: str,
) -> None:
    monkeypatch.setattr(
        analyst_identity, "build_opener", lambda *_args: pytest.fail("network called")
    )
    assert analyst_identity.resolve_supabase_identity(project, key, token).code == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"id": SUBJECT, "is_anonymous": True}, "anonymous_user_rejected"),
        ({"id": SUBJECT}, "invalid_auth_response"),
        ({"id": "not-a-uuid", "is_anonymous": False}, "invalid_auth_response"),
        ({"is_anonymous": False}, "invalid_auth_response"),
    ],
)
def test_ambiguous_or_anonymous_response_is_rejected(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, object], expected: str
) -> None:
    _install(monkeypatch, FakeResponse(json.dumps(body).encode()))
    result = analyst_identity.resolve_supabase_identity(PROJECT, KEY, TOKEN)
    assert result.code == expected
    assert result.identity is None


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (HTTPError(PROJECT, 401, "unauthorized", None, None), "rejected", "auth_user_rejected"),
        (
            HTTPError(PROJECT, 302, "redirect", None, None),
            "unavailable",
            "auth_service_unavailable",
        ),
        (URLError("private network detail"), "unavailable", "auth_service_unavailable"),
    ],
)
def test_auth_failure_returns_fixed_codes_without_details(
    monkeypatch: pytest.MonkeyPatch, error: Exception, status: str, code: str
) -> None:
    _install(monkeypatch, error)
    result = analyst_identity.resolve_supabase_identity(PROJECT, KEY, TOKEN)
    assert (result.status, result.code, result.identity) == (status, code, None)
    assert "private network detail" not in str(result)


def test_oversized_auth_response_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, FakeResponse(b"x" * 65_537))
    result = analyst_identity.resolve_supabase_identity(PROJECT, KEY, TOKEN)
    assert result.code == "invalid_auth_response"


def test_redirect_handler_does_not_follow_token_to_another_host() -> None:
    request = Request(f"{PROJECT}/auth/v1/user")
    assert (
        analyst_identity._NoRedirect().redirect_request(
            request, None, 302, "redirect", None, "https://evil.example"
        )
        is None
    )
