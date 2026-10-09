import json
import subprocess
from collections.abc import Callable

import pytest

from fyp_iam.engine2 import aws_guard, aws_preflight
from fyp_iam.engine2.aws_preflight import PreflightConfig, check_connection

_ACCOUNT = "111122223333"  # Synthetic test identifier; never a live account.


@pytest.fixture(autouse=True)
def isolated_call_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(aws_guard, "STATE_DIR", tmp_path / "guard")
    monkeypatch.delenv("FYP_AWS_STOP", raising=False)


def _config() -> PreflightConfig:
    return PreflightConfig(profile="fyp-readonly", expected_account=_ACCOUNT)


def _runner(
    responses: list[dict[str, object] | BaseException], calls: list[list[str]]
) -> Callable[..., subprocess.CompletedProcess[str]]:
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 20
        assert kwargs["stderr"] == subprocess.DEVNULL
        response = responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return subprocess.CompletedProcess(argv, 0, json.dumps(response))

    return run


def _identity(kind: str = "user/reviewer") -> dict[str, object]:
    return {"Account": _ACCOUNT, "Arn": f"arn:aws:iam::{_ACCOUNT}:{kind}"}


def test_root_is_blocked_before_iam_reads() -> None:
    calls: list[list[str]] = []
    result = check_connection(_config(), run=_runner([_identity("root")], calls))
    assert result.status == "blocked"
    assert result.code == "root_identity_not_allowed"
    assert len(calls) == 1
    assert _ACCOUNT not in result.model_dump_json()
    assert "arn:" not in result.model_dump_json()


def test_target_mismatch_is_blocked_before_iam_reads() -> None:
    calls: list[list[str]] = []
    identity = {"Account": "444455556666", "Arn": "arn:aws:iam::444455556666:user/test"}
    result = check_connection(_config(), run=_runner([identity], calls))
    assert result.code == "target_account_mismatch"
    assert len(calls) == 1


def test_valid_identity_only_runs_bounded_read_probes() -> None:
    calls: list[list[str]] = []
    response = {"item_count": 1, "truncated": True}
    result = check_connection(_config(), run=_runner([_identity(), response, response], calls))
    assert result.status == "ready"
    assert result.collection_complete is False
    assert [call[1:3] for call in calls] == [
        ["sts", "get-caller-identity"],
        ["iam", "list-users"],
        ["iam", "list-roles"],
    ]
    for call in calls:
        assert call[call.index("--profile") + 1] == "fyp-readonly"
        assert "--endpoint-url" in call
        assert "--no-cli-pager" in call
    assert calls[0][calls[0].index("--region") + 1] == "ap-southeast-2"
    assert calls[0][calls[0].index("--endpoint-url") + 1] == (
        "https://sts.ap-southeast-2.amazonaws.com"
    )
    for call in calls[1:]:
        assert call[call.index("--region") + 1] == "us-east-1"
        assert call[call.index("--endpoint-url") + 1] == "https://iam.amazonaws.com"
        assert "--no-paginate" in call
        assert json.loads(call[call.index("--cli-input-json") + 1]) == {"MaxItems": 1}


@pytest.mark.parametrize("profile", ["", "--debug", "bad profile", "a;whoami"])
def test_invalid_config_does_not_run_commands(profile: str) -> None:
    with pytest.raises(ValueError):
        PreflightConfig(profile=profile, expected_account=_ACCOUNT)


@pytest.mark.parametrize("identity", [{}, {"Account": _ACCOUNT, "Arn": "garbage"}])
def test_malformed_identity_fails_closed(identity: dict[str, object]) -> None:
    calls: list[list[str]] = []
    result = check_connection(_config(), run=_runner([identity], calls))
    assert result.code == "invalid_identity_response"
    assert len(calls) == 1


def test_timeouts_are_sanitized() -> None:
    calls: list[list[str]] = []
    failure = subprocess.TimeoutExpired("credential-secret", 20)
    result = check_connection(_config(), run=_runner([failure], calls))
    assert result.code == "aws_timeout"
    assert "credential-secret" not in result.model_dump_json()


@pytest.mark.parametrize(
    "probe", [{}, {"item_count": True, "truncated": False}, {"item_count": 2, "truncated": False}]
)
def test_invalid_probe_is_partial_not_ready(probe: dict[str, object]) -> None:
    calls: list[list[str]] = []
    result = check_connection(
        _config(),
        run=_runner(
            [_identity(), probe, {"item_count": 0, "truncated": False}],
            calls,
        ),
    )
    assert result.status == "partial"
    assert result.users_read is False
    assert result.roles_read is True


def test_failed_read_does_not_invent_an_empty_account() -> None:
    calls: list[list[str]] = []
    result = check_connection(
        _config(),
        run=_runner(
            [
                _identity(),
                subprocess.TimeoutExpired("secret", 20),
                {"item_count": 0, "truncated": False},
            ],
            calls,
        ),
    )
    assert result.status == "partial"
    assert result.collection_complete is False


def test_assumed_role_identity_is_supported() -> None:
    calls: list[list[str]] = []
    identity = {
        "Account": _ACCOUNT,
        "Arn": f"arn:aws:sts::{_ACCOUNT}:assumed-role/readonly/test-session",
    }
    probe = {"item_count": 0, "truncated": False}
    result = check_connection(_config(), run=_runner([identity, probe, probe], calls))
    assert result.identity_type == "assumed_role"
    assert result.status == "ready"


def test_missing_cli_is_sanitized() -> None:
    calls: list[list[str]] = []
    result = check_connection(_config(), run=_runner([FileNotFoundError("secret")], calls))
    assert result.code == "aws_cli_unavailable"


@pytest.mark.parametrize(
    "returncode,stdout",
    [
        (1, "secret"),
        (0, "secret"),
        (0, "s" * 16385),
        (0, "[]"),
    ],
)
def test_invalid_cli_output_never_leaks(returncode: int, stdout: str) -> None:
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, returncode, stdout)

    result = check_connection(_config(), run=run)
    assert result.status in ("error", "blocked")
    assert "secret" not in result.model_dump_json()


def test_ambient_keys_and_endpoints_cannot_override_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_STS",
        "AWS_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    ):
        monkeypatch.setenv(key, "secret")
    env = aws_preflight._child_environment()
    # Avoid assertion introspection dumping the inherited environment on failure.
    assert all(value != "secret" for value in env.values())
    assert env["AWS_MAX_ATTEMPTS"] == "1"
    assert env["AWS_CLI_AUTO_PROMPT"] == "off"
    assert env["AWS_EC2_METADATA_DISABLED"] == "true"


def test_target_account_is_not_serialized_or_shown_in_repr() -> None:
    config = _config()
    assert _ACCOUNT not in repr(config)
    assert _ACCOUNT not in config.model_dump_json()


def test_transport_refuses_any_operation_outside_the_three_read_probes() -> None:
    calls: list[list[str]] = []
    with pytest.raises(ValueError, match="unsupported preflight operation"):
        aws_preflight._read(_config(), "iam", "create-user", run=_runner([], calls))
    assert calls == []


@pytest.mark.parametrize("account", [None, "bad-account"])
def test_unconfigured_entrypoint_makes_no_calls_and_redacts_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    account: str | None,
) -> None:
    monkeypatch.setenv("FYP_AWS_PROFILE", "fyp-readonly")
    monkeypatch.delenv("FYP_AWS_EXPECTED_ACCOUNT_ID", raising=False)
    if account is not None:
        monkeypatch.setenv("FYP_AWS_EXPECTED_ACCOUNT_ID", account)

    def unexpected(config: PreflightConfig) -> None:
        pytest.fail("not-configured preflight must not contact AWS")

    monkeypatch.setattr(aws_preflight, "check_connection", unexpected)
    assert aws_preflight.main() == 2
    output = capsys.readouterr().out
    assert "bad-account" not in output
    assert json.loads(output)["status"] == "not_configured"
