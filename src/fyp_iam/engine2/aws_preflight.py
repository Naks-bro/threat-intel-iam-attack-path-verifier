"""Opt-in, redacted connection probes. Not a collector or permission-policy audit."""

import json
import os
import re
import subprocess
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from fyp_iam.engine2.aws_guard import GuardBlocked, record_failure, reserve_call


class PreflightConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    expected_account: str = Field(pattern=r"^[0-9]{12}$", exclude=True, repr=False)


class ConnectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["not_configured", "blocked", "ready", "partial", "error"]
    code: Literal[
        "configuration_required",
        "invalid_configuration",
        "root_identity_not_allowed",
        "target_account_mismatch",
        "invalid_identity_response",
        "aws_timeout",
        "aws_cli_unavailable",
        "aws_command_failed",
        "invalid_probe_response",
        "read_probes_passed",
        "read_probes_incomplete",
        "aws_guard_stopped",
        "aws_guard_rate_limit",
        "aws_guard_daily_limit",
        "aws_guard_cooldown",
        "aws_guard_state_unavailable",
        "aws_guard_clock_rollback",
    ]
    identity_type: Literal["unknown", "iam_user", "assumed_role", "root"] = "unknown"
    users_read: bool = False
    roles_read: bool = False
    collection_complete: Literal[False] = False


RunCommand = Callable[..., subprocess.CompletedProcess[str]]
SELECTED_REGION = "ap-southeast-2"


def _child_environment() -> dict[str, str]:
    """Explicit profile owns credentials; no ambient key or endpoint substitution."""
    keep = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "HOME",
        "TEMP",
        "TMP",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    env.update(
        {
            "AWS_MAX_ATTEMPTS": "1",
            "AWS_RETRY_MODE": "standard",
            "AWS_PAGER": "",
            "AWS_CLI_AUTO_PROMPT": "off",
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    return env


def _read(
    config: PreflightConfig,
    service: str,
    operation: str,
    *,
    run: RunCommand,
) -> tuple[object, ConnectionResult | None]:
    if (service, operation) not in {
        ("sts", "get-caller-identity"),
        ("iam", "list-users"),
        ("iam", "list-roles"),
    }:
        raise ValueError("unsupported preflight operation")
    # STS is regional for this project; IAM still has a commercial global endpoint.
    region = SELECTED_REGION if service == "sts" else "us-east-1"
    endpoint = (
        f"https://sts.{SELECTED_REGION}.amazonaws.com"
        if service == "sts"
        else "https://iam.amazonaws.com"
    )
    argv = [
        "aws",
        service,
        operation,
        "--profile",
        config.profile,
        "--region",
        region,
        "--endpoint-url",
        endpoint,
        "--output",
        "json",
        "--no-cli-pager",
        "--cli-connect-timeout",
        "5",
        "--cli-read-timeout",
        "10",
    ]
    if service == "iam":
        collection = "Users" if operation == "list-users" else "Roles"
        argv.extend(
            [
                "--no-paginate",
                "--cli-input-json",
                '{"MaxItems":1}',
                "--query",
                f"{{item_count:length({collection}),truncated:IsTruncated}}",
            ]
        )
    try:
        reserve_call()
    except GuardBlocked as exc:
        # The guard emits only these fixed codes, never its state or paths.
        return None, ConnectionResult.model_validate({"status": "blocked", "code": str(exc)})
    try:
        response = run(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            timeout=20,
            env=_child_environment(),
        )
        if response.returncode != 0:
            _cooldown()
            return None, ConnectionResult(status="error", code="aws_command_failed")
        if len(response.stdout) > 16384:
            return None, ConnectionResult(status="error", code="invalid_probe_response")
        return json.loads(response.stdout), None
    except subprocess.TimeoutExpired:
        _cooldown()
        return None, ConnectionResult(status="error", code="aws_timeout")
    except OSError:
        _cooldown()
        return None, ConnectionResult(status="error", code="aws_cli_unavailable")
    except (ValueError, UnicodeError):
        _cooldown()
        return None, ConnectionResult(status="error", code="invalid_probe_response")


def _cooldown() -> None:
    try:
        record_failure()
    except GuardBlocked:
        # Unreadable state blocks subsequent calls at reservation time.
        pass


def check_connection(
    config: PreflightConfig,
    *,
    run: RunCommand = subprocess.run,
) -> ConnectionResult:
    """Make at most three bounded CLI calls; never return raw AWS responses."""
    identity, error = _read(config, "sts", "get-caller-identity", run=run)
    if error is not None:
        return error
    if not isinstance(identity, dict):
        return ConnectionResult(status="blocked", code="invalid_identity_response")
    account, arn = identity.get("Account"), identity.get("Arn")
    if not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None:
        return ConnectionResult(status="blocked", code="invalid_identity_response")
    if not isinstance(arn, str):
        return ConnectionResult(status="blocked", code="invalid_identity_response")
    if arn == f"arn:aws:iam::{account}:root":
        return ConnectionResult(
            status="blocked",
            code="root_identity_not_allowed",
            identity_type="root",
        )
    principal = r"[A-Za-z0-9_+=,.@/-]+"
    if re.fullmatch(rf"arn:aws:iam::{account}:user/{principal}", arn):
        kind: Literal["iam_user", "assumed_role"] = "iam_user"
    elif re.fullmatch(rf"arn:aws:sts::{account}:assumed-role/{principal}/{principal}", arn):
        kind = "assumed_role"
    else:
        return ConnectionResult(status="blocked", code="invalid_identity_response")
    if account != config.expected_account:
        return ConnectionResult(status="blocked", code="target_account_mismatch")
    passed: list[bool] = []
    for operation in ("list-users", "list-roles"):
        probe, failure = _read(config, "iam", operation, run=run)
        if failure is not None and failure.status == "blocked":
            return failure.model_copy(
                update={
                    "status": "partial",
                    "identity_type": kind,
                    "users_read": passed[0] if passed else False,
                }
            )
        valid = (
            failure is None
            and isinstance(probe, dict)
            and type(probe.get("item_count")) is int
            and probe["item_count"] in (0, 1)
            and type(probe.get("truncated")) is bool
        )
        passed.append(valid)
    return ConnectionResult(
        status="ready" if all(passed) else "partial",
        code="read_probes_passed" if all(passed) else "read_probes_incomplete",
        identity_type=kind,
        users_read=passed[0],
        roles_read=passed[1],
    )


def main() -> int:
    """Explicit operator command only; ordinary API/preview paths never invoke it."""
    profile = os.environ.get("FYP_AWS_PROFILE")
    account = os.environ.get("FYP_AWS_EXPECTED_ACCOUNT_ID")
    if not profile or not account:
        result = ConnectionResult(status="not_configured", code="configuration_required")
    else:
        try:
            config = PreflightConfig(profile=profile, expected_account=account)
        except ValueError:
            result = ConnectionResult(status="not_configured", code="invalid_configuration")
        else:
            result = check_connection(config)
    print(result.model_dump_json())
    return 0 if result.status == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
