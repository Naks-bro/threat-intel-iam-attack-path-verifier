"""Offline tests: no AWS credentials, requests or billing API calls."""

import pytest

from fyp_iam.engine2 import aws_guard


@pytest.fixture(autouse=True)
def isolated_guard(tmp_path, monkeypatch):
    monkeypatch.setattr(aws_guard, "STATE_DIR", tmp_path / "guard")
    monkeypatch.delenv("FYP_AWS_STOP", raising=False)


def test_rolling_minute_limit_is_persistent_across_instances():
    for _ in range(12):
        aws_guard.reserve_call(now=1000)
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_rate_limit"):
        aws_guard.reserve_call(now=1000)
    aws_guard.reserve_call(now=1060)


def test_rolling_day_limit_does_not_reset_at_midnight():
    for batch in range(10):
        for _ in range(12):
            aws_guard.reserve_call(now=1000 + batch * 60)
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_daily_limit"):
        aws_guard.reserve_call(now=2000)
    aws_guard.reserve_call(now=1000 + 86400)


@pytest.mark.parametrize("method", ["environment", "file"])
def test_stop_switch_blocks_before_reservation(method, monkeypatch):
    if method == "environment":
        monkeypatch.setenv("FYP_AWS_STOP", "1")
    else:
        aws_guard.set_stopped(True)
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_stopped"):
        aws_guard.reserve_call(now=1000)


def test_failure_cooldown_increases_without_an_automatic_retry():
    aws_guard.reserve_call(now=1000)
    aws_guard.record_failure(now=1000)
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_cooldown"):
        aws_guard.reserve_call(now=1059)
    aws_guard.reserve_call(now=1060)
    aws_guard.record_failure(now=1060)
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_cooldown"):
        aws_guard.reserve_call(now=1179)
    aws_guard.reserve_call(now=1180)


def test_clock_rollback_and_missing_initialized_state_fail_closed():
    aws_guard.reserve_call(now=1000)
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_clock_rollback"):
        aws_guard.reserve_call(now=999)
    (aws_guard.STATE_DIR / "state.json").unlink()
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_state_unavailable"):
        aws_guard.reserve_call(now=1001)


def test_stop_resume_does_not_reset_consumed_calls():
    for _ in range(12):
        aws_guard.reserve_call(now=1000)
    aws_guard.set_stopped(True)
    aws_guard.set_stopped(False)
    with pytest.raises(aws_guard.GuardBlocked, match="aws_guard_rate_limit"):
        aws_guard.reserve_call(now=1000)


def test_invalid_state_never_prints_its_contents():
    aws_guard.reserve_call(now=1000)
    (aws_guard.STATE_DIR / "state.json").write_text("private-malformed-value")
    with pytest.raises(aws_guard.GuardBlocked) as caught:
        aws_guard.reserve_call(now=1001)
    assert str(caught.value) == "aws_guard_state_unavailable"


def test_preflight_stop_switch_invokes_no_transport(monkeypatch):
    from fyp_iam.engine2.aws_preflight import PreflightConfig, check_connection

    monkeypatch.setenv("FYP_AWS_STOP", "1")

    def forbidden(*args, **kwargs):
        pytest.fail("Stop switch must prevent every AWS command")

    result = check_connection(
        PreflightConfig(profile="readonly", expected_account="111122223333"), run=forbidden
    )
    assert result.status == "blocked"
    assert result.code == "aws_guard_stopped"


def test_unavailable_state_blocks_before_transport(tmp_path, monkeypatch):
    from fyp_iam.engine2.aws_preflight import PreflightConfig, check_connection

    obstructed = tmp_path / "not-a-directory"
    obstructed.touch()
    monkeypatch.setattr(aws_guard, "STATE_DIR", obstructed)

    def forbidden(*args, **kwargs):
        pytest.fail("Unwritable guard must prevent every AWS command")

    result = check_connection(
        PreflightConfig(profile="readonly", expected_account="111122223333"), run=forbidden
    )
    assert result.code == "aws_guard_state_unavailable"


def test_preflight_network_failure_trips_guard_and_stops_following_reads():
    import json
    import subprocess

    from fyp_iam.engine2.aws_preflight import PreflightConfig, check_connection

    calls = []

    def transport(argv, **kwargs):
        calls.append(argv)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(
                    {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:user/test"}
                ),
            )
        return subprocess.CompletedProcess(argv, 1, "")

    result = check_connection(
        PreflightConfig(profile="readonly", expected_account="111122223333"), run=transport
    )
    assert len(calls) == 2
    assert result.status == "partial"
    assert result.code == "aws_guard_cooldown"
    assert result.collection_complete is False


def test_real_processes_share_one_locked_budget():
    import json
    import subprocess
    import sys

    code = """
import sys
from pathlib import Path
from fyp_iam.engine2 import aws_guard
aws_guard.STATE_DIR = Path(sys.argv[1])
for _ in range(3):
    try:
        aws_guard.reserve_call(now=1000)
        print('reserved', flush=True)
    except aws_guard.GuardBlocked:
        print('blocked', flush=True)
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(aws_guard.STATE_DIR)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        for _ in range(6)
    ]
    outputs = []
    try:
        for process in processes:
            output, error = process.communicate(timeout=30)
            assert process.returncode == 0, error
            outputs.extend(output.splitlines())
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()
    state = json.loads((aws_guard.STATE_DIR / "state.json").read_text())
    assert outputs.count("reserved") == len(state["calls"])
    assert 0 < len(state["calls"]) <= 12
    assert outputs.count("blocked") > 0
