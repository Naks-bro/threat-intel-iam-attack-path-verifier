"""Local cooperative call budget, not an AWS quota or account spending cap."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

STATE_DIR = Path(__file__).resolve().parents[3] / ".aws-safety"
MINUTE_LIMIT = 12
DAY_LIMIT = 120


class GuardBlocked(Exception):
    """Fixed sanitized codes only; callers must not execute on this exception."""


class _Ledger(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(default=1, ge=1, le=1)
    calls: list[int] = Field(default_factory=list, max_length=DAY_LIMIT)
    last_seen: int = Field(default=0, ge=0)
    cooldown_until: int = Field(default=0, ge=0)
    failures: int = Field(default=0, ge=0, le=5)

    @model_validator(mode="after")
    def valid_history(self) -> _Ledger:
        if (
            self.calls != sorted(self.calls)
            or any(value < 0 or value > self.last_seen for value in self.calls)
            or self.cooldown_until > self.last_seen + 900
        ):
            raise ValueError("invalid guard history")
        return self


@contextmanager
def _locked() -> Iterator[None]:
    """Nonblocking OS lock; competing callers fail closed instead of waiting."""
    acquired = False
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with (STATE_DIR / "lock").open("a+b") as handle:
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            try:
                yield
            finally:
                if acquired:
                    handle.seek(0)
                    if sys.platform == "win32":
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        raise GuardBlocked("aws_guard_state_unavailable") from None


def _load() -> _Ledger:
    path = STATE_DIR / "state.json"
    try:
        if not path.exists():
            if (STATE_DIR / "initialized").exists():
                raise GuardBlocked("aws_guard_state_unavailable")
            return _Ledger()
        if path.stat().st_size > 8192:
            raise GuardBlocked("aws_guard_state_unavailable")
        return _Ledger.model_validate_json(path.read_bytes())
    except (ValueError, OSError):
        raise GuardBlocked("aws_guard_state_unavailable") from None


def _store(ledger: _Ledger) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=STATE_DIR, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(ledger.model_dump_json())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE_DIR / "state.json")
        (STATE_DIR / "initialized").touch(exist_ok=True)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _clock(now: int | None, ledger: _Ledger) -> int:
    moment = int(time.time()) if now is None else now
    if type(moment) is not int or moment < ledger.last_seen or moment < 0:
        raise GuardBlocked("aws_guard_clock_rollback")
    return moment


def reserve_call(*, now: int | None = None) -> None:
    """Persist a reservation BEFORE transport, including failed/abandoned attempts."""
    if os.environ.get("FYP_AWS_STOP", "0").strip() != "0":
        raise GuardBlocked("aws_guard_stopped")
    with _locked():
        if (STATE_DIR / "STOP").exists():
            raise GuardBlocked("aws_guard_stopped")
        ledger = _load()
        moment = _clock(now, ledger)
        if moment < ledger.cooldown_until:
            raise GuardBlocked("aws_guard_cooldown")
        calls = [stamp for stamp in ledger.calls if stamp > moment - 86400]
        if len(calls) >= DAY_LIMIT:
            raise GuardBlocked("aws_guard_daily_limit")
        if sum(stamp > moment - 60 for stamp in calls) >= MINUTE_LIMIT:
            raise GuardBlocked("aws_guard_rate_limit")
        ledger.calls = [*calls, moment]
        ledger.last_seen = moment
        _store(ledger)


def record_failure(*, now: int | None = None) -> None:
    """Trip an increasing cooldown. No automatic retry or sleep is performed."""
    with _locked():
        ledger = _load()
        moment = _clock(now, ledger)
        ledger.failures = min(5, ledger.failures + 1)
        ledger.cooldown_until = moment + min(900, 60 * 2 ** (ledger.failures - 1))
        ledger.last_seen = moment
        _store(ledger)


def set_stopped(stopped: bool) -> None:
    with _locked():
        marker = STATE_DIR / "STOP"
        if stopped:
            marker.touch(exist_ok=True)
        else:
            marker.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stop", "resume"))
    args = parser.parse_args()
    try:
        set_stopped(args.action == "stop")
    except GuardBlocked as exc:
        print(json.dumps({"status": "blocked", "code": str(exc)}))
        return 2
    print(json.dumps({"status": "stopped" if args.action == "stop" else "resumed"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
