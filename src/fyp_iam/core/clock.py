"""Time sources for deterministic tests and local verification timestamps."""

import time
from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def monotonic(self) -> float:
        """Return a monotonic timestamp in seconds."""

    def now(self) -> datetime:
        """Return an aware UTC datetime."""


class SystemClock:
    """Production clock. Tests can substitute a manual clock."""

    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(UTC)
