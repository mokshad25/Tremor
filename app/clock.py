"""
TREMOR — Injectable clock for deterministic testing.

Design principle: No direct time.time() or datetime.now() in core/.
All time-dependent code receives a Clock instance.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    """Protocol for injectable clocks. Implemented by SystemClock and FakeClock."""

    def now(self) -> float:
        """Return the current time as a Unix timestamp (seconds since epoch)."""
        ...


class SystemClock:
    """Production clock using the real system time."""

    def now(self) -> float:
        return time.time()


class FakeClock:
    """
    Deterministic clock for testing.

    Starts at a given time and can be advanced manually.
    """

    def __init__(self, start: float = 0.0) -> None:
        self._time = start

    def now(self) -> float:
        return self._time

    def advance(self, seconds: float) -> None:
        """Advance the clock by the given number of seconds."""
        if seconds < 0:
            raise ValueError("Cannot advance clock backwards")
        self._time += seconds

    def set(self, timestamp: float) -> None:
        """Set the clock to an exact timestamp."""
        self._time = timestamp
