"""
TREMOR — Clock tests.

Validates the Clock protocol, SystemClock, and FakeClock implementations.
"""

from __future__ import annotations

import time

import pytest

from app.clock import FakeClock, SystemClock


class TestSystemClock:
    """SystemClock returns real wall time."""

    def test_now_returns_float(self) -> None:
        clock = SystemClock()
        result = clock.now()
        assert isinstance(result, float)

    def test_now_is_close_to_time(self) -> None:
        clock = SystemClock()
        before = time.time()
        result = clock.now()
        after = time.time()
        assert before <= result <= after


class TestFakeClock:
    """FakeClock is deterministic and manually controlled."""

    def test_starts_at_given_time(self) -> None:
        clock = FakeClock(start=42.0)
        assert clock.now() == 42.0

    def test_default_start_is_zero(self) -> None:
        clock = FakeClock()
        assert clock.now() == 0.0

    def test_advance_moves_time_forward(self) -> None:
        clock = FakeClock(start=100.0)
        clock.advance(10.5)
        assert clock.now() == 110.5

    def test_advance_is_cumulative(self) -> None:
        clock = FakeClock(start=0.0)
        clock.advance(5.0)
        clock.advance(3.0)
        assert clock.now() == 8.0

    def test_advance_negative_raises(self) -> None:
        clock = FakeClock(start=100.0)
        with pytest.raises(ValueError, match="backwards"):
            clock.advance(-1.0)

    def test_set_overrides_time(self) -> None:
        clock = FakeClock(start=0.0)
        clock.set(999.0)
        assert clock.now() == 999.0

    def test_now_is_stable_without_advance(self) -> None:
        clock = FakeClock(start=50.0)
        assert clock.now() == clock.now() == 50.0
