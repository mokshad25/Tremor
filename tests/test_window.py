"""
TREMOR — Window engine tests.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis.strategies import integers, lists

from app.clock import FakeClock
from app.core.window import WindowEngine
from app.ingest.parser import LogEvent


def test_window_basic_ingestion() -> None:
    clock = FakeClock(start=100.0)
    engine = WindowEngine(clock, window_sizes=[10, 60], lateness_s=5)

    # Add an event at t=100
    engine.add_event(LogEvent(ts=100.0, level="INFO", service="svc", message=""))
    engine.add_event(LogEvent(ts=100.0, level="ERROR", service="svc", message=""))

    views = engine.get_views("svc")
    assert len(views) == 2

    # 10s window
    assert views[0].window_s == 10
    assert views[0].total == 2
    assert views[0].errors == 1
    assert views[0].rate == 0.5
    assert views[0].volume_per_s == 0.2  # 2 / 10


def test_window_eviction() -> None:
    clock = FakeClock(start=100.0)
    engine = WindowEngine(clock, window_sizes=[10], lateness_s=5)

    # Event at t=100
    engine.add_event(LogEvent(ts=100.0, level="ERROR", service="svc", message=""))

    # View at t=100
    views = engine.get_views("svc")
    assert views[0].total == 1

    # Advance clock to t=115 (event is now 15s old, > 10s window)
    clock.set(115.0)
    engine.tick()

    # View at t=115
    views = engine.get_views("svc")
    assert views[0].total == 0


def test_window_out_of_order() -> None:
    clock = FakeClock(start=100.0)
    engine = WindowEngine(clock, window_sizes=[10], lateness_s=5)

    # Latest event pushes _current_ts to 100
    engine.add_event(LogEvent(ts=100.0, level="INFO", service="svc", message=""))

    # Out of order but within lateness (t=98)
    engine.add_event(LogEvent(ts=98.0, level="ERROR", service="svc", message=""))

    views = engine.get_views("svc")
    assert views[0].total == 2
    assert views[0].errors == 1

    # Too late (t=90)
    engine.add_event(LogEvent(ts=90.0, level="ERROR", service="svc", message=""))

    views_after = engine.get_views("svc")
    # Total is still 2 because the late event was dropped
    assert views_after[0].total == 2


@settings(max_examples=50)
@given(event_timestamps=lists(integers(min_value=100, max_value=200), min_size=1, max_size=100))
def test_hypothesis_window_vs_naive(event_timestamps: list[int]) -> None:
    """Property test comparing sliding window to a naive reference implementation."""
    clock = FakeClock(start=max(event_timestamps))
    engine = WindowEngine(clock, window_sizes=[30], lateness_s=100)  # Large lateness to avoid drops

    for ts in event_timestamps:
        engine.add_event(LogEvent(ts=float(ts), level="ERROR", service="svc", message=""))

    engine.tick()
    view = engine.get_views("svc")[0]

    # Naive reference implementation
    current_ts = int(clock.now())
    naive_total = sum(1 for ts in event_timestamps if current_ts - 30 < ts <= current_ts)

    assert view.total == naive_total
    assert view.errors == naive_total
