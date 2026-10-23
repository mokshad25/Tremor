"""
TREMOR — Arrival-time sliding window for detection.

Detection keys on when a line *arrived*, not on the timestamp written in it, so skewed
or replayed log clocks cannot distort the error rate. window.py serves per-service
event-time views; this is the single 30 s arrival window the detectors share.

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Arrival:
    ts: float  # arrival time (seconds)
    is_error: bool
    duration_ms: float | None = None


class ArrivalWindow:
    """Lines that arrived in (now - window_s, now]. O(1) amortized per line."""

    def __init__(self, window_s: float) -> None:
        self.window_s = window_s
        self._items: deque[Arrival] = deque()
        self._errors = 0

    def add(self, ts: float, is_error: bool, duration_ms: float | None = None) -> None:
        self._items.append(Arrival(ts, is_error, duration_ms))
        if is_error:
            self._errors += 1

    def evict(self, now: float) -> None:
        cutoff = now - self.window_s
        while self._items and self._items[0].ts <= cutoff:
            if self._items.popleft().is_error:
                self._errors -= 1

    @property
    def n(self) -> int:
        return len(self._items)

    @property
    def errors(self) -> int:
        return self._errors

    def latencies(self) -> list[float]:
        """Latency samples in the window; lines without duration_ms are skipped."""
        return [a.duration_ms for a in self._items if a.duration_ms is not None]
