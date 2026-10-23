"""
TREMOR — Bucketed sliding window engine.

Responsibilities:
- Per-service deque of 1-second buckets (total, errors, latency_samples)
- Derived views over 10s, 60s, 300s windows: rate, total, errors, volume_per_s
- Handle out-of-order events within lateness tolerance
- Drop and count events beyond lateness tolerance
- Evict on every tick, not only on new events
- O(1) amortized per event (property-tested with hypothesis)

Owner: Mokshad (Phase 1)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from app.clock import Clock
    from app.ingest.parser import LogEvent


@dataclass(slots=True)
class Bucket:
    ts: int  # Second-aligned timestamp
    total: int = 0
    errors: int = 0
    latency_samples: list[float] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class WindowView:
    window_s: int
    rate: float
    total: int
    errors: int
    volume_per_s: float


class WindowEngine:
    """Per-service 1-second buckets with derived 10s/60s/300s views."""

    def __init__(
        self, clock: Clock, window_sizes: Sequence[int] = (10, 60, 300), lateness_s: int = 5
    ) -> None:
        self.clock = clock
        self.window_sizes = sorted(window_sizes)
        self.max_window = max(self.window_sizes)
        self.lateness_s = lateness_s

        # service -> deque of Buckets
        self._buckets: dict[str, deque[Bucket]] = {}
        # Keep track of the current time for eviction
        self._current_ts: int = 0

    def _get_or_create_bucket(self, service: str, event_ts_s: int) -> Bucket | None:
        if service not in self._buckets:
            self._buckets[service] = deque()

        buckets = self._buckets[service]

        # If queue is empty, just append
        if not buckets:
            b = Bucket(ts=event_ts_s)
            buckets.append(b)
            return b

        latest_ts = buckets[-1].ts

        # Check lateness
        if event_ts_s < self._current_ts - self.lateness_s:
            # Dropped due to being too late
            return None

        if event_ts_s == latest_ts:
            return buckets[-1]

        if event_ts_s > latest_ts:
            # Fill gaps if needed? Not necessary, we only store buckets that have data
            b = Bucket(ts=event_ts_s)
            buckets.append(b)
            return b

        # Out of order but within lateness tolerance. Find the right bucket.
        # Since lateness is small, linear search from the end is O(1)
        for i in range(len(buckets) - 1, -1, -1):
            if buckets[i].ts == event_ts_s:
                return buckets[i]
            if buckets[i].ts < event_ts_s:
                # Need to insert
                b = Bucket(ts=event_ts_s)
                buckets.insert(i + 1, b)
                return b

        # Insert at the beginning
        b = Bucket(ts=event_ts_s)
        buckets.appendleft(b)
        return b

    def add_event(self, event: LogEvent) -> None:
        """Count an event in its 1-second bucket; drop it if beyond lateness tolerance."""
        event_ts_s = int(event.ts)
        # Update our perceived current time if this event is the newest we've seen
        if event_ts_s > self._current_ts:
            self._current_ts = event_ts_s

        bucket = self._get_or_create_bucket(event.service, event_ts_s)
        if bucket is None:
            # Dropped event (too late)
            return

        bucket.total += 1
        if event.level == "ERROR":
            bucket.errors += 1
        if event.duration_ms is not None:
            bucket.latency_samples.append(event.duration_ms)

    def tick(self) -> None:
        """Advance time and evict old buckets."""
        now_s = int(self.clock.now())
        if now_s > self._current_ts:
            self._current_ts = now_s

        cutoff = self._current_ts - self.max_window

        # Evict old buckets
        for service, buckets in list(self._buckets.items()):
            while buckets and buckets[0].ts <= cutoff:
                buckets.popleft()
            if not buckets:
                del self._buckets[service]

    def get_views(self, service: str) -> list[WindowView]:
        """Return one view per configured window size, smallest first."""
        views: list[WindowView] = []
        buckets = self._buckets.get(service, deque())

        for w_size in self.window_sizes:
            cutoff = self._current_ts - w_size

            total = 0
            errors = 0
            for b in reversed(buckets):
                if b.ts <= cutoff:
                    break
                total += b.total
                errors += b.errors

            rate = (errors / total) if total > 0 else 0.0
            volume_per_s = total / float(w_size)

            views.append(
                WindowView(
                    window_s=w_size,
                    rate=rate,
                    total=total,
                    errors=errors,
                    volume_per_s=volume_per_s,
                )
            )

        return views
