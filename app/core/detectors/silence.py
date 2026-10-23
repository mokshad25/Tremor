"""
TREMOR — Traffic silence detector.

After warm-up, if no line has arrived for silence_seconds (judged from the last arrival
time, not the window), raise a HIGH "log stream silent" signal. The incident resolves on
the first tick after lines return. A stream going quiet is often worse than errors.

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.alerts import Signal, SignalType
from app.core.severity import Severity

if TYPE_CHECKING:
    from app.config import Settings
    from app.core.detectors.base import Observation, TickContext


class SilenceDetector:
    signal_type = SignalType.SILENCE

    def __init__(self, cfg: Settings, service: str = "*") -> None:
        self.cfg = cfg
        self.service = service
        self.last_arrival: float | None = None

    def observe(self, obs: Observation) -> None:
        if self.last_arrival is None or obs.arrival > self.last_arrival:
            self.last_arrival = obs.arrival

    def evaluate(self, ctx: TickContext) -> list[Signal]:
        if not ctx.warmed_up or self.last_arrival is None:
            return [Signal(self.signal_type, self.service, None)]
        gap = ctx.now - self.last_arrival
        if gap >= self.cfg.silence_seconds:
            reason = f"log stream silent: no lines for {gap:.0f} s"
            return [Signal(self.signal_type, self.service, Severity.HIGH, value=gap, reason=reason)]
        return [
            Signal(
                self.signal_type,
                self.service,
                None,
                resolve=True,
                value=gap,
                reason="log stream resumed",
            )
        ]
