"""
TREMOR — New/rare log pattern detector.

Novelty itself is the shared TemplateMiner's call (app/core/templates.py): a template is
new if it was first seen after the miner's warm-up, or a rare template resurfaced in a
surge, within the last novelty TTL. The miner's verdict arrives with every line as
Observation.is_new_template; this detector only decides when novelty is worth paging for.

- Lines are counted only after this service's warm-up (Observation.warmed_up).
- Per tick, for each template flagged new: count its new-flagged lines in the 30 s
  arrival window. At new_pattern_min_count or more, signal WARNING, or HIGH when any of
  those lines is an ERROR (a never-seen error message). A one-off new line never pages.
- One incident per template (Signal.template_id).
- Resolve once no new-flagged line of the template has arrived for
  new_pattern_resolve_s. This also covers the template ageing out of the miner's
  novelty TTL: it is then part of normal traffic.

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.core.alerts import Signal, SignalType
from app.core.severity import Severity

if TYPE_CHECKING:
    from app.config import Settings
    from app.core.detectors.base import Observation, TickContext


@dataclass(slots=True)
class _Seen:
    """New-flagged arrivals of one template: (arrival, is_error), oldest first."""

    arrivals: deque[tuple[float, bool]] = field(default_factory=deque)
    errors: int = 0
    last_arrival: float = 0.0


class NewPatternDetector:
    signal_type = SignalType.NEW_PATTERN

    def __init__(self, cfg: Settings, service: str = "*") -> None:
        self.cfg = cfg
        self.service = service
        self._seen: dict[str, _Seen] = {}

    def observe(self, obs: Observation) -> None:
        if not (obs.is_new_template and obs.warmed_up and obs.template_id):
            return
        seen = self._seen.setdefault(obs.template_id, _Seen())
        is_error = obs.level == "ERROR"
        seen.arrivals.append((obs.arrival, is_error))
        seen.errors += is_error
        seen.last_arrival = max(seen.last_arrival, obs.arrival)

    def evaluate(self, ctx: TickContext) -> list[Signal]:
        cfg = self.cfg
        cutoff = ctx.now - cfg.detection_window_s
        signals: list[Signal] = []
        for tid in sorted(self._seen):
            seen = self._seen[tid]
            while seen.arrivals and seen.arrivals[0][0] <= cutoff:
                seen.errors -= seen.arrivals.popleft()[1]
            n = len(seen.arrivals)
            idle = ctx.now - seen.last_arrival
            if idle >= cfg.new_pattern_resolve_s:
                del self._seen[tid]
                if ctx.is_open(self.signal_type, tid):
                    reason = f"new log pattern {tid} not seen for {idle:.0f} s"
                    signals.append(self._signal(tid, None, n, seen.errors, reason, resolve=True))
                continue
            if n >= cfg.new_pattern_min_count:
                severity = Severity.HIGH if seen.errors else Severity.WARNING
                kind = "error pattern" if seen.errors else "log pattern"
                reason = f"new {kind} {tid}: {n} lines in the last {cfg.detection_window_s} s"
                signals.append(self._signal(tid, severity, n, seen.errors, reason))
            elif ctx.is_open(self.signal_type, tid):
                reason = f"new log pattern {tid}: {n} lines in the last {cfg.detection_window_s} s"
                signals.append(self._signal(tid, None, n, seen.errors, reason))
        return signals

    def _signal(
        self,
        tid: str,
        severity: Severity | None,
        n: int,
        errors: int,
        reason: str,
        *,
        resolve: bool = False,
    ) -> Signal:
        return Signal(
            self.signal_type,
            self.service,
            severity,
            resolve=resolve,
            template_id=tid,
            value=float(n),
            lines=n,
            errors=errors,
            reason=reason,
        )
