"""
TREMOR — Error-rate anomaly detector.

Per 1 s tick, over the 30 s arrival window:
- r = errors / n (ERROR only; the parser folds FATAL into ERROR, WARNING is not an error)
- n < min_events: "insufficient" — no z, no baseline update, neutral for resolution
- Warm-up ("learning"): record r on warmup_ticks ticks, then seed the baseline.
  Ticks that hit the CRITICAL rule or have an incident open are not recorded.
- Afterwards: z against the previous tick's baseline with
    sigma_eff = max(sigma, sqrt(mu*(1-mu)/n), sigma_min)
  and a gated EWMA update (no open incident, z < baseline_update_max_z)
- CRITICAL: r > rate_ceiling with n >= min_events, active even during warm-up

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from app.core.alerts import Signal, SignalType
from app.core.baseline import Baseline, binomial_floor
from app.core.severity import Severity, score

if TYPE_CHECKING:
    from app.config import Settings
    from app.core.detectors.base import Observation, TickContext

DetectorState = Literal["learning", "insufficient", "active"]


@dataclass(frozen=True, slots=True)
class ErrorRateReading:
    now: float
    n: int
    errors: int
    rate: float | None  # None when the window is empty
    mu: float | None  # baseline the tick was judged against
    sigma_eff: float | None
    z: float | None
    state: DetectorState
    severity: Severity | None
    clear: bool | None  # True counts toward resolution, False resets it, None is neutral
    updated: bool = False  # baseline moved on this tick

    def signal(self, service: str, window_s: int) -> Signal:
        return Signal(
            signal_type=SignalType.ERROR_RATE,
            service=service,
            severity=self.severity,
            clear=self.clear,
            value=self.rate,
            baseline=self.mu,
            z_score=self.z,
            lines=self.n,
            errors=self.errors,
            reason=self.reason(window_s),
        )

    def reason(self, window_s: int) -> str:
        if self.rate is None:
            return f"no lines over the last {window_s} s"
        base = "baseline still learning" if self.mu is None else f"baseline {self.mu:.1%}"
        return f"error rate {self.rate:.1%} vs {base} over the last {window_s} s"


class ErrorRateDetector:
    signal_type = SignalType.ERROR_RATE

    def __init__(self, cfg: Settings, service: str = "*") -> None:
        self.cfg = cfg
        self.service = service
        self.baseline = Baseline(
            alpha=cfg.alpha,
            warmup_ticks=cfg.warmup_ticks,
            sigma_min=cfg.sigma_min,
            noise_floor=binomial_floor,
            max_update_z=cfg.baseline_update_max_z,
        )
        self.last: ErrorRateReading | None = None

    def observe(self, obs: Observation) -> None:
        """Counting happens in the shared ArrivalWindow; nothing to do per line."""

    def evaluate(self, ctx: TickContext) -> list[Signal]:
        incident_open = ctx.is_open(self.signal_type, None)
        reading = self.measure(ctx.now, ctx.window.n, ctx.window.errors, incident_open)
        return [reading.signal(self.service, self.cfg.detection_window_s)]

    def measure(self, now: float, n: int, errors: int, incident_open: bool) -> ErrorRateReading:
        """Judge one tick and apply the gated baseline update. Also stored as `last`."""
        self.last = self._measure(now, n, errors, incident_open)
        return self.last

    def _measure(self, now: float, n: int, errors: int, incident_open: bool) -> ErrorRateReading:
        cfg = self.cfg
        rate = errors / n if n > 0 else None
        mu = self.baseline.mu

        if rate is None or n < cfg.min_events:
            return ErrorRateReading(
                now, n, errors, rate, mu, None, None, "insufficient", None, None
            )

        critical = rate > cfg.rate_ceiling
        if not self.baseline.seeded:
            if not critical and not incident_open:
                self.baseline.add_warmup(rate)
            severity = Severity.CRITICAL if critical else None
            return ErrorRateReading(
                now, n, errors, rate, None, None, None, "learning", severity, not critical
            )

        sigma_eff = self.baseline.sigma_eff(n)
        z = self.baseline.z(rate, n)
        severity = score(z, cfg, rate=rate, n=n)
        updated = False if critical else self.baseline.update(rate, z, incident_open)
        clear = z < cfg.clear_z and not critical
        return ErrorRateReading(
            now, n, errors, rate, mu, sigma_eff, z, "active", severity, clear, updated
        )
