"""
TREMOR — Latency anomaly detector.

Per 1 s tick, over the 30 s arrival window:
- Only lines with duration_ms count; a service that never logs latency stays
  "insufficient" forever and never alerts.
- p = latency_percentile (p95) of the window's samples, nearest rank
- n < min_events samples: "insufficient" — no z, no baseline update, neutral for resolution
- Warm-up ("learning"): record p on warmup_ticks ticks, then seed the baseline.
  Ticks with an incident open are not recorded. No alert while learning.
- Afterwards: z against the previous tick's baseline with
    sigma_eff = max(sigma, latency_floor_frac * mu, latency_sigma_min_ms)
  so a +30% p95 is z = 3 at the default 10% floor however steady the baseline was.
  Same severity thresholds, gated EWMA update and clear rule as the error-rate detector.

There is no CRITICAL rule: latency has no natural ceiling like a 50% error rate.

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from app.core.alerts import Signal, SignalType
from app.core.baseline import Baseline, relative_floor
from app.core.severity import Severity, score

if TYPE_CHECKING:
    from app.config import Settings
    from app.core.detectors.base import Observation, TickContext

DetectorState = Literal["learning", "insufficient", "active"]


def percentile(samples: list[float], q: float) -> float:
    """Nearest-rank q-quantile of a non-empty sample (q in (0, 1])."""
    ordered = sorted(samples)
    rank = max(math.ceil(q * len(ordered)), 1)
    return ordered[rank - 1]


@dataclass(frozen=True, slots=True)
class LatencyReading:
    now: float
    n: int  # latency samples in the window
    p: float | None  # window percentile in ms; None when there are no samples
    mu: float | None  # baseline the tick was judged against
    sigma_eff: float | None
    z: float | None
    state: DetectorState
    severity: Severity | None
    clear: bool | None  # True counts toward resolution, False resets it, None is neutral
    updated: bool = False  # baseline moved on this tick

    def signal(self, service: str, window_s: int, q: float) -> Signal:
        return Signal(
            signal_type=SignalType.LATENCY,
            service=service,
            severity=self.severity,
            clear=self.clear,
            value=self.p,
            baseline=self.mu,
            z_score=self.z,
            lines=self.n,
            reason=self.reason(window_s, q),
        )

    def reason(self, window_s: int, q: float) -> str:
        name = f"p{q * 100:g}"
        if self.p is None:
            return f"no latency samples over the last {window_s} s"
        base = "baseline still learning" if self.mu is None else f"baseline {self.mu:.0f} ms"
        return f"{name} latency {self.p:.0f} ms vs {base} over the last {window_s} s"


class LatencyDetector:
    signal_type = SignalType.LATENCY

    def __init__(self, cfg: Settings, service: str = "*") -> None:
        self.cfg = cfg
        self.service = service
        self.baseline = Baseline(
            alpha=cfg.alpha,
            warmup_ticks=cfg.warmup_ticks,
            sigma_min=cfg.latency_sigma_min_ms,
            noise_floor=relative_floor(cfg.latency_floor_frac),
            max_update_z=cfg.baseline_update_max_z,
        )
        self.last: LatencyReading | None = None

    def observe(self, obs: Observation) -> None:
        """Samples are kept in the shared ArrivalWindow; nothing to do per line."""

    def evaluate(self, ctx: TickContext) -> list[Signal]:
        incident_open = ctx.is_open(self.signal_type, None)
        reading = self.measure(ctx.now, ctx.window.latencies(), incident_open)
        cfg = self.cfg
        return [reading.signal(self.service, cfg.detection_window_s, cfg.latency_percentile)]

    def measure(self, now: float, samples: list[float], incident_open: bool) -> LatencyReading:
        """Judge one tick and apply the gated baseline update. Also stored as `last`."""
        self.last = self._measure(now, samples, incident_open)
        return self.last

    def _measure(self, now: float, samples: list[float], incident_open: bool) -> LatencyReading:
        cfg = self.cfg
        n = len(samples)
        p = percentile(samples, cfg.latency_percentile) if n > 0 else None
        mu = self.baseline.mu

        if p is None or n < cfg.min_events:
            return LatencyReading(now, n, p, mu, None, None, "insufficient", None, None)

        if not self.baseline.seeded:
            if not incident_open:
                self.baseline.add_warmup(p)
            return LatencyReading(now, n, p, None, None, None, "learning", None, True)

        sigma_eff = self.baseline.sigma_eff(n)
        z = self.baseline.z(p, n)
        severity = score(z, cfg)
        updated = self.baseline.update(p, z, incident_open)
        clear = z < cfg.clear_z
        return LatencyReading(now, n, p, mu, sigma_eff, z, "active", severity, clear, updated)
