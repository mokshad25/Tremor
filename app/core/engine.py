"""
TREMOR — Detection engine: one call per tick.

The pipeline feeds every parsed line to observe() with its arrival time (and the shared
TemplateMiner's verdict), and calls tick(now) once per second. tick() evicts the arrival
window, runs every detector, pushes their signals through the alert lifecycle, and
returns the Tick for the chart plus any alerts to fan out to sinks.

Pure and synchronous: no I/O and no clock reads; time is always passed in.

Owner: Kostubh (Phase 3)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from app.core.alerts import Alert, AlertManager, SignalType
from app.core.arrivals import ArrivalWindow
from app.core.baseline import BaselineStore
from app.core.detectors.base import Detector, Observation, TickContext
from app.core.detectors.error_rate import ErrorRateDetector, ErrorRateReading
from app.core.detectors.silence import SilenceDetector

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.config import Settings
    from app.ingest.parser import LogEvent

TickState = Literal["learning", "insufficient", "active", "incident"]


@dataclass(frozen=True, slots=True)
class Tick:
    """Per-second snapshot for the live chart; produced on every tick."""

    ts: str  # UTC ISO 8601 of `now`
    error_rate: float | None  # None when no lines are in the window
    baseline: float | None  # always mu: the value this tick's z was judged against
    z: float | None
    lines: int  # lines in the 30 s window
    state: TickState  # incident > insufficient > learning > active
    severity: str | None  # highest severity among open incidents
    is_anomaly: bool  # an incident is open

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "error_rate": self.error_rate,
            "baseline": self.baseline,
            "z": self.z,
            "lines": self.lines,
            "state": self.state,
            "severity": self.severity,
            "is_anomaly": self.is_anomaly,
        }


@dataclass(frozen=True, slots=True)
class TickResult:
    tick: Tick
    alerts: list[Alert] = field(default_factory=list)  # emitted this tick, in order
    error_rate: ErrorRateReading | None = None  # full numbers, for tools and debugging


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


class DetectionEngine:
    def __init__(
        self,
        cfg: Settings,
        service: str = "*",
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.cfg = cfg
        self.service = service
        self.window = ArrivalWindow(cfg.detection_window_s)
        self.alerts = AlertManager(cfg, id_factory)
        self.baselines = BaselineStore()

        self.error_rate = ErrorRateDetector(cfg, service)
        self.baselines.register(service, SignalType.ERROR_RATE.value, self.error_rate.baseline)
        self.detectors: list[Detector] = [self.error_rate, SilenceDetector(cfg, service)]

    @property
    def warmed_up(self) -> bool:
        return self.baselines.is_warm(self.service)

    def observe(
        self,
        event: LogEvent,
        arrival: float,
        template_id: str | None = None,
        is_new_template: bool = False,
    ) -> None:
        """Record one parsed line. `arrival` is when TREMOR received it, not event.ts."""
        obs = Observation(
            arrival=arrival,
            level=event.level,
            duration_ms=event.duration_ms,
            template_id=template_id,
            is_new_template=is_new_template,
            warmed_up=self.warmed_up,
        )
        self.window.add(arrival, event.level == "ERROR", event.duration_ms)
        for det in self.detectors:
            det.observe(obs)

    def tick(self, now: float) -> TickResult:
        """Run every detector for the second ending at `now`."""
        self.window.evict(now)
        ctx = TickContext(
            now=now,
            window=self.window,
            warmed_up=self.warmed_up,
            is_open=lambda sig, template_id: self.alerts.is_open(sig, self.service, template_id),
        )
        alerts: list[Alert] = []
        for det in self.detectors:
            for sig in det.evaluate(ctx):
                alerts += self.alerts.process(sig, now)

        reading = self.error_rate.last
        assert reading is not None
        severity = self.alerts.highest_open_severity()
        state: TickState = "incident" if severity is not None else reading.state
        tick = Tick(
            ts=utc_iso(now),
            error_rate=reading.rate,
            baseline=reading.mu,
            z=reading.z,
            lines=reading.n,
            state=state,
            severity=severity.name if severity is not None else None,
            is_anomaly=severity is not None,
        )
        return TickResult(tick, alerts, reading)

    # ── For the API ──────────────────────────────────────────────────

    def ack(self, incident_id: str, now: float) -> Alert:
        return self.alerts.ack(incident_id, now)

    def silence(self, incident_id: str, until: float, now: float) -> Alert:
        return self.alerts.silence(incident_id, until, now)

    def active(self, now: float) -> list[Alert]:
        return self.alerts.active(now)
