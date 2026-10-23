"""
TREMOR — Alert lifecycle manager.

A small FSM, independent of the detectors. Each tick every detector hands it a Signal;
it answers with the alerts to emit.

- Dedup: at most one open incident per (signal_type, service, template_id)
- Emit only when severity rises above the highest severity already emitted for the
  incident: OPEN first, then ESCALATED. Drops and rebounds below the peak are silent.
- Resolve after clear_windows consecutive clear ticks (the detector decides what "clear"
  means, e.g. z < clear_z), or when the detector asks (silence, new pattern). Neutral
  ticks (insufficient data) neither advance nor reset the count.
- Cooldown: re-opening within alert_cooldown_s of resolving reuses the incident_id
- ack(): status ACKED; a later escalation emits ESCALATED and clears the ack
- silence(): status SILENCED; the key keeps tracking but emits nothing until the silence
  ends, except RESOLVED, which is always emitted

Owner: Kostubh (Phase 3)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.config import Settings
    from app.core.severity import Severity


class AlertStatus(StrEnum):
    """Alert lifecycle states."""

    OPEN = "OPEN"
    ESCALATED = "ESCALATED"
    ACKED = "ACKED"
    SILENCED = "SILENCED"
    RESOLVED = "RESOLVED"


class SignalType(StrEnum):
    """Types of anomaly signals."""

    ERROR_RATE = "ERROR_RATE"
    SILENCE = "SILENCE"
    NEW_PATTERN = "NEW_PATTERN"
    LATENCY = "LATENCY"


@dataclass
class TemplateHint:
    template_id: str
    pattern: str
    count: int


@dataclass
class TimelineEvent:
    ts: float
    status: AlertStatus
    reason: str


@dataclass
class Alert:
    id: str
    service: str
    signal_type: SignalType
    status: AlertStatus
    severity: str
    explanation: dict[str, Any] = field(default_factory=dict)
    timeline: list[TimelineEvent] = field(default_factory=list)
    samples: list[str] = field(default_factory=list)
    top_templates: list[TemplateHint] = field(default_factory=list)
    created_at: float = 0.0
    updated_at: float = 0.0
    # Detection details (optional so existing constructors keep working)
    incident_id: str | None = None
    value: float | None = None  # error rate, p95 latency (ms) or silent seconds
    baseline: float | None = None  # mu the value was judged against
    z_score: float | None = None
    lines: int | None = None
    errors: int | None = None
    reason: str = ""
    template_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "service": self.service,
            "signal_type": self.signal_type.value,
            "status": self.status.value,
            "severity": self.severity,
            "explanation": self.explanation,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "incident_id": self.incident_id,
            "value": self.value,
            "baseline": self.baseline,
            "z_score": self.z_score,
            "lines": self.lines,
            "errors": self.errors,
            "reason": self.reason,
            "template_id": self.template_id,
        }


@dataclass(frozen=True, slots=True)
class Signal:
    """One detector's verdict for one key on one tick."""

    signal_type: SignalType
    service: str
    severity: Severity | None
    clear: bool | None = None  # True counts toward resolution, False resets, None neutral
    resolve: bool = False  # detector's own rule says the incident is over
    template_id: str | None = None
    value: float | None = None
    baseline: float | None = None
    z_score: float | None = None
    lines: int | None = None
    errors: int | None = None
    reason: str = ""


IncidentKey = tuple[SignalType, str, str | None]


@dataclass
class _Incident:
    incident_id: str
    key: IncidentKey
    peak: Severity
    created_at: float
    last: Signal
    emitted_peak: Severity | None = None
    escalated: bool = False
    acked: bool = False
    clear_count: int = 0
    timeline: list[TimelineEvent] = field(default_factory=list)


def _key(sig: Signal) -> IncidentKey:
    return (sig.signal_type, sig.service, sig.template_id)


class AlertManager:
    def __init__(self, cfg: Settings, id_factory: Callable[[], str] | None = None) -> None:
        self.cfg = cfg
        self._new_id = id_factory or (lambda: uuid.uuid4().hex)
        self._open: dict[IncidentKey, _Incident] = {}
        self._by_id: dict[str, _Incident] = {}
        self._recent: dict[IncidentKey, tuple[_Incident, float]] = (
            {}
        )  # key -> (incident, resolved_at)
        self._mutes: dict[IncidentKey, float] = {}  # key -> silenced until

    # ── Tick input ───────────────────────────────────────────────────

    def process(self, sig: Signal, now: float) -> list[Alert]:
        key = _key(sig)
        inc = self._open.get(key)
        if inc is None:
            if sig.severity is None:
                return []
            inc = self._open_incident(sig, now)
        inc.last = sig

        if sig.severity is not None and sig.severity > inc.peak:
            inc.peak = sig.severity
        if sig.clear is True:
            inc.clear_count += 1
        elif sig.clear is False:
            inc.clear_count = 0

        if sig.resolve or inc.clear_count >= self.cfg.clear_windows:
            return [self._resolve(inc, now)]
        return self._maybe_emit(inc, now)

    # ── API actions ──────────────────────────────────────────────────

    def ack(self, incident_id: str, now: float) -> Alert:
        """Acknowledge an open incident. Raises KeyError if it is not open."""
        inc = self._by_id[incident_id]
        inc.acked = True
        inc.timeline.append(TimelineEvent(now, AlertStatus.ACKED, "acknowledged"))
        return self._snapshot(inc, now)

    def silence(self, incident_id: str, until: float, now: float) -> Alert:
        """Mute an open incident's key until `until`. Raises KeyError if it is not open."""
        inc = self._by_id[incident_id]
        self._mutes[inc.key] = until
        inc.timeline.append(TimelineEvent(now, AlertStatus.SILENCED, f"silenced until {until}"))
        return self._snapshot(inc, now)

    # ── Queries ──────────────────────────────────────────────────────

    def is_open(
        self, signal_type: SignalType, service: str = "*", template_id: str | None = None
    ) -> bool:
        return (signal_type, service, template_id) in self._open

    def active(self, now: float) -> list[Alert]:
        return [self._snapshot(inc, now) for inc in self._open.values()]

    def highest_open_severity(self) -> Severity | None:
        return max((inc.peak for inc in self._open.values()), default=None)

    # ── Internals ────────────────────────────────────────────────────

    def _open_incident(self, sig: Signal, now: float) -> _Incident:
        key = _key(sig)
        assert sig.severity is not None
        recent = self._recent.pop(key, None)
        if recent is not None and now - recent[1] <= self.cfg.alert_cooldown_s:
            old = recent[0]
            inc = _Incident(
                old.incident_id, key, sig.severity, old.created_at, sig, timeline=old.timeline
            )
        else:
            inc = _Incident(self._new_id(), key, sig.severity, now, sig)
        self._open[key] = inc
        self._by_id[inc.incident_id] = inc
        return inc

    def _muted(self, key: IncidentKey, now: float) -> bool:
        until = self._mutes.get(key)
        if until is None:
            return False
        if now >= until:
            del self._mutes[key]
            return False
        return True

    def _status(self, inc: _Incident, now: float) -> AlertStatus:
        if self._muted(inc.key, now):
            return AlertStatus.SILENCED
        if inc.acked:
            return AlertStatus.ACKED
        return AlertStatus.ESCALATED if inc.escalated else AlertStatus.OPEN

    def _maybe_emit(self, inc: _Incident, now: float) -> list[Alert]:
        if self._muted(inc.key, now):
            return []
        if inc.emitted_peak is not None and inc.peak <= inc.emitted_peak:
            return []
        status = AlertStatus.OPEN if inc.emitted_peak is None else AlertStatus.ESCALATED
        inc.escalated = inc.escalated or status is AlertStatus.ESCALATED
        inc.acked = False
        inc.emitted_peak = inc.peak
        inc.timeline.append(TimelineEvent(now, status, inc.last.reason))
        return [self._snapshot(inc, now, status)]

    def _resolve(self, inc: _Incident, now: float) -> Alert:
        del self._open[inc.key]
        del self._by_id[inc.incident_id]
        self._recent[inc.key] = (inc, now)
        reason = f"resolved: {inc.last.reason}" if inc.last.reason else "resolved"
        inc.timeline.append(TimelineEvent(now, AlertStatus.RESOLVED, reason))
        return self._snapshot(inc, now, AlertStatus.RESOLVED, reason)

    def _snapshot(
        self,
        inc: _Incident,
        now: float,
        status: AlertStatus | None = None,
        reason: str | None = None,
    ) -> Alert:
        sig = inc.last
        signal_type, service, template_id = inc.key
        return Alert(
            id=self._new_id(),
            service=service,
            signal_type=signal_type,
            status=status or self._status(inc, now),
            severity=inc.peak.name,
            timeline=list(inc.timeline),
            created_at=inc.created_at,
            updated_at=now,
            incident_id=inc.incident_id,
            value=sig.value,
            baseline=sig.baseline,
            z_score=sig.z_score,
            lines=sig.lines,
            errors=sig.errors,
            reason=reason if reason is not None else sig.reason,
            template_id=template_id,
        )
