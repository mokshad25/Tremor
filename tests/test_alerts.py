"""
TREMOR — Alert lifecycle tests.
"""

from __future__ import annotations

import itertools

import pytest

from app.core.alerts import Alert, AlertManager, AlertStatus, Signal, SignalType
from app.core.severity import Severity
from tests.detection_helpers import make_settings

ER = SignalType.ERROR_RATE


def manager(**overrides: object) -> AlertManager:
    counter = itertools.count(1)
    return AlertManager(make_settings(**overrides), id_factory=lambda: f"id-{next(counter)}")


def sig(
    severity: Severity | None,
    clear: bool | None = False,
    signal_type: SignalType = ER,
    template_id: str | None = None,
    resolve: bool = False,
) -> Signal:
    return Signal(
        signal_type=signal_type,
        service="*",
        severity=severity,
        clear=clear,
        resolve=resolve,
        template_id=template_id,
        value=0.094,
        baseline=0.019,
        z_score=7.5,
        lines=300,
        errors=28,
        reason="error rate 9.4% vs baseline 1.9% over the last 30 s",
    )


def statuses(alerts: list[Alert]) -> list[AlertStatus]:
    return [a.status for a in alerts]


def run(m: AlertManager, signals: list[Signal], start: float = 0.0) -> list[Alert]:
    out: list[Alert] = []
    for i, s in enumerate(signals):
        out += m.process(s, start + i)
    return out


def test_nothing_without_severity() -> None:
    m = manager()
    assert m.process(sig(None, clear=False), 0.0) == []
    assert not m.is_open(ER)


def test_open_once_and_dedup() -> None:
    m = manager()
    out = run(m, [sig(Severity.INFO)] * 5)
    assert statuses(out) == [AlertStatus.OPEN]
    assert m.is_open(ER)


def test_alert_fields() -> None:
    m = manager()
    [a] = m.process(sig(Severity.WARNING), 5.0)
    assert a.severity == "WARNING"
    assert a.service == "*"
    assert a.signal_type == ER
    assert a.incident_id is not None and a.incident_id != a.id
    assert (a.value, a.baseline, a.z_score, a.lines, a.errors) == (0.094, 0.019, 7.5, 300, 28)
    assert a.reason.startswith("error rate 9.4%")
    assert a.created_at == a.updated_at == 5.0
    d = a.to_dict()
    assert d["incident_id"] == a.incident_id
    assert d["z_score"] == 7.5
    assert d["status"] == "OPEN"


def test_escalation_only_alerts() -> None:
    m = manager()
    out = run(
        m, [sig(Severity.INFO), sig(Severity.WARNING), sig(Severity.WARNING), sig(Severity.HIGH)]
    )
    assert statuses(out) == [AlertStatus.OPEN, AlertStatus.ESCALATED, AlertStatus.ESCALATED]
    assert [a.severity for a in out] == ["INFO", "WARNING", "HIGH"]
    assert len({a.incident_id for a in out}) == 1


def test_drop_and_rebound_below_peak_are_silent() -> None:
    m = manager()
    out = run(
        m,
        [
            sig(Severity.HIGH),
            sig(Severity.INFO),
            sig(None),
            sig(Severity.WARNING),
            sig(Severity.HIGH),
        ],
    )
    assert statuses(out) == [AlertStatus.OPEN]
    assert m.highest_open_severity() == Severity.HIGH


def test_resolve_after_exactly_10_clear_ticks() -> None:
    m = manager()
    m.process(sig(Severity.INFO), 0.0)
    for t in range(1, 10):
        assert m.process(sig(None, clear=True), float(t)) == []
    [a] = m.process(sig(None, clear=True), 10.0)
    assert a.status == AlertStatus.RESOLVED
    assert a.severity == "INFO"
    assert a.reason.startswith("resolved: ")
    assert not m.is_open(ER)
    assert m.highest_open_severity() is None


def test_hysteresis_band_resets_resolve_count() -> None:
    # 2 <= z < 3: detector sends severity None, clear False — neither opens nor resolves
    m = manager()
    assert m.process(sig(None, clear=False), 0.0) == []
    assert not m.is_open(ER)
    m.process(sig(Severity.INFO), 1.0)
    run(m, [sig(None, clear=True)] * 9, start=2.0)
    assert m.process(sig(None, clear=False), 11.0) == []  # z = 2.5 breaks the streak
    assert run(m, [sig(None, clear=True)] * 9, start=12.0) == []
    assert statuses(m.process(sig(None, clear=True), 21.0)) == [AlertStatus.RESOLVED]


def test_neutral_ticks_neither_advance_nor_reset() -> None:
    m = manager()
    m.process(sig(Severity.INFO), 0.0)
    run(m, [sig(None, clear=True)] * 5, start=1.0)
    assert run(m, [sig(None, clear=None)] * 20, start=6.0) == []
    assert run(m, [sig(None, clear=True)] * 4, start=26.0) == []
    assert statuses(m.process(sig(None, clear=True), 30.0)) == [AlertStatus.RESOLVED]


def test_detector_resolve_flag() -> None:
    m = manager()
    m.process(sig(Severity.HIGH, clear=None, signal_type=SignalType.SILENCE), 0.0)
    [a] = m.process(sig(None, clear=None, signal_type=SignalType.SILENCE, resolve=True), 1.0)
    assert a.status == AlertStatus.RESOLVED


def resolve(m: AlertManager, start: float) -> Alert:
    out = run(m, [sig(None, clear=True)] * 10, start=start)
    assert statuses(out) == [AlertStatus.RESOLVED]
    return out[0]


def test_cooldown_reuses_incident_id() -> None:
    m = manager()
    [first] = m.process(sig(Severity.INFO), 0.0)
    resolved = resolve(m, 1.0)  # resolved at t = 10
    assert resolved.incident_id == first.incident_id
    [again] = m.process(sig(Severity.INFO), 70.0)  # exactly 60 s later
    assert again.status == AlertStatus.OPEN
    assert again.incident_id == first.incident_id
    assert again.created_at == 0.0


def test_new_incident_after_cooldown() -> None:
    m = manager()
    [first] = m.process(sig(Severity.INFO), 0.0)
    resolve(m, 1.0)
    [again] = m.process(sig(Severity.INFO), 70.5)
    assert again.incident_id != first.incident_id


def test_separate_keys_are_separate_incidents() -> None:
    m = manager()
    np = SignalType.NEW_PATTERN
    a = m.process(sig(Severity.INFO, signal_type=np, template_id="t1"), 0.0)
    b = m.process(sig(Severity.INFO, signal_type=np, template_id="t2"), 0.0)
    c = m.process(sig(Severity.INFO), 0.0)
    assert len({x.incident_id for x in a + b + c}) == 3
    assert a[0].template_id == "t1"
    assert m.is_open(np, "*", "t2")


def test_ack_sets_status_and_escalation_clears_it() -> None:
    m = manager()
    [opened] = m.process(sig(Severity.INFO), 0.0)
    assert opened.incident_id is not None
    acked = m.ack(opened.incident_id, 1.0)
    assert acked.status == AlertStatus.ACKED
    assert acked.incident_id == opened.incident_id
    assert m.process(sig(Severity.INFO), 2.0) == []
    assert m.active(2.0)[0].status == AlertStatus.ACKED
    [esc] = m.process(sig(Severity.WARNING), 3.0)
    assert esc.status == AlertStatus.ESCALATED
    assert m.active(3.0)[0].status == AlertStatus.ESCALATED


def test_ack_unknown_incident_raises() -> None:
    with pytest.raises(KeyError):
        manager().ack("nope", 0.0)


def test_silence_mutes_until_it_ends() -> None:
    m = manager()
    [opened] = m.process(sig(Severity.INFO), 0.0)
    assert opened.incident_id is not None
    silenced = m.silence(opened.incident_id, until=10.0, now=1.0)
    assert silenced.status == AlertStatus.SILENCED
    assert m.process(sig(Severity.HIGH), 2.0) == []  # tracked, not emitted
    assert m.active(3.0)[0].status == AlertStatus.SILENCED
    [esc] = m.process(sig(Severity.WARNING), 10.0)  # silence over; HIGH not yet emitted
    assert esc.status == AlertStatus.ESCALATED
    assert esc.severity == "HIGH"


def test_silenced_incident_still_emits_resolved() -> None:
    m = manager()
    [opened] = m.process(sig(Severity.INFO), 0.0)
    assert opened.incident_id is not None
    m.silence(opened.incident_id, until=1_000.0, now=0.5)
    assert resolve(m, 1.0).status == AlertStatus.RESOLVED
    # Re-opening while the key is still muted emits nothing
    assert m.process(sig(Severity.HIGH), 20.0) == []
    assert m.active(20.0)[0].status == AlertStatus.SILENCED


def test_silence_unknown_incident_raises() -> None:
    with pytest.raises(KeyError):
        manager().silence("nope", until=5.0, now=0.0)
