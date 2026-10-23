"""
TREMOR — Detection engine tests: Tick on every second, state precedence, API pass-throughs.
"""

from __future__ import annotations

import itertools

from app.core.alerts import AlertStatus, SignalType
from app.core.engine import DetectionEngine, utc_iso
from app.ingest.parser import LogEvent
from tests.detection_helpers import make_settings

OK = LogEvent(ts=0.0, level="INFO", service="svc", message="ok")
WARN = LogEvent(ts=0.0, level="WARNING", service="svc", message="slow")
ERR = LogEvent(ts=0.0, level="ERROR", service="svc", message="boom")


def engine() -> DetectionEngine:
    counter = itertools.count(1)
    return DetectionEngine(make_settings(), id_factory=lambda: f"id-{next(counter)}")


def feed(eng: DetectionEngine, sec: int, errors: int, lines: int = 10) -> None:
    """`lines` lines arriving in (sec, sec + 1], the first `errors` of them ERROR."""
    for k in range(lines):
        eng.observe(ERR if k < errors else OK, sec + (k + 1) / lines)


def test_tick_every_second_even_when_empty() -> None:
    eng = engine()
    res = eng.tick(1.0)
    assert res.tick.state == "insufficient"
    assert res.tick.lines == 0
    assert res.tick.error_rate is None
    assert res.tick.ts == utc_iso(1.0) == "1970-01-01T00:00:01+00:00"
    assert res.alerts == []


def test_warning_is_not_an_error() -> None:
    eng = engine()
    for k in range(20):
        eng.observe(WARN, 0.5 + k / 100)
    assert eng.tick(1.0).tick.error_rate == 0.0


def test_states_learning_then_active() -> None:
    eng = engine()
    feed(eng, 0, 0)
    assert eng.tick(1.0).tick.state == "insufficient"  # 10 lines < 20
    states = []
    sec = 1
    while not eng.warmed_up:
        feed(eng, sec, 0)
        sec += 1
        states.append(eng.tick(float(sec)).tick.state)
    assert states == ["learning"] * 30
    feed(eng, sec, 0)
    res = eng.tick(float(sec + 1))
    assert res.tick.state == "active"
    assert res.tick.baseline == 0.0
    assert res.tick.z == 0.0
    assert not res.tick.is_anomaly
    assert res.tick.to_dict()["state"] == "active"


def test_critical_during_warmup_through_engine() -> None:
    eng = engine()
    feed(eng, 0, 6)
    feed(eng, 1, 6)
    res = eng.tick(2.0)
    [a] = res.alerts
    assert (a.status, a.severity, a.signal_type) == (
        AlertStatus.OPEN,
        "CRITICAL",
        SignalType.ERROR_RATE,
    )
    assert a.baseline is None and a.z_score is None
    assert res.tick.state == "incident"
    assert res.tick.severity == "CRITICAL"
    assert res.tick.is_anomaly
    assert eng.baselines.states()[("*", "ERROR_RATE")].warmup_count == 0


def test_incident_beats_insufficient() -> None:
    eng = engine()
    feed(eng, 0, 11, lines=20)  # 55%
    assert eng.tick(1.0).alerts  # CRITICAL opens
    res = eng.tick(40.0)  # window empty
    assert res.tick.lines == 0
    assert res.tick.state == "incident"


def test_ack_and_silence_pass_through() -> None:
    eng = engine()
    feed(eng, 0, 11, lines=20)  # 55%
    [opened] = eng.tick(1.0).alerts
    assert opened.incident_id is not None
    assert eng.ack(opened.incident_id, 1.5).status == AlertStatus.ACKED
    assert eng.silence(opened.incident_id, until=100.0, now=2.0).status == AlertStatus.SILENCED
    [active] = eng.active(3.0)
    assert active.incident_id == opened.incident_id
