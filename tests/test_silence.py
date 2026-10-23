"""
TREMOR — Silence detector tests (unit and through the engine).
"""

from __future__ import annotations

from app.core.alerts import AlertStatus, SignalType
from app.core.detectors.silence import SilenceDetector
from app.core.engine import DetectionEngine
from app.core.severity import Severity
from app.ingest.parser import LogEvent
from tests.detection_helpers import ctx, make_settings, obs

INFO = LogEvent(ts=0.0, level="INFO", service="svc", message="ok")


def test_quiet_before_warmup() -> None:
    det = SilenceDetector(make_settings())
    det.observe(obs(0.0))
    [s] = det.evaluate(ctx(100.0, warmed_up=False))
    assert s.severity is None
    assert not s.resolve


def test_quiet_before_any_line() -> None:
    [s] = SilenceDetector(make_settings()).evaluate(ctx(100.0))
    assert s.severity is None


def test_opens_at_exactly_10_s() -> None:
    det = SilenceDetector(make_settings())
    det.observe(obs(100.0))
    assert det.evaluate(ctx(109.0))[0].severity is None
    [s] = det.evaluate(ctx(110.0))
    assert s.severity == Severity.HIGH
    assert s.signal_type == SignalType.SILENCE
    assert s.reason == "log stream silent: no lines for 10 s"


def test_resolve_flag_once_lines_return() -> None:
    det = SilenceDetector(make_settings())
    det.observe(obs(100.0))
    det.observe(obs(99.0))  # out-of-order arrival does not move last_arrival back
    assert det.last_arrival == 100.0
    det.observe(obs(115.0))
    [s] = det.evaluate(ctx(115.0))
    assert s.severity is None
    assert s.resolve


def warmed_engine() -> tuple[DetectionEngine, float]:
    """Engine after warm-up: 10 clean lines/s, ticked every second."""
    eng = DetectionEngine(make_settings())
    t = 0.0
    while not eng.warmed_up:
        for k in range(10):
            eng.observe(INFO, t + (k + 1) / 10)
        t += 1.0
        eng.tick(t)
    return eng, t


def test_engine_opens_at_10_s_and_resolves_on_return() -> None:
    eng, t = warmed_engine()
    last_line = t
    for s in range(1, 10):
        res = eng.tick(last_line + s)
        assert res.alerts == []
    res = eng.tick(last_line + 10)
    [opened] = res.alerts
    assert opened.signal_type == SignalType.SILENCE
    assert opened.status == AlertStatus.OPEN
    assert opened.severity == "HIGH"
    assert res.tick.state == "incident"
    assert res.tick.severity == "HIGH"

    eng.observe(INFO, last_line + 12.5)
    res = eng.tick(last_line + 13)
    [resolved] = res.alerts
    assert resolved.status == AlertStatus.RESOLVED
    assert resolved.incident_id == opened.incident_id
    assert resolved.reason == "resolved: log stream resumed"
    assert res.tick.state == "active"  # pre-silence lines are still in the 30 s window
