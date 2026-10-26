"""
TREMOR — New-pattern detector tests (unit and through the engine).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.alerts import AlertStatus, SignalType
from app.core.detectors.new_pattern import NewPatternDetector
from app.core.engine import DetectionEngine
from app.core.severity import Severity
from app.ingest.parser import LogEvent
from tests.detection_helpers import ctx, make_settings, obs

if TYPE_CHECKING:
    from app.core.detectors.base import Observation

NP = SignalType.NEW_PATTERN


def new(arrival: float, tid: str = "T9", level: str = "WARNING", warm: bool = True) -> Observation:
    return obs(arrival, level, template_id=tid, is_new_template=True, warmed_up=warm)


def feed(det: NewPatternDetector, times: list[float], tid: str = "T9") -> None:
    for t in times:
        det.observe(new(t, tid))


def test_below_min_count_is_silent() -> None:
    det = NewPatternDetector(make_settings())
    feed(det, [1.0, 2.0, 3.0, 4.0])
    assert det.evaluate(ctx(5.0)) == []


def test_fires_warning_at_min_count() -> None:
    det = NewPatternDetector(make_settings())
    feed(det, [1.0, 2.0, 3.0, 4.0, 5.0])
    [s] = det.evaluate(ctx(5.0))
    assert s.signal_type == NP
    assert s.severity == Severity.WARNING
    assert s.template_id == "T9"
    assert s.lines == 5
    assert s.reason == "new log pattern T9: 5 lines in the last 30 s"


def test_new_error_pattern_is_high() -> None:
    det = NewPatternDetector(make_settings())
    feed(det, [1.0, 2.0, 3.0, 4.0])
    det.observe(new(5.0, level="ERROR"))
    [s] = det.evaluate(ctx(5.0))
    assert s.severity == Severity.HIGH
    assert s.errors == 1
    assert s.reason.startswith("new error pattern T9")


def test_ignores_known_templates_and_lines_before_warmup() -> None:
    det = NewPatternDetector(make_settings())
    for t in range(10):
        det.observe(obs(float(t), template_id="T1", is_new_template=False, warmed_up=True))
        det.observe(new(float(t), tid="T2", warm=False))
        det.observe(obs(float(t), is_new_template=True, warmed_up=True))  # no template id
    assert det.evaluate(ctx(10.0)) == []


def test_count_is_over_the_window_only() -> None:
    det = NewPatternDetector(make_settings())
    feed(det, [1.0, 2.0, 3.0, 40.0, 41.0])  # the first three leave the window at 31-33 s
    assert det.evaluate(ctx(41.0)) == []


def test_one_signal_per_template() -> None:
    det = NewPatternDetector(make_settings())
    feed(det, [1.0, 2.0, 3.0, 4.0, 5.0], tid="T3")
    feed(det, [1.0, 2.0, 3.0, 4.0, 5.0], tid="T2")
    assert [s.template_id for s in det.evaluate(ctx(5.0))] == ["T2", "T3"]


def test_open_incident_gets_neutral_signal_then_resolves_when_idle() -> None:
    det = NewPatternDetector(make_settings())
    feed(det, [1.0, 2.0, 3.0, 4.0, 5.0])
    open_ = frozenset({(NP, "T9")})
    [s] = det.evaluate(ctx(40.0, open_keys=open_))  # all evicted, still within resolve_s
    assert s.severity is None and not s.resolve and s.clear is None
    [s] = det.evaluate(ctx(65.0, open_keys=open_))  # 60 s after the last line
    assert s.resolve
    assert s.reason == "new log pattern T9 not seen for 60 s"
    assert det.evaluate(ctx(66.0, open_keys=open_)) == []  # state dropped


def test_idle_template_without_incident_is_dropped_quietly() -> None:
    det = NewPatternDetector(make_settings())
    feed(det, [1.0, 2.0])
    assert det.evaluate(ctx(61.0)) == []
    feed(det, [62.0, 63.0, 64.0])  # counting starts over
    assert det.evaluate(ctx(64.0)) == []


def test_engine_opens_one_incident_and_resolves_it() -> None:
    eng = DetectionEngine(make_settings(warmup_ticks=2))
    known = LogEvent(ts=0.0, level="INFO", service="svc", message="ok")
    t = 0.0
    while not eng.warmed_up:
        for k in range(30):
            eng.observe(known, t + (k + 1) / 30, template_id="T1")
        t += 1.0
        eng.tick(t)

    hsm = LogEvent(ts=0.0, level="WARNING", service="svc", message="HSM key rotation failed")
    alerts = []
    for _ in range(20):  # 2 lines/s of the new template
        for k in range(30):
            eng.observe(known, t + (k + 1) / 30, template_id="T1")
        for k in (0.25, 0.75):
            eng.observe(hsm, t + k, template_id="T7", is_new_template=True)
        t += 1.0
        alerts += [a for a in eng.tick(t).alerts if a.signal_type == NP]
    [opened] = alerts
    assert opened.status == AlertStatus.OPEN
    assert opened.severity == "WARNING"
    assert opened.template_id == "T7"

    alerts = []
    for _ in range(61):
        for k in range(30):
            eng.observe(known, t + (k + 1) / 30, template_id="T1")
        t += 1.0
        alerts += [a for a in eng.tick(t).alerts if a.signal_type == NP]
    [resolved] = alerts
    assert resolved.status == AlertStatus.RESOLVED
    assert resolved.incident_id == opened.incident_id
