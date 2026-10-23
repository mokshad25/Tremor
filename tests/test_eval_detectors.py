"""
TREMOR — Tests for the eval baseline detectors.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.ingest.parser import LogEvent
from eval.detectors import (
    DETECTORS,
    RollingMeanDetector,
    StaticThresholdDetector,
    TremorDetector,
)

if TYPE_CHECKING:
    from eval.metrics import EvalAlert

T0 = 1_000_000.0


def feed_second(
    det: StaticThresholdDetector | RollingMeanDetector,
    second: int,
    errors: int,
    lines: int = 10,
    service: str = "svc",
) -> list[EvalAlert]:
    """``lines`` lines in second ``second`` (``errors`` of them ERROR), then tick."""
    for i in range(lines):
        level = "ERROR" if i < errors else "INFO"
        arrival = T0 + second + i / lines
        det.observe(LogEvent(ts=arrival, level=level, service=service, message="m"), arrival)
    return det.tick(T0 + second + 1)


def test_static_threshold_opens_once_and_resolves() -> None:
    det = StaticThresholdDetector()
    alerts: list[EvalAlert] = []
    for s in range(60):  # 0% errors: never fires
        alerts += feed_second(det, s, errors=0)
    assert alerts == []
    for s in range(60, 90):  # 20% errors: opens once, then stays open
        alerts += feed_second(det, s, errors=2)
    assert len(alerts) == 1
    assert alerts[0].signal_type == "ERROR_RATE" and alerts[0].service == "svc"
    for s in range(90, 150):  # back to 0%: the 30 s window drains, then 10 clear ticks
        alerts += feed_second(det, s, errors=0)
    for s in range(150, 160):  # fires again: a new incident
        alerts += feed_second(det, s, errors=5)
    assert len(alerts) == 2


def test_static_threshold_needs_min_events() -> None:
    det = StaticThresholdDetector(min_events=20)
    alerts: list[EvalAlert] = []
    for s in range(5):  # 1 line/s: at most 5 lines in the window
        alerts += feed_second(det, s, errors=1, lines=1)
    assert alerts == []


def test_static_threshold_is_per_service() -> None:
    det = StaticThresholdDetector()
    alerts: list[EvalAlert] = []
    for s in range(40):
        alerts += feed_second(det, s, errors=0, service="quiet")
        alerts += feed_second(det, s, errors=3, service="loud")
    assert [a.service for a in alerts] == ["loud"]


def test_rolling_mean_fires_on_step_not_on_steady() -> None:
    det = RollingMeanDetector(min_history=60)
    alerts: list[EvalAlert] = []
    for s in range(200):  # 10% steady: the mean settles at 10%
        alerts += feed_second(det, s, errors=1)
    assert alerts == []
    for s in range(200, 240):  # 50% is well above 2x the mean
        alerts += feed_second(det, s, errors=5)
    assert len(alerts) == 1


def test_rolling_mean_waits_for_history() -> None:
    det = RollingMeanDetector(min_history=60)
    alerts: list[EvalAlert] = []
    for s in range(30):  # would fire, but there is no history yet
        alerts += feed_second(det, s, errors=9)
    assert alerts == []


def drive_tremor(det: TremorDetector, seconds: range, plan: dict[str, int | None]) -> list[str]:
    """Each second, every service in ``plan`` logs 10 lines with ``errors`` ERRORs
    (``None`` = silent); returns "SIGNAL service" for every alert opened."""
    opened: list[str] = []
    for s in seconds:
        for service, errors in plan.items():
            if errors is None:
                continue
            for i in range(10):
                arrival = T0 + s + i / 10
                level = "ERROR" if i < errors else "INFO"
                event = LogEvent(ts=arrival, level=level, service=service, message="m")
                det.observe(event, arrival, template_id="T1")
        opened += [f"{a.signal_type} {a.service}" for a in det.tick(T0 + s + 1)]
    return opened


def test_tremor_adapter_routes_per_service() -> None:
    det = TremorDetector()
    assert drive_tremor(det, range(0, 120), {"a": 0, "b": 0}) == []  # warm-up + steady
    opened = drive_tremor(det, range(120, 150), {"a": 9, "b": 0})  # a: 90% errors
    assert opened == ["ERROR_RATE a"]


def test_tremor_per_service_sees_one_service_go_silent() -> None:
    det = TremorDetector()
    drive_tremor(det, range(0, 120), {"a": 0, "b": 0})
    opened = drive_tremor(det, range(120, 150), {"a": None, "b": 0})
    assert opened == ["SILENCE a"]


def test_tremor_whole_stream_misses_single_service_silence() -> None:
    det = TremorDetector(per_service=False)
    drive_tremor(det, range(0, 120), {"a": 0, "b": 0})
    assert drive_tremor(det, range(120, 150), {"a": None, "b": 0}) == []


def test_detector_registry() -> None:
    assert list(DETECTORS) == ["TREMOR", "TREMOR (WARNING+)", "Static 5%", "Rolling mean"]
    assert DETECTORS["TREMOR (WARNING+)"]().name == "TREMOR (WARNING+)"


def test_tremor_min_severity_filters_info_incidents() -> None:
    # 90% errors is CRITICAL (> rate ceiling), so it counts at any min_severity
    for min_severity in ("INFO", "WARNING", "CRITICAL"):
        det = TremorDetector(min_severity=min_severity)
        drive_tremor(det, range(0, 120), {"a": 0})
        assert drive_tremor(det, range(120, 150), {"a": 9}) == ["ERROR_RATE a"]
    # silence is HIGH: reported at WARNING+, dropped at CRITICAL+
    for min_severity, expected in (("WARNING", ["SILENCE a"]), ("CRITICAL", [])):
        det = TremorDetector(min_severity=min_severity)
        drive_tremor(det, range(0, 120), {"a": 0, "b": 0})
        assert drive_tremor(det, range(120, 150), {"a": None, "b": 0}) == expected
