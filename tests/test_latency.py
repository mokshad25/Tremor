"""
TREMOR — Latency detector tests (unit and through the engine).
"""

from __future__ import annotations

import pytest

from app.core.alerts import AlertStatus, SignalType
from app.core.detectors.latency import LatencyDetector, percentile
from app.core.engine import DetectionEngine
from app.core.severity import Severity
from app.ingest.parser import LogEvent
from tests.detection_helpers import make_settings


def seeded(p95: float = 200.0, **overrides: float) -> LatencyDetector:
    """A detector whose baseline is seeded at a flat `p95` (sigma 0, so the floor rules)."""
    det = LatencyDetector(make_settings(warmup_ticks=2, **overrides))
    for t in (1.0, 2.0):
        det.measure(t, [p95] * 20, incident_open=False)
    assert det.baseline.seeded
    return det


def test_percentile_nearest_rank() -> None:
    samples = [float(x) for x in range(1, 101)]
    assert percentile(samples, 0.95) == 95.0
    assert percentile(samples, 1.0) == 100.0
    assert percentile([7.0], 0.95) == 7.0
    assert percentile([3.0, 1.0, 2.0], 0.5) == 2.0


def test_insufficient_samples_is_neutral() -> None:
    det = LatencyDetector(make_settings())
    r = det.measure(1.0, [100.0] * 19, incident_open=False)
    assert r.state == "insufficient"
    assert r.severity is None and r.clear is None and r.z is None
    assert det.baseline.warmup_count == 0
    r = det.measure(2.0, [], incident_open=False)
    assert r.p is None
    assert r.signal("*", 30, 0.95).reason == "no latency samples over the last 30 s"


def test_learning_never_alerts_and_skips_open_incident_ticks() -> None:
    det = LatencyDetector(make_settings(warmup_ticks=2))
    r = det.measure(1.0, [10_000.0] * 20, incident_open=False)
    assert r.state == "learning" and r.severity is None
    det.measure(2.0, [999.0] * 20, incident_open=True)  # not recorded
    assert det.baseline.warmup_count == 1


def test_floor_is_ten_percent_of_baseline() -> None:
    det = seeded(200.0)
    r = det.measure(3.0, [260.0] * 20, incident_open=False)
    assert r.sigma_eff == pytest.approx(20.0)
    assert r.z == pytest.approx(3.0)
    assert r.severity == Severity.INFO


@pytest.mark.parametrize(
    ("p95", "severity"),
    [(250.0, None), (300.0, Severity.WARNING), (360.0, Severity.HIGH), (3000.0, Severity.HIGH)],
)
def test_severity_follows_z(p95: float, severity: Severity | None) -> None:
    r = seeded(200.0).measure(3.0, [p95] * 20, incident_open=False)
    assert r.severity == severity


def test_sigma_min_keeps_zero_baseline_finite() -> None:
    r = seeded(0.0).measure(3.0, [5.0] * 20, incident_open=False)
    assert r.sigma_eff == pytest.approx(1.0)
    assert r.z == pytest.approx(5.0)


def test_spike_does_not_move_the_baseline() -> None:
    det = seeded(200.0)
    r = det.measure(3.0, [3000.0] * 20, incident_open=False)
    assert not r.updated
    assert det.baseline.mu == pytest.approx(200.0)
    r = det.measure(4.0, [210.0] * 20, incident_open=True)
    assert not r.updated  # gated while the incident is open
    assert r.clear is True  # z = 0.5 < clear_z


def test_only_lines_with_duration_count() -> None:
    eng = DetectionEngine(make_settings(warmup_ticks=2))
    for k in range(40):
        eng.observe(LogEvent(ts=0.0, level="INFO", service="svc", message="no timing"), k / 40)
    eng.tick(1.0)
    assert eng.latency.last is not None and eng.latency.last.state == "insufficient"


def _line(ms: float) -> LogEvent:
    return LogEvent(ts=0.0, level="INFO", service="svc", message="request done", duration_ms=ms)


def test_engine_opens_on_spike_and_resolves_after_it() -> None:
    eng = DetectionEngine(make_settings())
    t = 0.0
    while not eng.latency.baseline.seeded:
        for k in range(10):
            eng.observe(_line(180.0 + k), t + (k + 1) / 10)
        t += 1.0
        assert all(a.signal_type != SignalType.LATENCY for a in eng.tick(t).alerts)
    assert eng.baselines.get("*", "LATENCY") is eng.latency.baseline

    opened = []
    for _ in range(5):  # 15x slower; p95 crosses after ~1.5 s of spike in the 30 s window
        for k in range(10):
            eng.observe(_line(2700.0), t + (k + 1) / 10)
        t += 1.0
        opened += [a for a in eng.tick(t).alerts if a.signal_type == SignalType.LATENCY]
    [alert] = opened
    assert alert.status == AlertStatus.OPEN
    assert alert.severity == "HIGH"
    assert alert.value == pytest.approx(2700.0)
    assert alert.reason.startswith("p95 latency 2700 ms vs baseline 18")

    resolved = []
    for _ in range(45):  # the spike leaves the window after 30 s, then 10 clear ticks
        for k in range(10):
            eng.observe(_line(180.0 + k), t + (k + 1) / 10)
        t += 1.0
        resolved += [a for a in eng.tick(t).alerts if a.signal_type == SignalType.LATENCY]
    [done] = resolved
    assert done.status == AlertStatus.RESOLVED
    assert done.incident_id == alert.incident_id
