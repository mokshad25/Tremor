"""
TREMOR — Error-rate detector tests.
"""

from __future__ import annotations

import math

import pytest

from app.core.alerts import SignalType
from app.core.arrivals import ArrivalWindow
from app.core.detectors.error_rate import ErrorRateDetector
from app.core.severity import Severity
from tests.detection_helpers import ctx, make_settings


def warmed(n: int = 1000, errors: int = 20) -> ErrorRateDetector:
    det = ErrorRateDetector(make_settings())
    for t in range(30):
        det.measure(float(t), n, errors, incident_open=False)
    assert det.baseline.seeded
    return det


def test_insufficient_below_min_events() -> None:
    det = ErrorRateDetector(make_settings())
    r = det.measure(0.0, 19, 19, incident_open=False)
    assert r.state == "insufficient"
    assert r.z is None
    assert r.severity is None  # even at 100% errors
    assert r.clear is None
    assert det.baseline.warmup_count == 0


def test_insufficient_does_not_update_seeded_baseline() -> None:
    det = warmed()
    mu = det.baseline.mu
    r = det.measure(100.0, 10, 0, incident_open=False)
    assert r.state == "insufficient"
    assert det.baseline.mu == mu


def test_empty_window_has_no_rate() -> None:
    r = ErrorRateDetector(make_settings()).measure(0.0, 0, 0, incident_open=False)
    assert r.rate is None
    assert r.state == "insufficient"


def test_warmup_seeds_after_30_ticks_without_alerting() -> None:
    det = ErrorRateDetector(make_settings())
    rates = [0.01 if t % 2 else 0.03 for t in range(30)]
    for t, rate in enumerate(rates):
        r = det.measure(float(t), 100, round(rate * 100), incident_open=False)
        assert r.state == "learning"
        assert r.z is None
        assert r.severity is None
    assert det.baseline.mu == pytest.approx(0.02)
    assert det.baseline.sigma == pytest.approx(0.01)
    assert det.measure(30.0, 100, 2, incident_open=False).state == "active"


def test_warmup_ignores_high_but_non_critical_rates() -> None:
    det = ErrorRateDetector(make_settings())
    r = det.measure(0.0, 100, 40, incident_open=False)  # 40%: no z yet, below ceiling
    assert r.severity is None
    assert r.clear is True


def test_critical_during_warmup_and_excluded_from_samples() -> None:
    det = ErrorRateDetector(make_settings())
    r = det.measure(0.0, 20, 11, incident_open=False)  # 55% with n = 20
    assert r.state == "learning"
    assert r.severity == Severity.CRITICAL
    assert r.clear is False
    assert det.baseline.warmup_count == 0


def test_ticks_with_open_incident_excluded_from_warmup() -> None:
    det = ErrorRateDetector(make_settings())
    r = det.measure(0.0, 100, 10, incident_open=True)
    assert r.clear is True  # r <= 0.5 counts toward resolving a warm-up incident
    assert det.baseline.warmup_count == 0


def test_finite_z_on_perfectly_clean_logs() -> None:
    det = warmed(errors=0)
    assert det.baseline.mu == 0.0
    assert det.baseline.sigma == 0.0
    r = det.measure(30.0, 1000, 0, incident_open=False)
    assert r.z == 0.0
    assert r.sigma_eff == pytest.approx(0.01)
    assert math.isfinite(det.measure(31.0, 1000, 10, incident_open=False).z or math.inf)


def test_floor_widens_at_low_n() -> None:
    det = warmed()  # mu 0.02, sigma 0
    low = det.measure(30.0, 20, 1, incident_open=True)
    assert low.sigma_eff == pytest.approx(math.sqrt(0.02 * 0.98 / 20))
    assert low.z == pytest.approx((0.05 - 0.02) / math.sqrt(0.02 * 0.98 / 20))
    high = det.measure(31.0, 1000, 50, incident_open=True)
    assert high.sigma_eff == pytest.approx(0.01)


def test_z_uses_previous_tick_baseline() -> None:
    det = warmed()
    r = det.measure(30.0, 1000, 30, incident_open=False)
    assert r.mu == pytest.approx(0.02)
    assert r.z == pytest.approx(1.0)
    assert r.updated
    assert det.baseline.mu == pytest.approx(0.01 * 0.03 + 0.99 * 0.02)


def test_no_baseline_update_while_incident_open() -> None:
    det = warmed()
    r = det.measure(30.0, 1000, 20, incident_open=True)
    assert r.z == pytest.approx(0.0)
    assert not r.updated
    assert det.baseline.mu == pytest.approx(0.02)


def test_no_baseline_update_when_z_at_least_2() -> None:
    det = warmed()
    r = det.measure(30.0, 1000, 40, incident_open=False)  # z = 2
    assert r.z == pytest.approx(2.0)
    assert not r.updated
    assert r.clear is False
    assert r.severity is None
    assert det.baseline.mu == pytest.approx(0.02)


def test_severity_from_z_after_warmup() -> None:
    det = warmed()
    assert det.measure(30.0, 1000, 50, incident_open=True).severity == Severity.INFO  # z 3
    assert det.measure(31.0, 1000, 70, incident_open=True).severity == Severity.WARNING  # z 5
    assert det.measure(32.0, 1000, 100, incident_open=True).severity == Severity.HIGH  # z 8


def test_critical_after_warmup_and_no_update() -> None:
    det = warmed()
    r = det.measure(30.0, 1000, 510, incident_open=False)
    assert r.severity == Severity.CRITICAL
    assert not r.updated
    assert r.clear is False


def test_evaluate_reads_window_and_open_incident() -> None:
    det = warmed()
    window = ArrivalWindow(30)
    for i in range(1000):
        window.add(29.0 + i / 1000, is_error=i < 50)
    open_keys = frozenset({(SignalType.ERROR_RATE, None)})
    [s] = det.evaluate(ctx(30.0, window=window, open_keys=open_keys))
    assert s.signal_type == SignalType.ERROR_RATE
    assert s.severity == Severity.INFO
    assert (s.lines, s.errors) == (1000, 50)
    assert s.value == pytest.approx(0.05)
    assert s.baseline == pytest.approx(0.02)
    assert s.reason == "error rate 5.0% vs baseline 2.0% over the last 30 s"
    assert det.last is not None and not det.last.updated  # incident open: no update


def test_reason_while_learning_and_empty() -> None:
    det = ErrorRateDetector(make_settings())
    assert det.measure(0.0, 0, 0, False).reason(30) == "no lines over the last 30 s"
    assert det.measure(1.0, 20, 11, False).reason(30) == (
        "error rate 55.0% vs baseline still learning over the last 30 s"
    )
