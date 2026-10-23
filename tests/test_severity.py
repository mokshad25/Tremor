"""
TREMOR — Severity scoring tests.
"""

from __future__ import annotations

import pytest

from app.core.severity import Severity, score
from tests.detection_helpers import make_settings

CFG = make_settings()


@pytest.mark.parametrize(
    ("z", "expected"),
    [
        (None, None),
        (-5.0, None),
        (0.0, None),
        (2.999, None),
        (3.0, Severity.INFO),
        (4.999, Severity.INFO),
        (5.0, Severity.WARNING),
        (7.999, Severity.WARNING),
        (8.0, Severity.HIGH),
        (1_000.0, Severity.HIGH),
    ],
)
def test_z_boundaries(z: float | None, expected: Severity | None) -> None:
    assert score(z, CFG) == expected


def test_critical_rule_ignores_z() -> None:
    assert score(0.0, CFG, rate=0.51, n=20) == Severity.CRITICAL
    assert score(None, CFG, rate=0.51, n=20) == Severity.CRITICAL


def test_critical_needs_rate_strictly_above_ceiling() -> None:
    assert score(None, CFG, rate=0.5, n=20) is None


def test_critical_needs_min_events() -> None:
    assert score(None, CFG, rate=0.9, n=19) is None


def test_no_critical_rule_without_rate() -> None:
    assert score(9.0, CFG) == Severity.HIGH


def test_thresholds_come_from_config() -> None:
    cfg = make_settings(z_info=1.0, z_warn=2.0, z_high=3.0, rate_ceiling=0.2, min_events=5)
    assert score(1.5, cfg) == Severity.INFO
    assert score(2.5, cfg) == Severity.WARNING
    assert score(3.5, cfg) == Severity.HIGH
    assert score(None, cfg, rate=0.25, n=5) == Severity.CRITICAL
