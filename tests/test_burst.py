"""
TREMOR — Burst validation: locks in the scripts/burst_sim.py results.

10 lines/s at 2% errors for 90 s, then a burst. Deterministic (even spread or seed 42).
"""

from __future__ import annotations

from app.core.severity import Severity
from scripts.burst_sim import simulate


def test_moderate_burst_even_errors() -> None:
    res = simulate(0.10, "even")
    assert res.normal_alerts() == []
    assert res.first_at(Severity.INFO) == 11  # spec: z >= 3 within about 15 s
    assert res.first_at(Severity.WARNING) == 18
    assert res.first_at(Severity.HIGH) == 29  # only once the 30 s window is ~full
    assert res.first_at(Severity.CRITICAL) is None
    assert res.alerts() == [(11, "OPEN INFO"), (18, "ESCALATED WARNING"), (29, "ESCALATED HIGH")]


def test_moderate_burst_random_errors() -> None:
    res = simulate(0.10, "random", seed=42)
    assert res.normal_alerts() == []
    assert res.first_at(Severity.INFO) == 14
    assert res.peak() == Severity.HIGH
    # Tick severity dips below HIGH late in the burst; the lifecycle stays silent
    assert res.alerts() == [(14, "OPEN INFO"), (17, "ESCALATED WARNING"), (25, "ESCALATED HIGH")]


def test_severe_burst_reaches_critical() -> None:
    even = simulate(0.60, "even")
    rand = simulate(0.60, "random", seed=42)
    assert even.first_at(Severity.CRITICAL) == 25  # r first exceeds 50%
    assert rand.first_at(Severity.CRITICAL) == 27
    assert even.alerts()[-1] == (25, "ESCALATED CRITICAL")
    assert even.normal_alerts() == rand.normal_alerts() == []
