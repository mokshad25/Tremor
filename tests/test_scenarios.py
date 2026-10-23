"""
TREMOR — Scenario definition tests: labels must match what the generator does.
"""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

import pytest

import simulator.scenarios as scenarios_module
from app.core.alerts import SignalType
from app.ingest.parser import parse_line
from simulator.gen_logs import LogGenerator
from simulator.scenarios import SCENARIOS, SERVICES, RateCurve, Scenario

if TYPE_CHECKING:
    from pathlib import Path

    from app.ingest.parser import LogEvent

LABELLED = [s for s in SCENARIOS.values() if s.labels]


@cache
def replay(name: str) -> tuple[list[tuple[float, LogEvent]], int]:
    """(scenario-relative ts, event) for parseable lines, plus the malformed count."""
    gen = LogGenerator(SCENARIOS[name])
    events: list[tuple[float, LogEvent]] = []
    malformed = 0
    for ts, line in gen.iter_lines():
        event = parse_line(line)
        if event is None:
            malformed += 1
        else:
            events.append((ts - gen.start_ts, event))
    return events, malformed


def window(name: str, service: str, start: float, end: float) -> list[LogEvent]:
    return [e for t, e in replay(name)[0] if start <= t < end and e.service == service]


def error_rate(events: list[LogEvent]) -> float:
    return sum(e.level == "ERROR" for e in events) / len(events)


def p95(events: list[LogEvent]) -> float:
    values = sorted(e.duration_ms for e in events if e.duration_ms is not None)
    return values[int(0.95 * (len(values) - 1))]


# ── Catalogue ─────────────────────────────────────────────────────────


def test_catalogue_matches_docstring() -> None:
    doc = scenarios_module.__doc__ or ""
    listed = doc.split("Scenarios:")[1].split("\n\n")[0].replace("\n", " ")
    names = [n.strip() for n in listed.split(",")]
    assert names == list(SCENARIOS)
    assert len(SCENARIOS) == 10
    assert "outage" in SCENARIOS
    assert all(key == s.name for key, s in SCENARIOS.items())


@pytest.mark.parametrize("scenario", list(SCENARIOS.values()), ids=lambda s: s.name)
def test_scenario_is_well_formed(scenario: Scenario) -> None:
    for label in scenario.labels:
        assert scenario.warmup_s <= label.start_s < label.end_s <= scenario.duration_s
        assert label.signal_type in {s.value for s in SignalType}
        assert label.service in SERVICES
    assert {p.service for p in scenario.plans} <= set(SERVICES)
    assert {i.service for i in scenario.injected} <= set(SERVICES)
    assert scenario.expected_anomalies == [
        (lb.start_s, lb.end_s, lb.signal_type) for lb in scenario.labels
    ]


def test_unlabelled_scenarios() -> None:
    quiet = {"steady", "noisy_normal", "rotation", "malformed_flood"}
    assert {name for name, s in SCENARIOS.items() if not s.labels} == quiet


# ── RateCurve ─────────────────────────────────────────────────────────


def test_rate_curve_interpolates_and_clamps() -> None:
    curve = RateCurve(((10.0, 0.0), (20.0, 1.0)))
    assert curve.value_at(0) == 0.0
    assert curve.value_at(15) == pytest.approx(0.5)
    assert curve.value_at(99) == 1.0


def test_rate_curve_step_edges() -> None:
    curve = RateCurve.step(1.0, 5.0, 100, 200)
    assert curve.value_at(99.999) == 1.0
    assert curve.value_at(100) == 5.0
    assert curve.value_at(199.999) == 5.0
    assert curve.value_at(200) == 1.0
    assert RateCurve.constant(0.3).value_at(1e6) == 0.3


def test_rate_curve_rejects_bad_points() -> None:
    with pytest.raises(ValueError):
        RateCurve(())
    with pytest.raises(ValueError):
        RateCurve(((5.0, 1.0), (1.0, 2.0)))


# ── Generator agrees with labels ──────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "label"),
    [(s.name, lb) for s in LABELLED for lb in s.labels],
    ids=lambda x: x if isinstance(x, str) else x.signal_type,
)
def test_label_matches_generated_behaviour(name: str, label: scenarios_module.Label) -> None:
    scenario = SCENARIOS[name]
    inside = window(name, label.service, label.start_s, label.end_s)
    clean = window(name, label.service, 60, scenario.warmup_s)
    assert clean, "service must be active before warm-up ends"

    if label.signal_type == "ERROR_RATE":
        assert error_rate(inside) > max(0.10, 3 * error_rate(clean))
    elif label.signal_type == "SILENCE":
        assert inside == []
    elif label.signal_type == "LATENCY":
        assert p95(inside) > 5 * p95(clean)
    elif label.signal_type == "NEW_PATTERN":
        (inj,) = [i for i in scenario.injected if i.service == label.service]
        marker = inj.template.split("{")[0]
        events = replay(name)[0]
        before = [e for t, e in events if t < inj.start_s and marker in e.message]
        during = [e for t, e in events if inj.start_s <= t < inj.end_s and marker in e.message]
        after = [e for t, e in events if t >= inj.end_s and marker in e.message]
        assert before == [] and after == []
        assert len(during) > 0.5 * inj.rate_per_s * (inj.end_s - inj.start_s)
    else:  # pragma: no cover
        pytest.fail(f"unknown signal {label.signal_type}")


@pytest.mark.parametrize("name", ["burst", "outage", "latency_spike", "silence"])
def test_service_recovers_after_label(name: str) -> None:
    scenario = SCENARIOS[name]
    label = scenario.labels[0]
    after = window(name, label.service, label.end_s + 30, scenario.duration_s)
    clean = window(name, label.service, 60, scenario.warmup_s)
    assert error_rate(after) < 0.05
    rate_after = len(after) / (scenario.duration_s - label.end_s - 30)
    rate_clean = len(clean) / (scenario.warmup_s - 60)
    assert rate_after == pytest.approx(rate_clean, rel=0.25)  # lines per second
    if name == "latency_spike":
        assert p95(after) < 2 * p95(clean)


def test_new_pattern_does_not_move_error_rate() -> None:
    label = SCENARIOS["new_pattern"].labels[0]
    inside = window("new_pattern", label.service, label.start_s, label.end_s)
    assert error_rate(inside) < 0.05


def test_noisy_normal_is_low_volume_three_percent() -> None:
    auth = window("noisy_normal", "auth-service", 0, 900)
    steady_auth = window("steady", "auth-service", 0, 900)
    assert 0.02 < error_rate(auth) < 0.04
    assert len(auth) < 0.4 * len(steady_auth)


def test_malformed_flood_is_half_garbage() -> None:
    events, malformed = replay("malformed_flood")
    assert 0.45 < malformed / (malformed + len(events)) < 0.55
    assert replay("steady")[1] == 0


async def test_rotation_scenario_rotates_by_default(tmp_path: Path) -> None:
    async def no_sleep(_: float) -> None:
        return None

    out = tmp_path / "app.log"
    gen = LogGenerator(SCENARIOS["rotation"])
    written = await gen.write_file(out, sleep=no_sleep)
    parts = [tmp_path / "app.log.2", tmp_path / "app.log.1", out]
    assert all(p.exists() for p in parts)
    assert sum(len(p.read_text().splitlines()) for p in parts) == written
