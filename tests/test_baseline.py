"""
TREMOR — Baseline tests.
"""

from __future__ import annotations

import math

import pytest

from app.core.baseline import (
    Baseline,
    BaselineState,
    BaselineStore,
    binomial_floor,
    relative_floor,
)


def make_baseline(warmup_ticks: int = 4) -> Baseline:
    return Baseline(
        alpha=0.01,
        warmup_ticks=warmup_ticks,
        sigma_min=0.01,
        noise_floor=binomial_floor,
        max_update_z=2.0,
    )


def test_learning_until_warmup_complete() -> None:
    b = make_baseline()
    for v in (0.01, 0.02, 0.03):
        b.add_warmup(v)
        assert not b.seeded
        assert b.mu is None
    with pytest.raises(RuntimeError):
        b.z(0.1, 100)


def test_seeds_with_mean_and_population_variance() -> None:
    b = make_baseline()
    for v in (0.01, 0.02, 0.03, 0.04):
        b.add_warmup(v)
    assert b.seeded
    assert b.mu == pytest.approx(0.025)
    # Population variance: mean of squared deviations over k, not k - 1
    assert b.sigma == pytest.approx(math.sqrt(0.000125))
    b.add_warmup(0.9)  # ignored once seeded
    assert b.mu == pytest.approx(0.025)


def seeded(values: tuple[float, ...] = (0.02, 0.02, 0.02, 0.02)) -> Baseline:
    b = make_baseline(len(values))
    for v in values:
        b.add_warmup(v)
    return b


def test_update_follows_ewma_formulas() -> None:
    b = seeded((0.01, 0.03, 0.01, 0.03))  # mu 0.02, var 0.0001
    assert b.update(0.03, z=1.0, incident_open=False)
    assert b.mu == pytest.approx(0.01 * 0.03 + 0.99 * 0.02)
    assert b.sigma == pytest.approx(math.sqrt(0.99 * (0.0001 + 0.01 * 0.01**2)))


def test_no_update_while_incident_open() -> None:
    b = seeded()
    assert not b.update(0.03, z=0.5, incident_open=True)
    assert b.mu == pytest.approx(0.02)
    assert b.sigma == 0.0


@pytest.mark.parametrize("z", [2.0, 2.5, 40.0])
def test_no_update_when_z_at_or_above_gate(z: float) -> None:
    b = seeded()
    assert not b.update(0.2, z=z, incident_open=False)
    assert b.mu == pytest.approx(0.02)


def test_sigma_min_floor_on_zero_variance() -> None:
    b = seeded()
    # binomial floor at n=10_000 is ~0.0014, below sigma_min
    assert b.sigma_eff(10_000) == pytest.approx(0.01)


def test_binomial_floor_widens_at_low_n() -> None:
    b = seeded()
    assert b.sigma_eff(20) == pytest.approx(math.sqrt(0.02 * 0.98 / 20))
    assert b.sigma_eff(20) > b.sigma_eff(300)


def test_relative_floor_for_latency() -> None:
    b = Baseline(
        alpha=0.01, warmup_ticks=2, sigma_min=1.0, noise_floor=relative_floor(0.1), max_update_z=2
    )
    b.add_warmup(200.0)
    b.add_warmup(200.0)
    assert b.sigma_eff(50) == pytest.approx(20.0)
    assert b.z(260.0, 50) == pytest.approx(3.0)


def test_binomial_floor_handles_empty_sample() -> None:
    assert binomial_floor(0.02, 0) == 0.0


def test_baseline_store_registers_and_reports_warmth() -> None:
    store = BaselineStore()
    b = store.register("*", "ERROR_RATE", make_baseline(warmup_ticks=2))
    assert store.get("*", "ERROR_RATE") is b
    assert store.get("*", "LATENCY") is None
    assert not store.is_warm("*")
    assert not store.is_warm("other")
    b.add_warmup(0.01)
    b.add_warmup(0.03)
    assert store.is_warm("*")
    state = store.states()[("*", "ERROR_RATE")]
    assert state == BaselineState(
        mu=pytest.approx(0.02), sigma=pytest.approx(0.01), seeded=True, warmup_count=0
    )
