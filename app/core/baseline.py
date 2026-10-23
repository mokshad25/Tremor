"""
TREMOR — EWMA baseline with warm-up seeding and gated updates.

Shared by the error-rate and latency detectors:
- Warm-up: collect `warmup_ticks` values, then seed mu = mean, sigma^2 = population variance
- Deviation against the previous tick's state:
    sigma_eff = max(sigma, noise_floor(mu, n), sigma_min)
    z = (value - mu) / sigma_eff
- Update only when the caller says no incident is open and z < max_update_z:
    mu_t      = alpha * x + (1 - alpha) * mu_prev
    sigma^2_t = (1 - alpha) * (sigma^2_prev + alpha * (x - mu_prev)^2)

The baseline never absorbs an incident, so an ongoing burst cannot become "normal".

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass

NoiseFloor = Callable[[float, int], float]
"""(mu, n) -> minimum plausible sigma for a sample of size n."""


def binomial_floor(mu: float, n: int) -> float:
    """Sampling noise of a proportion estimated from n lines."""
    if n <= 0:
        return 0.0
    return math.sqrt(max(mu * (1.0 - mu), 0.0) / n)


def relative_floor(frac: float) -> NoiseFloor:
    """Floor proportional to the baseline, e.g. 10% of the p95 latency."""

    def floor(mu: float, n: int) -> float:
        return frac * abs(mu)

    return floor


class Baseline:
    """Warm-up seeded EWMA mean and variance of one signal."""

    def __init__(
        self,
        alpha: float,
        warmup_ticks: int,
        sigma_min: float,
        noise_floor: NoiseFloor,
        max_update_z: float,
    ) -> None:
        self.alpha = alpha
        self.warmup_ticks = warmup_ticks
        self.sigma_min = sigma_min
        self.noise_floor = noise_floor
        self.max_update_z = max_update_z
        self._warmup: list[float] = []
        self._mu: float | None = None
        self._var: float = 0.0

    @property
    def seeded(self) -> bool:
        return self._mu is not None

    @property
    def mu(self) -> float | None:
        return self._mu

    @property
    def sigma(self) -> float | None:
        return math.sqrt(self._var) if self._mu is not None else None

    @property
    def warmup_count(self) -> int:
        return len(self._warmup)

    def add_warmup(self, value: float) -> None:
        """Record one warm-up value; seeds the baseline on the last one."""
        if self.seeded:
            return
        self._warmup.append(value)
        if len(self._warmup) >= self.warmup_ticks:
            k = len(self._warmup)
            mu = sum(self._warmup) / k
            self._var = sum((x - mu) ** 2 for x in self._warmup) / k
            self._mu = mu
            self._warmup.clear()

    def sigma_eff(self, n: int) -> float:
        mu = self._require_mu()
        return max(math.sqrt(self._var), self.noise_floor(mu, n), self.sigma_min)

    def z(self, value: float, n: int) -> float:
        return (value - self._require_mu()) / self.sigma_eff(n)

    def update(self, value: float, z: float, incident_open: bool) -> bool:
        """Gated EWMA update. Returns True if the baseline moved."""
        if incident_open or z >= self.max_update_z:
            return False
        mu_prev = self._require_mu()
        a = self.alpha
        self._var = (1.0 - a) * (self._var + a * (value - mu_prev) ** 2)
        self._mu = a * value + (1.0 - a) * mu_prev
        return True

    def _require_mu(self) -> float:
        if self._mu is None:
            raise RuntimeError("baseline is still learning")
        return self._mu

    def state(self) -> BaselineState:
        return BaselineState(self._mu, self.sigma, self.seeded, self.warmup_count)


@dataclass(frozen=True, slots=True)
class BaselineState:
    """Read-only view of one baseline, for the API and the eval harness."""

    mu: float | None
    sigma: float | None
    seeded: bool
    warmup_count: int


class BaselineStore:
    """
    Keyed store of Baseline objects, one per (service, signal), e.g. ("*", "ERROR_RATE").

    Detectors own their Baseline and register it here; the store is the single place to
    inspect them. Warm-up for a service means its ERROR_RATE baseline is seeded.
    """

    WARMUP_SIGNAL = "ERROR_RATE"

    def __init__(self) -> None:
        self._baselines: dict[tuple[str, str], Baseline] = {}

    def register(self, service: str, signal: str, baseline: Baseline) -> Baseline:
        self._baselines[(service, signal)] = baseline
        return baseline

    def get(self, service: str, signal: str) -> Baseline | None:
        return self._baselines.get((service, signal))

    def is_warm(self, service: str) -> bool:
        b = self.get(service, self.WARMUP_SIGNAL)
        return b is not None and b.seeded

    def states(self) -> dict[tuple[str, str], BaselineState]:
        return {key: b.state() for key, b in self._baselines.items()}
