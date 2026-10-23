"""
TREMOR — Simulation scenarios.

Each scenario defines: duration, per-service rate curves (volume, error rate,
latency), injected templates, and label windows for the eval harness.
Scenarios: steady, drift, burst, outage, silence, new_pattern, latency_spike,
           noisy_normal, rotation, malformed_flood

Every anomaly starts after a clean warm-up prefix (``WARMUP_S``), so a detector
with a 300 s warm-up can see it. Label windows are built from the same constants
as the curves that cause them, so they match what the generator actually does.

All scenarios are seeded for reproducibility.

Owner: Mokshad (Phase 6)
"""

from __future__ import annotations

from dataclasses import dataclass, field

PG = "payment-gateway"
AUTH = "auth-service"
LEDGER = "ledger"
SERVICES: tuple[str, ...] = (PG, AUTH, LEDGER)

# Same values as app.core.alerts.SignalType (kept as strings to avoid coupling).
SIGNAL_TYPES: tuple[str, ...] = ("ERROR_RATE", "SILENCE", "NEW_PATTERN", "LATENCY")

WARMUP_S = 360  # WARMUP_SECONDS=300 plus margin; nothing abnormal happens before this
ANOMALY_S = 480  # default anomaly onset, two minutes after warm-up


@dataclass(frozen=True, slots=True)
class RateCurve:
    """Piecewise-linear curve over scenario time, given as ``(t_s, value)`` keyframes.

    Values before the first / after the last keyframe are held constant. Two
    keyframes at the same time make a step: the later one applies from that time on.
    """

    points: tuple[tuple[float, float], ...]

    def __post_init__(self) -> None:
        if not self.points:
            raise ValueError("RateCurve needs at least one point")
        times = [t for t, _ in self.points]
        if times != sorted(times):
            raise ValueError("RateCurve points must be in time order")

    @classmethod
    def constant(cls, value: float) -> RateCurve:
        """A flat curve."""
        return cls(((0.0, value),))

    @classmethod
    def step(cls, base: float, value: float, start: float, end: float) -> RateCurve:
        """``base``, then ``value`` on ``[start, end)``, then ``base`` again."""
        return cls(((0.0, base), (start, base), (start, value), (end, value), (end, base)))

    def value_at(self, t: float) -> float:
        """Curve value at scenario time ``t`` (seconds)."""
        points = self.points
        if t < points[0][0]:
            return points[0][1]
        for (t0, v0), (t1, v1) in zip(points, points[1:], strict=False):
            if t < t1:
                return v0 + (v1 - v0) * (t - t0) / (t1 - t0)
        return points[-1][1]


ONE = RateCurve.constant(1.0)


@dataclass(frozen=True, slots=True)
class ServicePlan:
    """How one service deviates from its default profile during a scenario.

    ``error_rate=None`` keeps the service's baseline error rate.
    """

    service: str
    volume_mult: RateCurve = ONE
    error_rate: RateCurve | None = None
    latency_mult: RateCurve = ONE


@dataclass(frozen=True, slots=True)
class InjectedTemplate:
    """Extra lines from a template that does not exist in normal traffic.

    ``template`` may use the generator's fields, e.g. ``{uuid}``, ``{ip}``, ``{ms}``.
    """

    service: str
    level: str
    template: str
    rate_per_s: float
    start_s: float
    end_s: float


@dataclass(frozen=True, slots=True)
class Label:
    """Ground truth: ``service`` should raise ``signal_type`` during ``[start_s, end_s]``."""

    start_s: float
    end_s: float
    signal_type: str
    service: str


@dataclass(frozen=True, slots=True)
class Scenario:
    """Definition of a simulation scenario."""

    name: str
    description: str
    duration_s: int
    seed: int
    warmup_s: int = WARMUP_S
    plans: tuple[ServicePlan, ...] = ()
    injected: tuple[InjectedTemplate, ...] = ()
    labels: tuple[Label, ...] = ()
    malformed_ratio: float = 0.0
    rotate_at_s: tuple[float, ...] = field(default=())

    def plan_for(self, service: str) -> ServicePlan | None:
        """The plan for ``service``, or None if it runs on its default profile."""
        for plan in self.plans:
            if plan.service == service:
                return plan
        return None

    @property
    def expected_anomalies(self) -> list[tuple[float, float, str]]:
        """Labels as ``(start_s, end_s, signal_type)`` tuples (legacy view)."""
        return [(lb.start_s, lb.end_s, lb.signal_type) for lb in self.labels]


def _drift() -> Scenario:
    ramp_start, ramp_end, duration = WARMUP_S, WARMUP_S + 300, 1200
    return Scenario(
        name="drift",
        description="payment-gateway error rate ramps 2% -> 15% over 5 minutes, then holds",
        duration_s=duration,
        seed=43,
        plans=(
            ServicePlan(
                PG,
                error_rate=RateCurve(
                    ((0.0, 0.02), (ramp_start, 0.02), (ramp_end, 0.15), (duration, 0.15))
                ),
            ),
        ),
        labels=(Label(ramp_start, duration, "ERROR_RATE", PG),),
    )


def _burst() -> Scenario:
    start, end = ANOMALY_S, ANOMALY_S + 30
    return Scenario(
        name="burst",
        description="payment-gateway errors spike to 80% for 30 seconds",
        duration_s=900,
        seed=44,
        plans=(ServicePlan(PG, error_rate=RateCurve.step(0.02, 0.80, start, end)),),
        labels=(Label(start, end, "ERROR_RATE", PG),),
    )


def _outage() -> Scenario:
    start, end = ANOMALY_S, ANOMALY_S + 90
    return Scenario(
        name="outage",
        description="ledger database down for 90 s: 95% errors, 30% volume, new error template",
        duration_s=900,
        seed=51,
        plans=(
            ServicePlan(
                LEDGER,
                volume_mult=RateCurve.step(1.0, 0.3, start, end),
                error_rate=RateCurve.step(0.015, 0.95, start, end),
            ),
        ),
        injected=(
            InjectedTemplate(
                LEDGER,
                "ERROR",
                "Connection refused to ledger-db at {ip}:5432 after {ms}ms",
                2.0,
                start,
                end,
            ),
        ),
        labels=(
            Label(start, end, "ERROR_RATE", LEDGER),
            Label(start, end, "NEW_PATTERN", LEDGER),
        ),
    )


def _silence() -> Scenario:
    start, end = ANOMALY_S, ANOMALY_S + 60
    return Scenario(
        name="silence",
        description="payment-gateway goes completely quiet for 60 seconds",
        duration_s=900,
        seed=45,
        plans=(ServicePlan(PG, volume_mult=RateCurve.step(1.0, 0.0, start, end)),),
        labels=(Label(start, end, "SILENCE", PG),),
    )


def _new_pattern() -> Scenario:
    start, end = ANOMALY_S, ANOMALY_S + 240
    return Scenario(
        name="new_pattern",
        description="auth-service starts logging a never-seen HSM warning (error rate unchanged)",
        duration_s=900,
        seed=46,
        injected=(
            # WARNING, not ERROR, so this scenario isolates NEW_PATTERN from ERROR_RATE.
            InjectedTemplate(
                AUTH,
                "WARNING",
                "HSM key rotation failed kid={uuid} falling back to previous key",
                2.0,
                start,
                end,
            ),
        ),
        labels=(Label(start, end, "NEW_PATTERN", AUTH),),
    )


def _latency_spike() -> Scenario:
    start, end = ANOMALY_S, ANOMALY_S + 120
    return Scenario(
        name="latency_spike",
        description="payment-gateway latency jumps 15x (p50 ~180 ms -> ~2.7 s) for 2 minutes",
        duration_s=900,
        seed=47,
        plans=(ServicePlan(PG, latency_mult=RateCurve.step(1.0, 15.0, start, end)),),
        labels=(Label(start, end, "LATENCY", PG),),
    )


# Pre-defined scenarios, in the order listed in the module docstring.
SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in (
        Scenario(
            name="steady",
            description="Normal traffic with 1.5-2% error rates, no anomalies expected",
            duration_s=900,
            seed=42,
        ),
        _drift(),
        _burst(),
        _outage(),
        _silence(),
        _new_pattern(),
        _latency_spike(),
        Scenario(
            name="noisy_normal",
            description="auth-service at a steady 3% errors on low volume (noisy) — must NOT alert",
            duration_s=900,
            seed=48,
            plans=(
                ServicePlan(
                    AUTH,
                    volume_mult=RateCurve.constant(0.25),
                    error_rate=RateCurve.constant(0.03),
                ),
            ),
        ),
        Scenario(
            name="rotation",
            description="Log file rotated twice mid-stream — no data loss, no alerts expected",
            duration_s=900,
            seed=49,
            rotate_at_s=(300.0, 600.0),
        ),
        Scenario(
            name="malformed_flood",
            description="50% of lines are malformed — parser must survive, no alerts expected",
            duration_s=900,
            seed=50,
            malformed_ratio=0.5,
        ),
    )
}
