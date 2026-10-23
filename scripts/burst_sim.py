"""
TREMOR — Burst validation simulation.

Drives the real arrival window, baseline, detectors and alert lifecycle with synthetic
traffic: `rate` lines/s at a 2% error rate for `normal_s` seconds, then a burst.
Deterministic: errors are either spread evenly (exact fraction per line) or drawn from
a seeded RNG (binomial).

Usage:
    python -m scripts.burst_sim                 # moderate (10%) and severe (60%), both modes
    python -m scripts.burst_sim --all           # also print the warm-up ticks

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

import argparse
import random
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Literal

from app.config import Settings
from app.core.engine import DetectionEngine
from app.core.severity import Severity
from app.ingest.parser import LogEvent

Mode = Literal["even", "random"]

_OK = LogEvent(ts=0.0, level="INFO", service="sim", message="request ok")
_ERR = LogEvent(ts=0.0, level="ERROR", service="sim", message="request failed")


@dataclass(frozen=True, slots=True)
class Row:
    t: int  # seconds since start; the burst starts after t = normal_s
    n: int
    errors: int
    rate: float | None
    mu: float | None
    sigma_eff: float | None
    z: float | None
    severity: Severity | None  # this tick's error-rate severity
    state: str
    alerts: tuple[str, ...] = ()


@dataclass
class SimResult:
    burst_rate: float
    mode: Mode
    normal_s: int
    rows: list[Row] = field(default_factory=list)

    def burst_rows(self) -> list[Row]:
        return [r for r in self.rows if r.t > self.normal_s]

    def first_at(self, level: Severity) -> int | None:
        """Seconds after the burst start of the first tick at or above `level`."""
        for r in self.burst_rows():
            if r.severity is not None and r.severity >= level:
                return r.t - self.normal_s
        return None

    def peak(self) -> Severity | None:
        return max((r.severity for r in self.burst_rows() if r.severity), default=None)

    def alerts(self) -> list[tuple[int, str]]:
        return [(r.t - self.normal_s, a) for r in self.rows for a in r.alerts]

    def normal_alerts(self) -> list[str]:
        return [a for r in self.rows if r.t <= self.normal_s for a in r.alerts]


class _ErrorSource:
    def __init__(self, mode: Mode, seed: int) -> None:
        self.mode = mode
        self.rng = random.Random(seed)
        self._p = Fraction(0)
        self._i = 0

    def set_rate(self, p: float) -> None:
        self._p = Fraction(str(p))
        self._i = 0

    def next_is_error(self) -> bool:
        if self.mode == "random":
            return self.rng.random() < float(self._p)
        i, p = self._i, self._p
        self._i += 1
        return int((i + 1) * p) > int(i * p)


def simulate(
    burst_rate: float,
    mode: Mode = "even",
    *,
    seed: int = 42,
    lines_per_s: int = 10,
    base_rate: float = 0.02,
    normal_s: int = 90,
    burst_s: int = 60,
    cfg: Settings | None = None,
) -> SimResult:
    cfg = cfg or Settings(_env_file=None)
    engine = DetectionEngine(cfg, service="*")
    source = _ErrorSource(mode, seed)
    result = SimResult(burst_rate, mode, normal_s)

    for sec in range(normal_s + burst_s):
        if sec == 0:
            source.set_rate(base_rate)
        elif sec == normal_s:
            source.set_rate(burst_rate)
        for k in range(lines_per_s):
            event = _ERR if source.next_is_error() else _OK
            engine.observe(event, sec + (k + 1) / lines_per_s)
        res = engine.tick(float(sec + 1))
        er = res.error_rate
        assert er is not None
        result.rows.append(
            Row(
                t=sec + 1,
                n=er.n,
                errors=er.errors,
                rate=er.rate,
                mu=er.mu,
                sigma_eff=er.sigma_eff,
                z=er.z,
                severity=er.severity,
                state=res.tick.state,
                alerts=tuple(f"{a.status.value} {a.severity}" for a in res.alerts),
            )
        )
    return result


def _fmt(v: float | None, spec: str) -> str:
    return "-" if v is None else format(v, spec)


def print_result(result: SimResult, show_all: bool = False) -> None:
    title = f"burst to {result.burst_rate:.0%} ({result.mode} errors)"
    print(f"\n=== {title} ===")
    print(
        f"{'t':>4} {'+s':>4} {'n':>4} {'err':>4} {'r':>7} {'mu':>7} {'sig_eff':>7} "
        f"{'z':>7}  {'severity':<9}{'state':<13}alerts"
    )
    for r in result.rows:
        if not show_all and r.t <= result.normal_s - 5:
            continue
        since = r.t - result.normal_s
        sev = r.severity.name if r.severity else "-"
        print(
            f"{r.t:>4} {since:>+4} {r.n:>4} {r.errors:>4} {_fmt(r.rate, '.2%'):>7} "
            f"{_fmt(r.mu, '.2%'):>7} {_fmt(r.sigma_eff, '.4f'):>7} {_fmt(r.z, '.2f'):>7}  "
            f"{sev:<9}{r.state:<13}{', '.join(r.alerts)}"
        )
    print(f"--- {title}")
    print(f"    alerts before burst: {result.normal_alerts() or 'none'}")
    for level in Severity:
        at = result.first_at(level)
        print(f"    first {level.name:<8}: {'never' if at is None else f'+{at} s'}")
    peak = result.peak()
    print(f"    peak severity : {peak.name if peak else 'none'}")
    print(f"    alerts emitted: {result.alerts()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="print warm-up ticks too")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    for burst in (0.10, 0.60):
        for mode in ("even", "random"):
            print_result(simulate(burst, mode, seed=args.seed), args.all)


if __name__ == "__main__":
    main()
