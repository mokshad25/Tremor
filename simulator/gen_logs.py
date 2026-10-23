"""
TREMOR — Log generator.

Generates realistic fintech log lines for payment-gateway, auth-service and ledger.
Poisson arrivals, a 1-3% baseline error rate, an hour-of-day volume pattern, and
fake PII (emails, test cards, bearer tokens, API keys) so redaction is exercised.

Two modes share one code path:
- ``LogGenerator.iter_lines()``: offline iterator of ``(ts, line)`` in virtual time
  (eval, tests). Nothing reads the wall clock.
- ``LogGenerator.write_file()``: async writer that replays the same lines into a
  file in (scaled) real time, with optional logrotate-style rotation.

The same scenario and seed always produce byte-identical output.

Usage: python -m simulator.gen_logs --scenario steady --out sample/app.log [--speed 10]

Owner: Mokshad (Phase 1 for steady, Phase 6 for all scenarios)
"""

from __future__ import annotations

import argparse
import asyncio
import heapq
import json
import math
import random
import string
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal, NamedTuple, TextIO

from simulator.scenarios import SCENARIOS, InjectedTemplate, Scenario

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator, Sequence

    Sleep = Callable[[float], Awaitable[None]]

DEFAULT_START_TS = 1_767_621_600.0  # 2026-01-05T14:00:00Z, a Monday afternoon
WARN_RATE = 0.03
LATENCY_SIGMA = 0.35
LEVEL_TEXT = {"INFO": "INFO", "WARNING": "WARN", "ERROR": "ERROR"}


class GeneratedLine(NamedTuple):
    """One generated log line and its event time (Unix seconds, ms precision)."""

    ts: float
    line: str


@dataclass(frozen=True, slots=True)
class ServiceProfile:
    """Steady-state behaviour of one simulated service."""

    name: str
    base_rate_per_s: float
    error_rate: float
    latency_p50_ms: float
    fmt: Literal["json", "text"]


DEFAULT_SERVICES: tuple[ServiceProfile, ...] = (
    ServiceProfile("payment-gateway", 8.0, 0.020, 180.0, "json"),
    ServiceProfile("auth-service", 6.0, 0.015, 60.0, "text"),
    ServiceProfile("ledger", 4.0, 0.015, 90.0, "text"),
)

# ── Message catalogue ─────────────────────────────────────────────────

_TEMPLATES: dict[str, dict[str, tuple[str, ...]]] = {
    "payment-gateway": {
        "INFO": (
            "Payment authorized {txn} amount={amount} {cur} merchant={merchant} card {card}",
            "Capture settled {txn} amount={amount} {cur} in {ms}ms",
            "Refund issued re_{hex} for {txn} amount={amount} {cur}",
            "3DS challenge completed for {txn} customer={email}",
        ),
        "WARNING": (
            "Card declined {txn} reason={decline} card {card}",
            "Retrying acquirer call {txn} attempt={attempt} after {ms}ms",
        ),
        "ERROR": (
            "Acquirer timeout {txn} after {ms}ms upstream={ip}",
            "Payment failed {txn} code={code} for {email}",
        ),
    },
    "auth-service": {
        "INFO": (
            "Login succeeded user={email} ip={ip} session=sess_{hex}",
            "Token refreshed Authorization: Bearer {jwt} expires_in={ttl}",
            "MFA challenge passed user={email} method={mfa}",
        ),
        "WARNING": ("Login failed user={email} ip={ip} attempts={attempt}",),
        "ERROR": (
            "Token validation failed Authorization: Bearer {jwt} reason=signature_mismatch",
            "Rate limit store unreachable at {ip} after {ms}ms",
        ),
    },
    "ledger": {
        "INFO": (
            "Ledger entry posted acct_{hex} amount={amount} {cur} journal={uuid}",
            "Balance check acct_{hex} balance={amount} {cur}",
            "Reconciliation batch {uuid} completed entries={entries}",
        ),
        "WARNING": ("Slow query on ledger_entries took {ms}ms",),
        "ERROR": (
            "DB timeout posting acct_{hex} after {ms}ms",
            "Webhook signing failed for endpoint {uuid} key={sk}",
        ),
    },
}

# Published Luhn-valid test card numbers, in the formats people actually log.
_TEST_CARDS = ("4111111111111111", "5555 5555 5555 4444", "3782-822463-10005")
_FIRST = ("alice", "bob", "carol", "dev", "erin", "farah", "gopal", "hana")
_LAST = ("smith", "khan", "garcia", "iyer", "chen", "okafor")
_DOMAINS = ("example.com", "mail.test", "corp.example")
_MERCHANTS = ("acme_books", "blue_cafe", "metro_rail", "pixel_store")
_ALNUM = string.ascii_letters + string.digits
_B64URL = _ALNUM + "-_"


def _hex(rng: random.Random, n: int) -> str:
    return f"{rng.getrandbits(4 * n):0{n}x}"


def _chars(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


_FILLERS: dict[str, Callable[[random.Random], str]] = {
    "txn": lambda r: f"txn_{_hex(r, 12)}",
    "hex": lambda r: _hex(r, 10),
    "amount": lambda r: f"{r.uniform(1, 2500):.2f}",
    "cur": lambda r: r.choice(("USD", "EUR", "GBP", "INR")),
    "merchant": lambda r: r.choice(_MERCHANTS),
    "card": lambda r: r.choice(_TEST_CARDS),
    "email": lambda r: f"{r.choice(_FIRST)}.{r.choice(_LAST)}{r.randint(1, 99)}@"
    f"{r.choice(_DOMAINS)}",
    "ip": lambda r: f"10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}",
    "decline": lambda r: r.choice(("insufficient_funds", "do_not_honor", "expired_card")),
    "attempt": lambda r: str(r.randint(1, 4)),
    "code": lambda r: r.choice(("502", "503", "504", "ACQ_TIMEOUT")),
    "jwt": lambda r: f"eyJhbGciOiJIUzI1NiJ9.{_chars(r, _B64URL, 24)}.{_chars(r, _B64URL, 16)}",
    "ttl": lambda r: str(r.choice((900, 1800, 3600))),
    "mfa": lambda r: r.choice(("totp", "sms", "webauthn")),
    "uuid": lambda r: str(uuid.UUID(int=r.getrandbits(128), version=4)),
    "entries": lambda r: str(r.randint(50, 5000)),
    "sk": lambda r: f"sk_test_{_chars(r, _ALNUM, 24)}",
}


class _Fill(dict[str, str]):
    """Lazily generates template fields in the order ``format_map`` asks for them."""

    def __init__(self, rng: random.Random, ms: int) -> None:
        super().__init__(ms=str(ms))
        self._rng = rng

    def __missing__(self, key: str) -> str:
        value = _FILLERS[key](self._rng)
        self[key] = value
        return value


def hour_of_day_factor(ts: float) -> float:
    """Traffic multiplier by UTC hour: peaks at 15:00 (x1.4), bottoms at 03:00 (x0.6)."""
    hour = (ts % 86_400) / 3_600
    return 1.0 + 0.4 * math.sin(2 * math.pi * (hour - 9) / 24)


def format_ts(ts_ms: int) -> str:
    """ISO-8601 UTC with millisecond precision, e.g. ``2026-01-05T14:00:00.123Z``."""
    seconds, ms = divmod(ts_ms, 1000)
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


async def _no_sleep(_: float) -> None:
    return None


class LogGenerator:
    """Seeded, deterministic log generator for one scenario."""

    def __init__(
        self,
        scenario: Scenario,
        *,
        seed: int | str | None = None,
        start_ts: float = DEFAULT_START_TS,
        services: Sequence[ServiceProfile] = DEFAULT_SERVICES,
    ) -> None:
        """Create a generator.

        Args:
            scenario: What to simulate (duration, and later rate curves and labels).
            seed: Overrides ``scenario.seed``. The same seed gives byte-identical output.
            start_ts: Virtual start time (Unix seconds).
            services: Service profiles to simulate.
        """
        self._scenario = scenario
        self._seed = scenario.seed if seed is None else seed
        self._start_ts = start_ts
        self._services = tuple(services)
        self._profiles = {p.name: p for p in self._services}
        self._plans = {p.name: scenario.plan_for(p.name) for p in self._services}
        self._adhoc_rng = random.Random(f"{self._seed}:adhoc")

    @property
    def start_ts(self) -> float:
        """Virtual start time of the scenario."""
        return self._start_ts

    # ── Offline mode ──────────────────────────────────────────────────

    def iter_lines(self) -> Iterator[GeneratedLine]:
        """Yield every line of the scenario in timestamp order, in virtual time."""
        streams = [self._service_stream(i, p) for i, p in enumerate(self._services)]
        base = len(streams)
        streams += [
            self._injected_stream(base + i, inj) for i, inj in enumerate(self._scenario.injected)
        ]
        if self._scenario.malformed_ratio > 0:
            streams.append(self._malformed_stream(base + len(self._scenario.injected)))
        for ts_ms, _idx, _seq, line in heapq.merge(*streams):
            yield GeneratedLine(ts_ms / 1000, line)

    def generate_line(self, service: str, level: str, ts: float) -> str:
        """Render a single line for ``service`` at ``level`` (INFO/WARNING/ERROR).

        Uses its own RNG stream, so calling it never changes ``iter_lines()`` output.
        """
        profile = self._profiles[service]
        latency = self._latency(self._adhoc_rng, profile, ts - self._start_ts)
        return self._render(self._adhoc_rng, profile, level, round(ts * 1000), latency)

    # ── Real-time mode ────────────────────────────────────────────────

    async def write_file(
        self,
        path: str | Path,
        *,
        speed: float = 1.0,
        sleep: Sleep = asyncio.sleep,
        rotate_at_s: Sequence[float] | None = None,
        append: bool = False,
    ) -> int:
        """Write the scenario to ``path``, pacing lines by virtual time.

        Args:
            path: Output log file.
            speed: Virtual seconds per real second (10 = ten times faster).
            sleep: Awaitable used for pacing. Inject a no-op for instant output.
            rotate_at_s: Scenario-relative times at which to rotate the file
                (``app.log`` -> ``app.log.1``, older files shift up).
            append: Keep existing content instead of truncating first.

        Returns:
            Number of lines written.
        """
        if speed <= 0:
            raise ValueError("speed must be positive")
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        rotations = sorted(self._scenario.rotate_at_s if rotate_at_s is None else rotate_at_s)
        batch: list[str] = []
        written = 0
        current = 0
        fh = out.open("a" if append else "w", encoding="utf-8")
        try:
            for ts, line in self.iter_lines():
                second = math.floor(ts - self._start_ts)
                if second > current:
                    written += _flush(fh, batch)
                    await sleep((second - current) / speed)
                    current = second
                while rotations and second >= rotations[0]:
                    written += _flush(fh, batch)
                    fh.close()
                    _rotate(out)
                    fh = out.open("a", encoding="utf-8")
                    rotations.pop(0)
                batch.append(line)
            written += _flush(fh, batch)
        finally:
            fh.close()
        return written

    # ── Internals ─────────────────────────────────────────────────────

    def _service_stream(
        self, idx: int, profile: ServiceProfile
    ) -> Iterator[tuple[int, int, int, str]]:
        """Poisson arrivals for one service, as (ts_ms, service_idx, seq, line)."""
        rng = random.Random(f"{self._seed}:{profile.name}")
        seq = 0
        for second in range(self._scenario.duration_s):
            base = self._start_ts + second
            lam = self._rate(profile, second, base)
            if lam <= 0:
                continue
            # Exponential gaps are memoryless, so restarting each second at the
            # boundary is exact for a piecewise-constant rate.
            offset = rng.expovariate(lam)
            while offset < 1.0:
                t_rel = second + offset
                level = self._level(rng, profile, t_rel)
                latency = self._latency(rng, profile, t_rel)
                ts_ms = round((base + offset) * 1000)
                yield ts_ms, idx, seq, self._render(rng, profile, level, ts_ms, latency)
                seq += 1
                offset += rng.expovariate(lam)

    def _rate(self, profile: ServiceProfile, t_rel: float, ts: float) -> float:
        return profile.base_rate_per_s * hour_of_day_factor(ts) * self._volume_mult(profile, t_rel)

    def _volume_mult(self, profile: ServiceProfile, t_rel: float) -> float:
        plan = self._plans.get(profile.name)
        return plan.volume_mult.value_at(t_rel) if plan else 1.0

    def _error_rate(self, profile: ServiceProfile, t_rel: float) -> float:
        plan = self._plans.get(profile.name)
        if plan is None or plan.error_rate is None:
            return profile.error_rate
        return plan.error_rate.value_at(t_rel)

    def _latency_mult(self, profile: ServiceProfile, t_rel: float) -> float:
        plan = self._plans.get(profile.name)
        return plan.latency_mult.value_at(t_rel) if plan else 1.0

    def _injected_stream(
        self, idx: int, inj: InjectedTemplate
    ) -> Iterator[tuple[int, int, int, str]]:
        """Poisson lines from an injected template over ``[start_s, end_s)``."""
        rng = random.Random(f"{self._seed}:inject:{idx}")
        profile = self._profiles[inj.service]
        seq = 0
        t_rel = inj.start_s + rng.expovariate(inj.rate_per_s)
        while t_rel < min(inj.end_s, self._scenario.duration_s):
            latency = self._latency(rng, profile, t_rel)
            ts_ms = round((self._start_ts + t_rel) * 1000)
            yield ts_ms, idx, seq, self._render(
                rng, profile, inj.level, ts_ms, latency, template=inj.template
            )
            seq += 1
            t_rel += rng.expovariate(inj.rate_per_s)

    def _malformed_stream(self, idx: int) -> Iterator[tuple[int, int, int, str]]:
        """Garbage lines at ``ratio / (1 - ratio)`` times the normal volume."""
        rng = random.Random(f"{self._seed}:malformed")
        ratio = self._scenario.malformed_ratio
        seq = 0
        for second in range(self._scenario.duration_s):
            base = self._start_ts + second
            normal = sum(self._rate(p, second, base) for p in self._services)
            lam = normal * ratio / (1.0 - ratio)
            if lam <= 0:
                continue
            offset = rng.expovariate(lam)
            while offset < 1.0:
                ts_ms = round((base + offset) * 1000)
                yield ts_ms, idx, seq, _malformed_line(rng, ts_ms)
                seq += 1
                offset += rng.expovariate(lam)

    def _level(self, rng: random.Random, profile: ServiceProfile, t_rel: float) -> str:
        roll = rng.random()
        error_rate = self._error_rate(profile, t_rel)
        if roll < error_rate:
            return "ERROR"
        if roll < error_rate + WARN_RATE:
            return "WARNING"
        return "INFO"

    def _latency(self, rng: random.Random, profile: ServiceProfile, t_rel: float) -> float:
        p50 = profile.latency_p50_ms * self._latency_mult(profile, t_rel)
        return round(p50 * math.exp(LATENCY_SIGMA * rng.gauss(0.0, 1.0)), 1)

    def _render(
        self,
        rng: random.Random,
        profile: ServiceProfile,
        level: str,
        ts_ms: int,
        latency: float,
        template: str | None = None,
    ) -> str:
        if template is None:
            template = rng.choice(_TEMPLATES[profile.name][level])
        message = template.format_map(_Fill(rng, round(latency)))
        stamp = format_ts(ts_ms)
        if profile.fmt == "json":
            record = {
                "timestamp": stamp,
                "level": level.lower(),
                "service": profile.name,
                "message": message,
                "duration_ms": latency,
            }
            return json.dumps(record, separators=(",", ":"))
        return f"{stamp} {LEVEL_TEXT[level]} {profile.name} {message}"


def _malformed_line(rng: random.Random, ts_ms: int) -> str:
    """A line the parser must reject: truncated JSON, no timestamp, stack frame, junk."""
    stamp = format_ts(ts_ms)
    kind = rng.randrange(4)
    if kind == 0:
        full = f'{{"timestamp":"{stamp}","level":"error","service":"ledger","message":"x"}}'
        return full[: rng.randint(10, len(full) - 2)]
    if kind == 1:
        return f"ERROR payment-gateway upstream reset by peer after {rng.randint(1, 900)}ms"
    if kind == 2:
        return f"    at com.pay.gateway.Charge.run(Charge.java:{rng.randint(10, 999)})"
    return "".join(rng.choice("\x00\x01\x1b#%&?~\ufffd") for _ in range(rng.randint(5, 40)))


def _flush(fh: TextIO, batch: list[str]) -> int:
    if not batch:
        return 0
    fh.write("".join(f"{line}\n" for line in batch))
    fh.flush()
    count = len(batch)
    batch.clear()
    return count


def _rotate(path: Path) -> None:
    """logrotate "create" mode: app.log.N -> app.log.N+1, app.log -> app.log.1, new app.log."""
    n = 1
    while path.with_name(f"{path.name}.{n}").exists():
        n += 1
    for i in range(n - 1, 0, -1):
        path.with_name(f"{path.name}.{i}").rename(path.with_name(f"{path.name}.{i + 1}"))
    if path.exists():
        path.rename(path.with_name(f"{path.name}.1"))
    path.touch()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: write a scenario to a log file."""
    parser = argparse.ArgumentParser(
        prog="python -m simulator.gen_logs", description="Generate TREMOR scenario logs."
    )
    parser.add_argument("--scenario", default="steady", choices=sorted(SCENARIOS))
    parser.add_argument("--out", default="sample/app.log")
    parser.add_argument("--seed", type=int, default=None, help="default: the scenario's seed")
    parser.add_argument("--speed", type=float, default=1.0, help="virtual seconds per second")
    parser.add_argument("--offline", action="store_true", help="write everything immediately")
    parser.add_argument("--append", action="store_true", help="append instead of truncating")
    parser.add_argument("--rotate-at", type=float, action="append", default=None, metavar="SECONDS")
    args = parser.parse_args(argv)

    generator = LogGenerator(SCENARIOS[args.scenario], seed=args.seed)
    written = asyncio.run(
        generator.write_file(
            args.out,
            speed=args.speed,
            sleep=_no_sleep if args.offline else asyncio.sleep,
            rotate_at_s=args.rotate_at,
            append=args.append,
        )
    )
    print(f"wrote {written} lines to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
