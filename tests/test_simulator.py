"""
TREMOR — Log generator tests.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from collections import Counter
from typing import TYPE_CHECKING

import pytest

from app.clock import SystemClock
from app.ingest.parser import parse_line
from app.ingest.tailer import Tailer
from simulator.gen_logs import (
    DEFAULT_SERVICES,
    DEFAULT_START_TS,
    LogGenerator,
    format_ts,
    hour_of_day_factor,
    main,
)
from simulator.scenarios import SCENARIOS, Scenario

if TYPE_CHECKING:
    from pathlib import Path


def short(duration_s: int = 60, seed: int = 7) -> Scenario:
    return Scenario(name="short", description="", duration_s=duration_s, seed=seed)


def offline_text(gen: LogGenerator) -> str:
    return "".join(f"{line}\n" for _, line in gen.iter_lines())


async def no_sleep(_: float) -> None:
    return None


PII_RAW = re.compile(r"@|sk_test_|Bearer eyJ|4111111111111111|5555 5555 5555 4444|3782-822463")


# ── Determinism ───────────────────────────────────────────────────────


def test_same_seed_is_byte_identical() -> None:
    assert offline_text(LogGenerator(short())) == offline_text(LogGenerator(short()))


def test_different_seed_differs() -> None:
    assert offline_text(LogGenerator(short(seed=1))) != offline_text(LogGenerator(short(seed=2)))


def test_seed_override_matches_scenario_seed() -> None:
    assert offline_text(LogGenerator(short(seed=5))) == offline_text(
        LogGenerator(short(seed=99), seed=5)
    )


def test_generate_line_does_not_disturb_stream() -> None:
    gen = LogGenerator(short())
    gen.generate_line("ledger", "ERROR", DEFAULT_START_TS)
    assert offline_text(gen) == offline_text(LogGenerator(short()))


# ── Shape of the stream ───────────────────────────────────────────────


def test_timestamps_ordered_and_in_range() -> None:
    lines = list(LogGenerator(short(120)).iter_lines())
    stamps = [ts for ts, _ in lines]
    assert stamps == sorted(stamps)
    assert stamps[0] >= DEFAULT_START_TS
    assert stamps[-1] <= DEFAULT_START_TS + 120


def test_every_line_parses_and_formats_match_profiles() -> None:
    fmt = {p.name: p.fmt for p in DEFAULT_SERVICES}
    for ts, line in LogGenerator(short(120)).iter_lines():
        event = parse_line(line)
        assert event is not None, line
        assert event.ts == pytest.approx(ts, abs=1e-3)
        if fmt[event.service] == "json":
            assert json.loads(line)["duration_ms"] == event.duration_ms
            assert event.duration_ms is not None and event.duration_ms > 0
        else:
            assert not line.startswith("{")


def test_steady_error_rates_and_volume() -> None:
    scenario = SCENARIOS["steady"]
    counts: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    for _, line in LogGenerator(scenario).iter_lines():
        event = parse_line(line)
        assert event is not None
        counts[event.service] += 1
        errors[event.service] += event.level == "ERROR"

    for profile in DEFAULT_SERVICES:
        assert 0.01 <= profile.error_rate <= 0.03
        n = counts[profile.name]
        sd = math.sqrt(profile.error_rate * (1 - profile.error_rate) / n)
        assert abs(errors[profile.name] / n - profile.error_rate) < 4 * sd
        expected = sum(
            profile.base_rate_per_s * hour_of_day_factor(DEFAULT_START_TS + s)
            for s in range(scenario.duration_s)
        )
        assert abs(n - expected) / expected < 0.10


def test_hour_of_day_pattern() -> None:
    day = DEFAULT_START_TS - DEFAULT_START_TS % 86_400
    assert hour_of_day_factor(day + 15 * 3600) == pytest.approx(1.4)
    assert hour_of_day_factor(day + 3 * 3600) == pytest.approx(0.6)


def test_format_ts() -> None:
    assert format_ts(1_767_621_600_007) == "2026-01-05T14:00:00.007Z"


# ── PII ───────────────────────────────────────────────────────────────


def test_fake_pii_present_raw_and_redacted_after_parse() -> None:
    raw_hits: Counter[str] = Counter()
    for _, line in LogGenerator(short(300)).iter_lines():
        for match in PII_RAW.findall(line):
            raw_hits[match] += 1
        event = parse_line(line)
        assert event is not None
        assert not PII_RAW.search(event.message), event.message
    assert set(raw_hits) == {
        "@",
        "sk_test_",
        "Bearer eyJ",
        "4111111111111111",
        "5555 5555 5555 4444",
        "3782-822463",
    }


def test_generate_line_respects_level() -> None:
    gen = LogGenerator(short())
    for service in ("payment-gateway", "auth-service", "ledger"):
        for level in ("INFO", "WARNING", "ERROR"):
            event = parse_line(gen.generate_line(service, level, DEFAULT_START_TS + 5))
            assert event is not None
            assert (event.service, event.level) == (service, level)


# ── Real-time writer ──────────────────────────────────────────────────


async def test_write_file_matches_offline(tmp_path: Path) -> None:
    gen = LogGenerator(short())
    out = tmp_path / "app.log"
    written = await gen.write_file(out, sleep=no_sleep)
    expected = offline_text(LogGenerator(short()))
    assert out.read_text() == expected
    assert written == expected.count("\n")


async def test_write_file_paces_by_virtual_time(tmp_path: Path) -> None:
    slept: list[float] = []

    async def record(delay: float) -> None:
        slept.append(delay)

    gen = LogGenerator(short(60))
    await gen.write_file(tmp_path / "app.log", speed=10, sleep=record)
    last_second = math.floor(list(gen.iter_lines())[-1].ts - DEFAULT_START_TS)
    assert sum(slept) == pytest.approx(last_second / 10)
    assert all(d > 0 for d in slept)


async def test_write_file_truncates_unless_append(tmp_path: Path) -> None:
    out = tmp_path / "app.log"
    out.write_text("old line\n")
    await LogGenerator(short()).write_file(out, sleep=no_sleep)
    assert not out.read_text().startswith("old line")
    out.write_text("old line\n")
    await LogGenerator(short()).write_file(out, sleep=no_sleep, append=True)
    assert out.read_text().startswith("old line\n")


async def test_write_file_rotation_loses_nothing(tmp_path: Path) -> None:
    out = tmp_path / "app.log"
    await LogGenerator(short(90)).write_file(out, sleep=no_sleep, rotate_at_s=[30, 60])
    parts = [tmp_path / "app.log.2", tmp_path / "app.log.1", out]
    assert all(p.exists() and p.stat().st_size > 0 for p in parts)
    assert "".join(p.read_text() for p in parts) == offline_text(LogGenerator(short(90)))
    first_after = parse_line(out.read_text().splitlines()[0])
    assert first_after is not None and first_after.ts >= DEFAULT_START_TS + 60


async def test_write_file_rejects_bad_speed(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        await LogGenerator(short()).write_file(tmp_path / "x.log", speed=0)


@pytest.mark.integration
async def test_tailer_reads_through_rotation(tmp_path: Path) -> None:
    out = tmp_path / "app.log"
    out.touch()
    expected = [line for _, line in LogGenerator(short(20)).iter_lines()]
    queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
    tailer = Tailer(str(out), "sim", queue, SystemClock(), start_pos="beginning", poll_ms=5)
    await tailer.run()
    try:
        await LogGenerator(short(20)).write_file(out, speed=100, rotate_at_s=[10])
        received: list[str] = []
        async with asyncio.timeout(5):
            while len(received) < len(expected):
                received.append((await queue.get())[1])
    finally:
        await tailer.stop()
    assert received == expected


# ── CLI ───────────────────────────────────────────────────────────────


def test_cli_offline_is_reproducible(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    assert main(["--scenario", "steady", "--offline", "--out", str(a)]) == 0
    assert main(["--scenario", "steady", "--offline", "--out", str(b)]) == 0
    assert a.read_bytes() == b.read_bytes()
    assert a.stat().st_size > 0
    assert "wrote" in capsys.readouterr().out
