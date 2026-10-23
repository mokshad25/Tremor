"""
TREMOR — Evaluation harness.

Usage: python -m eval.run --seed 42

Generates every labelled scenario, replays it through the pipeline on a FakeClock
(parser -> TemplateMiner -> detector.observe / detector.tick), and scores each
detector against the labels with the matching rule in ``eval.metrics``.
Compares TREMOR vs a static 5% threshold vs a rolling-mean-only baseline.
Reports precision, recall, F1, mean/median detection delay and false positives/hour.
Output: markdown tables printed to the console and written to docs/EVAL.md.

Owner: Mokshad (Phase 6)
"""

from __future__ import annotations

import argparse
import math
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from app.clock import FakeClock
from app.core.templates import TemplateMiner
from app.ingest.parser import parse_line
from eval.detectors import DETECTORS, ERROR_RATE
from eval.metrics import (
    DEFAULT_GRACE_S,
    EvalAlert,
    EvalResult,
    LabelWindow,
    ScenarioOutcome,
    aggregate,
    match_alerts,
)
from simulator.gen_logs import LogGenerator
from simulator.scenarios import SCENARIOS

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from app.ingest.parser import LogEvent
    from eval.detectors import EvalDetector
    from simulator.scenarios import Scenario

DEFAULT_SEED = 42
DEFAULT_OUT = Path("docs/EVAL.md")


@dataclass(frozen=True, slots=True)
class ReplayLine:
    """One parsed line, ready to hand to any detector."""

    arrival: float
    event: LogEvent
    template_id: str
    is_new: bool


@dataclass(frozen=True, slots=True)
class Replay:
    """A scenario after generation, parsing and template mining. Shared by all detectors."""

    scenario: Scenario
    start_ts: float
    lines: tuple[ReplayLine, ...]
    total_lines: int
    malformed: int

    @property
    def labels(self) -> list[LabelWindow]:
        """The scenario's labels, in the eval's terms."""
        return [
            LabelWindow(lb.start_s, lb.end_s, lb.signal_type, lb.service)
            for lb in self.scenario.labels
        ]


@dataclass(frozen=True, slots=True)
class DetectorRun:
    """One detector over all scenarios; ``result`` is None if the detector is unavailable."""

    name: str
    result: EvalResult | None
    error_rate_result: EvalResult | None
    unavailable_reason: str = ""


def build_replay(scenario: Scenario, seed: int) -> Replay:
    """Generate and pre-process a scenario once; arrival time = the line's virtual time.

    Template ids and ``is_new`` are computed once here, in arrival order, exactly as
    the production pipeline does: one shared miner, one ``add_message`` per event.
    """
    generator = LogGenerator(scenario, seed=f"{seed}:{scenario.name}")
    clock = FakeClock(start=generator.start_ts)
    miner = TemplateMiner(clock)
    lines: list[ReplayLine] = []
    total = malformed = 0
    for arrival, raw in generator.iter_lines():
        total += 1
        clock.set(max(clock.now(), arrival))
        event = parse_line(raw)
        if event is None:
            malformed += 1
            continue
        tid = miner.add_message(event.message, service=event.service, ts=arrival)
        lines.append(ReplayLine(arrival, event, tid, miner.is_new(tid, now=arrival)))
    return Replay(scenario, generator.start_ts, tuple(lines), total, malformed)


def run_detector(replay: Replay, detector: EvalDetector) -> list[EvalAlert]:
    """Drive one detector through a replay; returns alerts in scenario-relative time.

    Ticks once per virtual second, including seconds with no lines. A line arriving
    exactly on a tick boundary is observed before that tick (as in DETECTION_API.md).
    """
    start = replay.start_ts
    end = start + replay.scenario.duration_s
    alerts: list[EvalAlert] = []
    next_tick = start + 1.0

    def tick_until(limit: float) -> None:
        nonlocal next_tick
        while next_tick < limit:
            alerts.extend(detector.tick(next_tick))
            next_tick += 1.0

    for line in replay.lines:
        tick_until(line.arrival)
        detector.observe(line.event, line.arrival, line.template_id, line.is_new)
    tick_until(end + 1.0)
    return [EvalAlert(a.ts - start, a.signal_type, a.service) for a in alerts]


def _score(
    name: str, per_scenario: Sequence[tuple[Replay, list[EvalAlert]]], grace_s: float
) -> tuple[EvalResult, EvalResult]:
    outcomes: list[ScenarioOutcome] = []
    er_outcomes: list[ScenarioOutcome] = []
    for replay, alerts in per_scenario:
        labels = replay.labels
        duration = float(replay.scenario.duration_s)
        outcomes.append(
            match_alerts(replay.scenario.name, alerts, labels, duration_s=duration, grace_s=grace_s)
        )
        er_outcomes.append(
            match_alerts(
                replay.scenario.name,
                [a for a in alerts if a.signal_type == ERROR_RATE],
                [lb for lb in labels if lb.signal_type == ERROR_RATE],
                duration_s=duration,
                grace_s=grace_s,
            )
        )
    return aggregate(name, outcomes), aggregate(name, er_outcomes)


class EvalHarness:
    """Replays scenarios through every detector and renders the comparison."""

    def __init__(
        self,
        seed: int = DEFAULT_SEED,
        *,
        grace_s: float = DEFAULT_GRACE_S,
        scenarios: Mapping[str, Scenario] = SCENARIOS,
        detectors: Mapping[str, Callable[[], EvalDetector]] = DETECTORS,
    ) -> None:
        """Configure a run. Scenario seeds are derived from ``seed`` and the scenario name."""
        self.seed = seed
        self.grace_s = grace_s
        self.scenarios = dict(scenarios)
        self.detectors = dict(detectors)
        self._replays: dict[str, Replay] = {}

    def replay(self, name: str) -> Replay:
        """The (cached) replay for one scenario."""
        if name not in self._replays:
            self._replays[name] = build_replay(self.scenarios[name], self.seed)
        return self._replays[name]

    def run_scenario(
        self, scenario: Scenario, detector_fn: Callable[[], EvalDetector]
    ) -> list[EvalAlert]:
        """Alerts one fresh detector raises on one scenario (scenario-relative times)."""
        return run_detector(self.replay(scenario.name), detector_fn())

    def run(self) -> list[DetectorRun]:
        """Run every detector on every scenario."""
        runs: list[DetectorRun] = []
        for name, factory in self.detectors.items():
            try:
                per_scenario = [
                    (self.replay(s.name), self.run_scenario(s, factory))
                    for s in self.scenarios.values()
                ]
            except NotImplementedError as exc:
                runs.append(DetectorRun(name, None, None, str(exc)))
                continue
            result, er_result = _score(name, per_scenario, self.grace_s)
            runs.append(DetectorRun(name, result, er_result))
        return runs

    def compare(self, runs: Sequence[DetectorRun]) -> str:
        """Render the full markdown report (deterministic: no timestamps)."""
        return render_markdown(self, runs)


# ── Rendering ─────────────────────────────────────────────────────────


def _fmt(value: float | None, pct: bool = False, digits: int = 1) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "—"
    return f"{value * 100:.{digits}f}%" if pct else f"{value:.{digits}f}"


def _metric_rows(runs: Sequence[DetectorRun], pick: str) -> list[str]:
    def cell(run: DetectorRun, fn: Callable[[EvalResult], str]) -> str:
        result = run.result if pick == "all" else run.error_rate_result
        return "n/a" if result is None else fn(result)

    rows = [
        ("Precision", lambda r: _fmt(r.precision, pct=True)),
        ("Recall", lambda r: _fmt(r.recall, pct=True)),
        ("F1", lambda r: _fmt(r.f1, digits=3)),
        ("Mean detection delay (s)", lambda r: _fmt(r.mean_delay_s)),
        ("Median detection delay (s)", lambda r: _fmt(r.median_delay_s)),
        ("False positives / hour", lambda r: _fmt(r.false_positives_per_hour, digits=2)),
        (
            "TP / FP / FN / dup",
            lambda r: f"{r.true_positives} / {r.false_positives} / "
            f"{r.false_negatives} / {r.duplicates}",
        ),
    ]
    header = "| Metric | " + " | ".join(r.name for r in runs) + " |"
    sep = "|---|" + "---|" * len(runs)
    body = [f"| {label} | " + " | ".join(cell(r, fn) for r in runs) + " |" for label, fn in rows]
    return [header, sep, *body]


def _scenario_cell(outcome: ScenarioOutcome) -> str:
    mark = "✅" if outcome.correct else "❌"
    parts = [f"{outcome.detected}/{outcome.labels} detected"] if outcome.labels else []
    if outcome.false_positives:
        parts.append(f"{outcome.false_positives} FP")
    if outcome.delays:
        parts.append("delay " + ", ".join(f"{d:.0f}s" for d in outcome.delays))
    return f"{mark} " + ("; ".join(parts) if parts else "quiet")


def _headline(runs: Sequence[DetectorRun]) -> str:
    scored = [r for r in runs if r.result is not None]
    if not scored:
        return "No detector could be run."
    lines = []
    for run in scored:
        assert run.result is not None
        correct = sum(o.correct for o in run.result.scenarios)
        lines.append(
            f"- **{run.name}**: {correct}/{len(run.result.scenarios)} scenarios fully correct, "
            f"F1 {_fmt(run.result.f1, digits=3)}, "
            f"{_fmt(run.result.false_positives_per_hour, digits=2)} false positives/hour."
        )
    missing = [r for r in runs if r.result is None]
    for run in missing:
        lines.append(f"- **{run.name}**: not evaluated ({run.unavailable_reason}).")
    return "\n".join(lines)


def render_markdown(harness: EvalHarness, runs: Sequence[DetectorRun]) -> str:
    """The full EVAL.md contents."""
    replays = [harness.replay(name) for name in harness.scenarios]
    total_lines = sum(r.total_lines for r in replays)
    hours = sum(r.scenario.duration_s for r in replays) / 3600
    out = [
        "# TREMOR — Evaluation Results",
        "",
        f"> Generated by `python -m eval.run --seed {harness.seed}`. Do not edit by hand.",
        "",
        f"{len(replays)} scenarios, {total_lines:,} generated lines, {hours:.2f} h of simulated "
        f"traffic. Matching grace: {harness.grace_s:.0f} s. Matching rule and metric definitions: "
        "`docs/TRADEOFFS.md` → *Eval matching rule*.",
        "",
        "## Headline",
        "",
        _headline(runs),
        "",
        "## All signals",
        "",
        *_metric_rows(runs, "all"),
        "",
        "## ERROR_RATE only (apples-to-apples: the baselines only detect error rate)",
        "",
        *_metric_rows(runs, "error_rate"),
        "",
        "## Per-scenario breakdown",
        "",
        "| Scenario | Expected | " + " | ".join(r.name for r in runs) + " |",
        "|---|---|" + "---|" * len(runs),
    ]
    for i, replay in enumerate(replays):
        expected = (
            ", ".join(
                f"{lb.signal_type} {lb.service} [{lb.start:.0f}–{lb.end:.0f}s]"
                for lb in replay.labels
            )
            or "no alerts"
        )
        cells = ["n/a" if r.result is None else _scenario_cell(r.result.scenarios[i]) for r in runs]
        out.append(f"| {replay.scenario.name} | {expected} | " + " | ".join(cells) + " |")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(prog="python -m eval.run", description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--grace", type=float, default=DEFAULT_GRACE_S, help="seconds")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIOS), default=None)
    parser.add_argument("--no-write", action="store_true", help="print only")
    args = parser.parse_args(argv)

    scenarios = {name: SCENARIOS[name] for name in args.scenario} if args.scenario else SCENARIOS
    harness = EvalHarness(args.seed, grace_s=args.grace, scenarios=scenarios)
    report = harness.compare(harness.run())
    print(report)
    if not args.no_write:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
