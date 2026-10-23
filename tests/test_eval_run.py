"""
TREMOR — Eval harness tests (replay loop, reporting, CLI).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

try:
    from eval.run import EvalHarness, build_replay, main, run_detector
    from simulator.scenarios import SCENARIOS, Label, RateCurve, Scenario, ServicePlan
except ImportError:  # pragma: no cover - needs the templates + simulator branches merged
    pytest.skip("TemplateMiner / LogGenerator not on this branch yet", allow_module_level=True)

from eval.detectors import StaticThresholdDetector
from eval.metrics import EvalAlert

if TYPE_CHECKING:
    from pathlib import Path

    from app.ingest.parser import LogEvent

PG = "payment-gateway"
TINY = Scenario(
    name="tiny",
    description="pg errors spike to 90% on [60, 90)",
    duration_s=120,
    seed=1,
    warmup_s=30,
    plans=(ServicePlan(PG, error_rate=RateCurve.step(0.02, 0.9, 60, 90)),),
    labels=(Label(60, 90, "ERROR_RATE", PG),),
)


class Recorder:
    """Detector that records calls and alerts once, at t = 75 s (scenario time)."""

    name = "Recorder"

    def __init__(self) -> None:
        self.ticks: list[float] = []
        self.observed: list[float] = []

    def observe(
        self,
        event: LogEvent,
        arrival: float,
        template_id: str | None = None,
        is_new_template: bool = False,
    ) -> None:
        assert template_id is not None and template_id.startswith("T")
        self.observed.append(arrival)

    def tick(self, now: float) -> list[EvalAlert]:
        self.ticks.append(now)
        if len(self.ticks) == 75:
            return [EvalAlert(now, "ERROR_RATE", PG)]
        return []


def test_run_detector_ticks_every_second_and_orders_calls() -> None:
    replay = build_replay(TINY, seed=42)
    rec = Recorder()
    alerts = run_detector(replay, rec)
    start = replay.start_ts
    assert rec.ticks == [start + s for s in range(1, 121)]  # every second, incl. the last
    assert len(rec.observed) == len(replay.lines)
    # every line is observed before the first tick at or after its arrival
    assert rec.observed == sorted(rec.observed)
    assert alerts == [EvalAlert(75.0, "ERROR_RATE", PG)]  # scenario-relative time


def test_replay_counts_and_novelty() -> None:
    replay = build_replay(SCENARIOS["new_pattern"], seed=42)
    assert replay.malformed == 0
    assert replay.total_lines == len(replay.lines)
    injected = [ln for ln in replay.lines if "HSM key rotation failed" in ln.event.message]
    assert injected, "scenario must inject the new template"
    assert len({ln.template_id for ln in injected}) == 1
    assert injected[0].is_new  # first seen long after the miner's warm-up
    assert not any(ln.is_new for ln in replay.lines if ln.arrival - replay.start_ts < 300)

    flood = build_replay(SCENARIOS["malformed_flood"], seed=42)
    assert 0.45 < flood.malformed / flood.total_lines < 0.55


def test_harness_scores_baselines_and_reports_tremor_unavailable() -> None:
    harness = EvalHarness(42, scenarios={"tiny": TINY})
    runs = {r.name: r for r in harness.run()}
    static = runs["Static 5%"]
    assert static.result is not None and static.result.true_positives == 1
    tremor = runs["TREMOR"]
    assert tremor.result is not None and tremor.result.true_positives == 1
    report = harness.compare(list(runs.values()))
    assert "## All signals" in report and "## ERROR_RATE only" in report
    assert "| tiny |" in report


def test_run_scenario_alias_matches_run_detector() -> None:
    harness = EvalHarness(42, scenarios={"tiny": TINY})
    via_harness = harness.run_scenario(TINY, StaticThresholdDetector)
    via_function = run_detector(build_replay(TINY, 42), StaticThresholdDetector())
    assert via_harness == via_function


def test_report_is_deterministic() -> None:
    def report() -> str:
        harness = EvalHarness(42, scenarios={"tiny": TINY})
        return harness.compare(harness.run())

    assert report() == report()
    other = EvalHarness(7, scenarios={"tiny": TINY})
    assert other.compare(other.run()) != report()


def test_cli_writes_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "EVAL.md"
    assert main(["--seed", "42", "--scenario", "burst", "--out", str(out)]) == 0
    text = out.read_text()
    assert text.startswith("# TREMOR — Evaluation Results")
    assert "--seed 42" in text
    assert "| burst |" in text
    assert "wrote" in capsys.readouterr().out
