"""Export TREMOR's 10 labelled scenarios for the Go evaluation harness.

For each scenario this runs the Python pipeline exactly as `python -m eval.run`
does (simulator -> parse_line -> replay), and writes:
  - every parsed line (arrival time, service, level, message),
  - the ground-truth labels,
  - the alerts the Python detectors open on it ("TREMOR", "TREMOR (WARNING+)",
    "Static 5%", "Rolling mean"), so Go can be compared alert by alert.

Usage (TREMOR repo root): .venv/bin/python go/bench/eval/export_scenarios.py OUT_DIR [--seed 42]
"""

import argparse
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from eval.detectors import DETECTORS  # noqa: E402
from eval.run import build_replay, run_detector  # noqa: E402
from simulator.scenarios import SCENARIOS  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, scenario in SCENARIOS.items():
        replay = build_replay(scenario, args.seed)
        python_alerts = {
            det: [[a.ts, a.signal_type, a.service] for a in run_detector(replay, factory())]
            for det, factory in DETECTORS.items()
        }
        header = {
            "name": name,
            "seed": args.seed,
            "duration_s": scenario.duration_s,
            "start_ts": replay.start_ts,
            "total_lines": replay.total_lines,
            "malformed": replay.malformed,
            "labels": [[lb.start, lb.end, lb.signal_type, lb.service] for lb in replay.labels],
            "python_alerts": python_alerts,
        }
        path = out_dir / f"{name}.jsonl.gz"
        with gzip.open(path, "wt", encoding="utf-8") as f:
            f.write(json.dumps(header) + "\n")
            for line in replay.lines:
                ev = line.event
                f.write(json.dumps([line.arrival, ev.service, ev.level, ev.message]) + "\n")
        print(f"{name}: {len(replay.lines)} lines, {len(header['labels'])} labels -> {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
