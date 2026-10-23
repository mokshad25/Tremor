"""Run the real drain3 (TREMOR's configuration) over a log file and record,
for every message, the cluster id drain3 assigned. The Go Drain port is tested
against this output (internal/drain/drain3_compare_test.go).

Usage (from the TREMOR repo root, with its virtualenv):
    .venv/bin/python go/bench/drain3/export_drain3.py sample/app.log OUT.jsonl.gz [--max-clusters N] [--max-children N] [--limit N]

Messages go through TREMOR's own parse_line (which redacts PII), exactly as in
the Python pipeline. Output: gzipped JSON lines
    {"config": {...}}                                   first line
    {"m": <message>, "id": <cluster id>}                one per message
    {"final": {<cluster id>: <template>, ...}}           last line
"""

import argparse
import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # TREMOR repo root
sys.path.insert(0, str(ROOT))

from drain3 import TemplateMiner  # noqa: E402

from app.core.templates import _MASKS, _build_config  # noqa: E402
from app.ingest.parser import parse_line  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("out")
    ap.add_argument("--sim-th", type=float, default=0.4)
    ap.add_argument("--depth", type=int, default=4)
    ap.add_argument("--max-clusters", type=int, default=1000)
    ap.add_argument("--max-children", type=int, default=100)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    cfg = _build_config(args.sim_th, args.depth, args.max_clusters)
    cfg.drain_max_children = args.max_children
    miner = TemplateMiner(config=cfg)
    n = 0
    with open(args.log, encoding="utf-8", errors="replace") as f, gzip.open(args.out, "wt", encoding="utf-8") as out:
        out.write(json.dumps({"config": {
            "sim_th": args.sim_th, "depth": args.depth, "max_clusters": args.max_clusters,
            "max_children": args.max_children, "masks": [list(m) for m in _MASKS],
        }}) + "\n")
        for raw in f:
            ev = parse_line(raw.rstrip("\n"))
            if ev is None:
                continue
            res = miner.add_log_message(ev.message)
            out.write(json.dumps({"m": ev.message, "id": res["cluster_id"]}) + "\n")
            n += 1
            if args.limit and n >= args.limit:
                break
        final = {c.cluster_id: c.get_template() for c in miner.drain.clusters}
        out.write(json.dumps({"final": final}) + "\n")
    print(f"{n} messages, {len(final)} live clusters, {miner.drain.clusters_counter} created -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
