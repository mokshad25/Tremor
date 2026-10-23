"""Differential fixture for the Go masker: random strings built from the
characters TREMOR's mask regexes care about, masked by drain3's LogMasker with
TREMOR's exact masking instructions.

Usage: .venv/bin/python go/bench/drain3/export_masks.py OUT.jsonl.gz [--n 30000] [--seed 1]
"""

import argparse
import gzip
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from drain3.masking import LogMasker, MaskingInstruction  # noqa: E402

from app.core.templates import _MASKS  # noqa: E402

PIECES = [
    "0", "1", "7", "42", "255", "1.5", "3.14", "-", "+", ".", "..", "ms", "s", "m", "x", "_",
    " ", " ", " ", ":", "=", "/", ",", "(", ")", "0x", "0xFF", "abc", "deadbeef", "DEADBEEF",
    "a1b2c3d4e5f6", "f" * 12, "123456789012", "10.0.0.1", "192.168.1.300", "10.1.2.3:8080",
    "txn_", "acct_", "re_", "usr_ab12", "550e8400-e29b-41d4-a716-446655440000", "v2", "x86_64",
    "1e5", "1,000", "-12ms", "+3s", "200ms", "5s,", "2024-01-05T14:00:00.123Z", "<EMAIL>", "é", "1é",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--n", type=int, default=30000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    masker = LogMasker([MaskingInstruction(p, name) for p, name in _MASKS], "<", ">")
    with gzip.open(args.out, "wt", encoding="utf-8") as out:
        for _ in range(args.n):
            s = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 12)))
            out.write(json.dumps({"in": s, "out": masker.mask(s)}, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
