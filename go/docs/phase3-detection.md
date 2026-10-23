# Phase 3: sharding, Drain and adaptive baselines

## Result

On TREMOR's 10 labelled scenarios (seed 42; 226,104 parsed lines; 2.58 h of simulated traffic), the Go port produces **exactly the alerts the Python implementation produces**: the same time, signal and service, for all 4 detectors in all 10 scenarios. That means it also reproduces the numbers the original TREMOR claim rests on:

| (ERROR_RATE, the signal the claim covers) | TREMOR (WARNING+) | TREMOR (all severities) | Static 5% | Rolling mean |
|---|---|---|---|---|
| Recall | **100% (3/3)** | 100% | 100% | 100% |
| False positives / hour | **0.00** | 4.65 | 7.74 | 13.94 |
| Precision | 100% | 20% | 13% | 7.7% |
| Median detection delay | 4 s | 3 s | 2 s | 1 s |

"0 false alarms/hour with 100% recall" holds for **paging** alerts (WARNING and above). Counting INFO-level alerts too, there are 12 false positives over 2.58 h (4.65/h). The same was true in Python. The full report, including per-scenario results and the parity table, is in `bench/results/phase3/eval-warmup30.md`.

Recall on *all* signals is 57% (4/7) for every TREMOR variant, because NEW_PATTERN and LATENCY detectors were TODO stubs in the Python version as well. Those labels are counted as misses rather than excluded.

## Pipeline

```
dispatcher ──(ring: service.name → shard)──▶ shard goroutine
                                                ├─ per service: Drain tree      → template id
                                                └─ per service: detection Engine → alerts ──▶ alert stream
```

### Consistent-hash router (`internal/router/ring.go`)

- Each of N shards owns 512 points on a 64-bit ring (FNV-1a plus a SplitMix64 finaliser). A service goes to the first point clockwise from its hash.
- **Why a ring:** per-service state (Drain tree, baselines) lives on exactly one shard, which is why it needs no locks. Going from 8 to 9 shards with hash-mod-N remapped **89.0%** of 50,000 services; the ring moved **11.3%** (the ideal is 1/9 = 11.1%), and only *to* the new shard (`TestRingMovesFewServicesWhenAShardIsAdded`).
- **Why 512 virtual nodes (measured, 200k services):** at 128 vnodes the busiest of 8 shards held +23% over a fair share; at 256, +14%; at 512, within about ±11%. The ring is 64 KiB and a lookup takes 35 ns.
- **Limit:** this balances the *number of services* per shard, not traffic. One hot service is one shard's work. Splitting it would mean a different shard key and giving up single-owner state.
- **Checkpoints:** the router's ID (`ring-fnv1a-splitmix/8x512`) is stored in the checkpoint. A Phase 2 checkpoint written under `mod-fnv1a/8` is recognised as a different layout, and every shard replays from the minimum checkpoint, which can cause duplicates but never skips.

### Drain port (`internal/drain`)

A behaviour-for-behaviour port of drain3 0.9.11's `Drain`, including its quirks:

- fixed depth (`depth − 2` token levels below the length level);
- tokens containing a digit take the wildcard branch when inserting;
- the `max_children` overflow rules;
- ties on similarity go to more wildcards, then to the first inserted;
- an LRU cluster cache where scanning candidates does **not** refresh recency but a match does.

TREMOR's configuration: depth 4, sim_th 0.4, max_children 100, max_clusters 1000.

**Masking** happens before Drain, using TREMOR's six rules in the same order: UUID, 0x-hex, 12+ hex with a digit, IP[:port], prefixed IDs, numbers. Go's RE2 regex engine has no lookaround, which two of those rules use:

- the **HEX12** lookahead becomes a post-filter on each match (provably equivalent: there is no `\b` inside a word run);
- **NUM** is a hand-written matcher that reproduces Python's backtracking order (sign or no sign, greedy digits, fraction or not, `ms`/`s`/nothing, then the lookahead). For example, `1.5x` masks to `<NUM>.5x`, exactly as in Python.

**Verification against the real drain3** (`bench/drain3/export_*.py` generates the fixtures; `internal/drain/*_test.go` checks them):

| fixture | messages | result |
|---|---|---|
| `sample/app.log` through TREMOR's parser, TREMOR's config | 100,473 | identical cluster id for every message; identical 19 final templates |
| same log, `max_clusters=8, max_children=4` (stress: 7,793 clusters created, constant LRU eviction) | 30,000 | identical ids and the 8 final templates |
| 30,000 random strings built from tricky pieces, masked by drain3's `LogMasker` | 30,000 | all 28,336 ASCII inputs identical; the 1,664 inputs with non-ASCII characters differ |

The non-ASCII difference is a known, documented divergence: Python's `\b` and `\d` are Unicode-aware for `str` patterns, while Go's are ASCII-only. For example, `é1` has no word boundary before the `1` in Python but does in Go.

**Per-service trees.** Python used one shared drain3 tree for all services; Go gives each service its own tree, owned by its shard. The algorithm is the same, but template IDs (`T1`, `T2`, ...) are now per service. That's what lets shards work independently, and it means one noisy service can't evict another's templates from the LRU. The drain3 comparison runs a single tree, so it is apples to apples.

**Cost.** Mask + Drain is about 10.9 µs per message, of which **masking is 10.7 µs (98%)** and the tree 0.2 µs. That's five passes of Go's regexp, and it's the planned pprof-guided optimisation for Phase 7: a single-pass masker, checked against the same Python differential fixture.

### Detection (`internal/detect`)

This is a port of the Python modules `baseline.py`, `detectors/error_rate.py`, `detectors/silence.py`, `severity.py`, `alerts.py` and `engine.py`, with the same arithmetic.

- **Baseline.** Seeded from the mean and population variance of `warmup_ticks` values, then a gated EWMA: no update while an incident is open or when z ≥ `max_update_z`, so an incident never becomes the new normal.
  - `sigma_eff = max(sigma, sqrt(mu(1−mu)/n), sigma_min)`. The binomial floor stops a quiet service from paging on one unlucky error.
  - **Float parity detail:** since 3.12, Python's `sum()` over floats uses Neumaier compensated summation. `detect.PySum` reproduces CPython's exact algorithm (a test checks it against values printed by CPython 3.14). The EWMA keeps Python's `a * (x − mu)**2` grouping.
- **Error rate.** Computed over lines that *arrived* in the last 30 s, not their self-reported timestamps, so skewed or replayed clocks can't distort it.
  - Fewer than 20 lines: no verdict.
  - Above 50% errors: CRITICAL immediately, even while the baseline is still learning.
  - Otherwise, severity by z: INFO ≥ 3, WARNING ≥ 5, HIGH ≥ 8.
- **Silence.** After warm-up, no lines for 10 s raises HIGH. The first tick with lines again resolves it.
- **Alert lifecycle.**
  - At most one incident per (signal, service, template).
  - A notification is sent only when severity rises: OPEN, then ESCALATED.
  - An incident resolves after 10 clear ticks in a row; neutral ticks neither count nor reset.
  - Re-opening within 60 s reuses the incident ID.
- **Window, in constant memory.** Python keeps every line from the last 30 s in a deque, which at 100k lines/s for one service is 3M entries. Go buckets lines by the tick that first counts them, `ceil(arrival)`: a line counts at tick k exactly when `k−30 < arrival ≤ k`. That's the same set of lines in 31 buckets per service. A property test (`TestWindowMatchesNaiveDeque`) checks this against a naive deque on 20,000 random arrivals, including arrivals exactly on tick boundaries.

### Time: one clock for live, replay and eval

Shards don't read the wall clock to decide what happened. Each event's gateway receive time (`ReceivedAt`) advances the shard's clock, and before an event is observed, every whole-second tick strictly before its arrival runs. That's the Python harness's rule, which is why the eval harness can simply feed scenario events through the **production** `detect.Processor` (`internal/eval/detectors.go`). The parity result covers the code that runs in the server, not a copy of it.

- A 1 s wall-clock ticker (`shards.tick_interval`) advances the clock when no events arrive, so silence is still noticed.
- A clock jump larger than `max_catch_up_s` (1 h) skips ticks instead of replaying an hour of empty seconds. That only happens if the shard wasn't running, and replaying would just produce silence alerts about TREMOR's own downtime.

### Alerts

Each alert carries what the spec asks for:

- alert ID and stable incident ID;
- type, service and template ("top error template" in the window, as ID and text);
- the window `(window_end − 30, window_end]`;
- observed vs baseline (`value`, `baseline`, `z_score`, `lines`, `errors`);
- **source sequence numbers**: the WAL seq range of the window, plus a sample of the most recent error-line seqs, so the evidence can be fetched from the WAL.

The JSON field names follow the UI contract (`docs/ui-contract.md`). The `Tick` JSON matches the UI's `metric` message, including its ISO timestamp format (`TestTickJSONMatchesUIContract`).

Incident and alert IDs are **deterministic** (a hash of type, service, template and tick), so the same input always produces the same IDs. Downstream dedup (Phase 6) relies on this.

Until Phase 6 adds the correlator and sinks, alerts go to a bounded channel that is consumed into structured log lines and `alerts_*` counters at `/debug/vars`.

## Decisions and trade-offs

**Warm-up length (the under-learning finding).** The Python team noted that 30 warm-up ticks of *overlapping* 30 s windows is only about one minute of real data, so low-volume services learn a baseline that's too low. That's where all 12 INFO false positives come from. Measured with the Go port (`bench/results/phase3/eval-warmup*.md`):

| warmup_ticks | INFO-level FP/hour | ERROR_RATE recall | WARNING+ FP/hour |
|---|---|---|---|
| **30 (default, = Python)** | 4.65 | 100% | 0.00 |
| 60 | 2.32 | 100% | 0.00 |
| 120 | 1.55 | 100% | 0.00 |
| 300 | 1.16 | 100% | 0.00 |

A longer warm-up cuts INFO noise by up to 75% without losing recall. The cost is a blind period: until a service's baseline is seeded, only the CRITICAL rule (over 50% errors) can fire. Detection state isn't persisted, so that blind period recurs **after every restart**. The decision:

- keep 30 for exact parity with the original TREMOR;
- page only on WARNING+ (Phase 6 sinks);
- treat INFO as dashboard-only;
- record 120 as the recommended setting once baselines are persisted. That's a natural extension of the checkpoint (baselines are a few floats per service) and is listed as future work.

**Detection state after a crash.** Events are never lost (Phase 2), but baselines and Drain trees are rebuilt from scratch on restart. Replay covers only about the last second (the checkpoint interval), so a restarted shard re-learns for `warmup_ticks` seconds. An incident open at crash time is opened again under a different incident ID.

**Masking divergence.** On ASCII text the masks are identical to Python. On non-ASCII text adjacent to numbers, results can differ (Unicode `\b`/`\d`). That affects which messages share a template, but not error-rate detection, which doesn't use templates.

## Throughput with Drain and detection

`bench/maxrate.sh` with the full pipeline (gateway → WAL with fsync → ring → Drain + detection; 10 services, 8 shards; tremor and loadgen each at GOMAXPROCS=4):

| | max sustainable | notes |
|---|---|---|
| Phase 1: gateway only | 1,050,000 ev/s | |
| Phase 2: + WAL (pipelined fsync) | 550,000 ev/s | |
| **Phase 3: + Drain + detection** | **150,000 ev/s** | at 200k offered: 165k accepted, 16.9% of requests got 429 (10,117 of 60,000) |

Above 150k the server is CPU-bound. From the microbenchmark, mask + Drain at 165k ev/s is about 165,000 × 10.9 µs ≈ 1.8 CPU-seconds per second: nearly half of the 4 cores. That's an estimate from the benchmark, not a profile; Phase 7 profiles it.

That clears the plan's 100k ev/s on 4 cores. The next big win is very likely the masker (Phase 7 will confirm it with pprof).

## Reproduce

```bash
.venv/bin/python go/bench/drain3/export_drain3.py sample/app.log go/internal/drain/testdata/drain3_tremor.jsonl.gz
.venv/bin/python go/bench/eval/export_scenarios.py go/bench/eval/scenarios
cd go && go test ./internal/drain/ ./internal/eval/
go run ./cmd/eval
```

The first two commands run from the TREMOR repo root: one regenerates a drain3 fixture, the other re-exports the scenarios and Python's alerts. The `go test` runs the parity and acceptance tests, and `go run ./cmd/eval` prints the full report.
