# Benchmark results

Every number here was produced by the scripts in `bench/`. The raw outputs are in `bench/results/<phase>/`. Nothing is estimated.

## Machine

- CPU: Apple M2, 8 cores (4 performance + 4 efficiency)
- RAM: 8 GiB
- OS: macOS 26.3
- Go: go1.26.3
- The server and the load generator run **on the same machine**, so they compete for CPU. GOMAXPROCS is set per run (below). macOS can't pin threads to cores, so the scheduler may place either process on performance or efficiency cores.

## Phase 1: gateway throughput (2026-10-14)

**What this measures:** HTTP JSON ingest → admission → decode/validate → bounded queue → a pass-through stage that counts events and acks. No redaction, WAL, Drain or detection yet. This is the **gateway's ceiling**, not the throughput of the full pipeline, which later phases will lower.

**Workload:** `-batch 100 -services 10 -pregen 1024 -concurrency 512`. Requests are realistic catalogue messages (~25 KB per 100-event batch), with 1024 distinct bodies cycled so the load generator doesn't spend CPU generating them. Each step runs 30 s. "Max sustainable" is the highest step with ≤1% of requests getting 429, ≥99% of offered events accepted, and ≤1% client-side drops.

### Max sustainable rate

| tremor GOMAXPROCS | loadgen GOMAXPROCS | max sustainable | first step over the limit | raw |
|---|---|---|---|---|
| 4 | 4 | **1,050,000 ev/s** | 1,100,000 (1.5% of requests 429, 98.5% accepted) | `results/phase1/maxrate-4procs.tsv` |
| 2 | 6 | **600,000 ev/s** | 650,000 (4.6% 429, 95.4% accepted) | `results/phase1/maxrate-2procs.tsv` |

4-proc sweep (accepted p50/p99 latency is measured from the scheduled send time):

| offered ev/s | accepted ev/s | 429s | p50 ms | p99 ms |
|---|---|---|---|---|
| 500,000 | 499,997 | 0 | 0.31 | 0.55 |
| 550,000 | 549,929 | 19 | 0.32 | 92.75 |
| 600,000 | 599,997 | 0 | 0.42 | 0.73 |
| 700,000 | 699,989 | 0 | 0.60 | 1.42 |
| 800,000 | 799,976 | 0 | 1.08 | 3.87 |
| 850,000 | 846,414 | 547 | 0.68 | 84.11 |
| 900,000 | 899,711 | 83 | 0.41 | 20.23 |
| 950,000 | 946,391 | 820 | 0.59 | 79.17 |
| 1,000,000 | 999,988 | 0 | 0.84 | 13.52 |
| 1,050,000 | 1,045,195 | 1,437 | 0.54 | 44.93 |
| 1,100,000 | 1,082,788 | 5,006 | 10.25 | 71.86 |

**Caveat:** the curve is not smooth. Short 429 bursts with p99 latency around 80–90 ms appear well below the max (at 550k and 850k), then vanish at higher steps. Something stalls briefly every so often: GC, macOS scheduling onto efficiency cores, or the load generator itself. This hasn't been diagnosed yet and is a Phase 7 profiling target. The first 429 appeared at 550,000 ev/s.

### 2× overload for 10 minutes (Phase 1 acceptance)

Doubling the 4-proc max (2.1M ev/s) is **not achievable on this machine**: the load generator shares the same cores and topped out around 1.35M ev/s received by the server in a 20 s trial. So the acceptance run uses the 2-proc server and offers 2× *its* measured max.

Command: `SERVER_PROCS=2 LOADGEN_PROCS=6 RATE=1200000 DURATION=600s bench/overload.sh` (concurrency 1024).

| | result |
|---|---|
| offered by producer (scheduled) | 1,199,465 ev/s (2.0× max) |
| actually received by the server | 665,120 ev/s (3,992,521 requests) |
| accepted | 604,805 ev/s (3,630,463 requests, 363,046,300 events) |
| 429 | 362,058 |
| 503 / other status / transport errors | **0 / 0 / 0** |
| producer-side backpressure (`client_dropped`) | 3,207,508 requests never sent: all 1024 connections were busy |
| accepted latency p50 / p99 / max | 236 / 717 / 1752 ms (from scheduled send time) |
| 429 latency p50 / p99 | 260 / 519 ms |
| server RSS after warm-up | min 83 MB, max 92 MB, first-quarter peak 91 MB, last-quarter peak 91 MB, trend **+0.05 MB/min** |
| Go heap in use | 29–54 MB throughout (`overload-2x-10min-mem.csv`) |
| graceful shutdown at the end | drained in 1.6 ms; events_accepted == events_processed == 363,046,300 |
| **every rejection explicit** | **PASS** |
| **memory flat** | **PASS** |

**Reading this honestly:** the producer offered 2× the max, but the server *received* only 1.1× its max. The rest was held back on the producer side because every connection was waiting on the CPU-saturated server: that is TCP/connection-level backpressure, and loadgen counts it explicitly as `client_dropped`, never silently. Admission slots bound the server's **memory** (flat at ~90 MB against a 256 MiB worst-case bound). They don't make shedding free in **CPU**: even a 429 needs its headers parsed and its unread body drained for keep-alive. A real 2× offered-at-the-server test needs the load generator on a separate machine (Phase 7).

A 15 s CPU profile taken during this run (`results/phase1/overload-cpu-top.txt`) showed 81% of samples in socket read/write syscalls. 55% was under `net/http.(*connReader).backgroundRead`, the per-connection goroutine net/http uses to detect client disconnects. `json.Unmarshal` was about 6%. macOS CPU profiles are known to attribute syscall time unreliably, so this will be re-checked on Linux before any optimisation is based on it. The profile was taken about 10 s into the run and briefly perturbed it.

## Phase 2: WAL, crash recovery (2026-10-14)

Same machine. The pipeline is now: gateway → ingest queue → WAL (group commit, `F_FULLFSYNC`) → dispatcher → 8 shards (no-op processor) → checkpoints every 1 s. Defaults: `sync_interval 10ms`, `sync_every_records 10000`, 64 MiB segments. tremor and loadgen each run at GOMAXPROCS=4. The WAL is on the internal SSD.

### Crash test: 50 × kill -9 (Phase 2 acceptance)

`SEED=<seed> bench/chaos.sh`: 16 producers, kill at a random time in [0, 3 s] (20% of kills in the first 50 ms, during recovery), and 30% chance of garbage appended to the WAL tail after a kill. Raw: `results/phase2/chaos-50-seed*.json`.

| seed | crashes | acked events | **lost acked events** | seq reused | killed before ready | torn tails injected / truncated | replay duplicates | max recovery | max replayed |
|---|---|---|---|---|---|---|---|---|---|
| 20261014 | 50 | 3,585,450 | **0** | 0 | 11 | 17 / 16 | 50,700 | 10.3 ms | 25,700 |
| 7 | 50 | 4,544,900 | **0** | 0 | 6 | 15 / 13 | 29,150 | 14.0 ms | 19,650 |

`kill -9` doesn't simulate power loss (the page cache survives); see docs/phase2-wal.md.

### Throughput with the WAL in the path

`bench/maxrate.sh` with the WAL (30 s steps, same criteria as Phase 1):

| committer | max sustainable | p99 at 400k ev/s | raw |
|---|---|---|---|
| synchronous (append + fsync + ack in one goroutine) | 400,000 ev/s (0.75% 429 already) | 91.7 ms | `results/phase2/maxrate-wal-synchronous-committer.tsv` |
| **pipelined** (fsync on its own goroutine, next group keeps filling) | **550,000 ev/s** | 18.2 ms | `results/phase2/maxrate-wal-pipelined-committer.tsv` |

For comparison, the Phase 1 gateway alone (no WAL) sustained 1,050,000 ev/s.

### fsync trade-off (pipelined committer)

`bench/fsync.sh`. "Saturated" means offering 1.2M ev/s for 20 s and recording what was accepted. Latency is measured at a steady 50k ev/s, from the scheduled send time. Raw: `results/phase2/fsync-pipelined-committer.tsv` (and `fsync-synchronous-committer.tsv` for the earlier design).

| setting | saturated accepted ev/s | ack p50 | ack p99 | fsyncs / 20 s | avg / max fsync |
|---|---|---|---|---|---|
| no fsync (not durable) | 975,381 | 6.96 ms | 13.16 ms | 1,762 | 0.00 / 0.14 ms |
| 1 ms | 785,752 | 4.83 ms | 16.12 ms | 7,716 | 2.11 / 33.16 ms |
| 5 ms | 721,870 | 7.43 ms | 13.62 ms | 2,950 | 2.48 / 24.29 ms |
| **10 ms (default)** | 659,291 | 9.78 ms | 19.45 ms | 1,690 | 2.78 / 51.86 ms |
| 50 ms | 775,924 | 30.32 ms | 56.09 ms | 387 | 3.09 / 8.09 ms |
| 50 ms or 1,000 records | 617,216 | 13.04 ms | 23.09 ms | 1,000 | 2.75 / 12.15 ms |

The saturated numbers with fsync vary by ±15% between runs, with no reliable ordering among the fsync rows. The clear signals are that no fsync is about 20–35% faster, and that ack latency tracks the interval.

### 2× overload with the WAL (2 minutes)

`RATE=1200000 DURATION=120s bench/overload.sh` (both at GOMAXPROCS=4, concurrency 1024). Raw: `results/phase2/overload-wal-2x-120s*`.

| | result |
|---|---|
| offered / received by server | 1,199,656 ev/s / all of it (0 client drops) |
| accepted | 825,068 ev/s |
| 429 / 503 / other / transport errors | 449,636 / 0 / 0 / 0 |
| RSS after warm-up | 110–126 MB, trend +3.3 MB/min over 2 min (first-quarter peak 119 MB, last-quarter peak 122 MB) |
| every rejection explicit / memory flat | PASS / PASS |

Unlike Phase 1, the server received the whole 2× load. With the WAL as the bottleneck, the CPU isn't saturated, so 429s stay cheap and fast. This was a 2-minute run, not the 10-minute Phase 1 acceptance run.

## Phase 3: sharding, Drain, adaptive baselines (2026-10-14)

Same machine. 8 shards on a consistent-hash ring (512 vnodes); per-service Drain + detection in every shard.

### Detection on TREMOR's 10 labelled scenarios (acceptance)

`go run ./cmd/eval`, on scenarios exported by `bench/eval/export_scenarios.py` (seed 42, the Python simulator and parser; 226,104 lines, 2.58 h). The matching rule is the Python harness's (60 s grace). Raw: `results/phase3/eval-warmup30.md`.

| ERROR_RATE only | TREMOR (WARNING+) | TREMOR (all severities) | Static 5% | Rolling mean |
|---|---|---|---|---|
| Recall | **100% (3/3)** | 100% | 100% | 100% |
| False positives / hour | **0.00** | 4.65 | 7.74 | 13.94 |
| Precision | 100% | 20.0% | 13.0% | 7.7% |
| Median delay | 4.0 s | 3.0 s | 2.0 s | 1.0 s |

Parity with the Python implementation is alert-by-alert identical (time, signal, service) for all 4 detectors in 10/10 scenarios, with 0 alerts that only one implementation raised.

Warm-up sweep (`results/phase3/eval-warmup{30,60,120,300}.md`): INFO-level FP/hour 4.65 → 2.32 → 1.55 → 1.16. ERROR_RATE recall stays at 100% and WARNING+ at 0.00 FP/hour throughout.

### Drain parity with drain3 0.9.11

| fixture | messages | identical cluster ids | identical final templates |
|---|---|---|---|
| sample/app.log, TREMOR config | 100,473 | yes (all) | yes (19/19) |
| same, max_clusters=8, max_children=4 (7,793 clusters created) | 30,000 | yes (all) | yes (8/8) |
| random mask stress strings vs drain3 LogMasker | 30,000 | all 28,336 ASCII inputs | n/a; 1,664 non-ASCII differ (Unicode `\b`/`\d`, documented) |

### Microbenchmarks (`results/phase3/microbench.txt`)

| | ns/op |
|---|---|
| mask + Drain add, one message | 10,937 (masking ≈ 10,700; tree ≈ 200) |
| ring lookup (8 shards × 512 vnodes) | 35 |

### Full-pipeline throughput

`bench/maxrate.sh` (30 s steps), with gateway → WAL (fsync) → ring → Drain + detection. Raw: `results/phase3/maxrate-full-pipeline.tsv`.

| offered ev/s | accepted ev/s | 429 | p50 ms | p99 ms |
|---|---|---|---|---|
| 100,000 | 99,955 | 0 | 8.8 | 16.1 |
| 150,000 | 149,937 | 0 | 8.7 | 34.1 |
| 200,000 | 165,517 | 10,117 | 144.4 | 163.7 |

Max sustainable: **150,000 ev/s** (Phase 2 without detection: 550,000).

### Crash test with detection enabled

`SEED=20261014 bench/chaos.sh`: 50 crashes, 4,114,450 acked events, **0 lost**, 0 seq reuse, max recovery 11.1 ms. Raw: `results/phase3/chaos-50-with-detection.json`.

## Phase 4: OTLP ingestion and PII redaction (2026-10-14)

Same machine. OpenTelemetry Collector-contrib 0.136.0 in Docker 29.5.2 (Docker Desktop, arm64).

### OpenTelemetry Collector end to end (acceptance)

`deploy/otel-collector/verify.sh`: the Collector tails loadgen JSON lines (with PII) and exports to TREMOR by configuration only. Raw: `results/phase4/otel-collector-e2e*.txt`.

| run | exporter | delivered | 429 | raw PII values in WAL |
|---|---|---|---|---|
| normal, N=20,000 | otlphttp (gzip) | 20,000/20,000 | 0 | 0 of 5,655 |
| normal, N=20,000 | otlp gRPC (gzip) | 20,000/20,000 | 0 | 0 of 5,655 |
| overload (1 admission slot), N=50,000 | otlphttp | 50,000/50,000 | 9 (retried by the Collector) | 0 of 12,282 |
| overload (1 admission slot), N=50,000 | otlp gRPC | 50,000/50,000 | 0 (backpressure via HTTP/2 stream limit) | 0 of 12,282 |

### Redaction accuracy (labelled synthetic set, 5,000 lines, 4,713 labelled values)

Raw: `results/phase4/pii-precision-recall.md`. Strict scoring: same kind, covering the whole value.

| | precision | recall | leaked verbatim |
|---|---|---|---|
| all kinds | **94.5%** (re-measured in Phase 5: **94.9%** on 4,734 values, after role accounts stopped counting as personal data) | **100.0%** | **0** |
| api_key, token, secret, username, email, pan, ip | 100% each | 100% each | 0 |
| card / aadhaar / phone | 92.1% / 77.3% / 77.5% | 100% each | 0 |

The false positives are random numeric IDs that pass Luhn or Verhoeff, or look like a mobile number, by chance (generated deliberately, not filtered). The set is synthetic and written by me; see docs/phase4-otlp-redaction.md.

### Redaction throughput cost (full pipeline: WAL + Drain + detection, 4 cores)

| | redaction on | redaction off | raw |
|---|---|---|---|
| max sustainable (10k steps, ≤1% 429) | **150,000 ev/s** | 140,000 ev/s | `results/phase4/maxrate-redact-{on,off}.tsv` |
| accepted at saturation (300k offered; 3 alternating 30 s runs) | 173,466 / 169,846 / 166,202 (mean 169,838) | 159,620 / 152,332 / 158,212 (mean 156,721) | `results/phase4/redact-cost-saturation.tsv` |

There's no measurable cost at this stage. Redaction (about 1.9 µs per loadgen event, `microbench.txt`) runs in parallel gateway goroutines, and it shortens messages before the bottleneck. Shard Drain masking measured 7,506 ns per raw message vs 6,705 ns per redacted message. Re-measured after the Phase 7 masker optimisation: see Phase 7, *Redaction cost, re-measured*.

## Phase 5: security detection (2026-10-15)

Same machine. The rules run in the shards on redacted events. Simulator scenarios: 21 days, 600 employees (400 behind one office NAT), 10 admins, attacks after 14 days of learning. Raw: `results/phase5/`.

### Detection rate per attack type (acceptance)

`go run ./cmd/eval -security` (`results/phase5/security-eval.md`):

| attack type | instances | detected (all severities) | detected (paging, WARNING+) | median delay |
|---|---|---|---|---|
| brute force (T1110.001) | 10 | 10 | 10 | 48 s |
| credential stuffing (T1110.004), single source + distributed | 10 + 5 | 15 | 15 | 66 s |
| privilege change (T1548 / T1098) | 10 | 10 | 10 | 0 s |
| unusual access (T1078) | 10 | 10 | 5 (takeovers 3/3; single-signal anomalies are INFO by design) | 0 s |

### False alarms per hour on attack-free traffic

| | all severities | paging (WARNING+) |
|---|---|---|
| 504 h attack-free, rules as configured | 163 (0.323/h), all UNUSUAL_ACCESS INFO | **0 (0.000/h)** |
| same, NAT guards off | 179 (0.355/h) | 16 (0.032/h), all CREDENTIAL_STUFFING from the office NAT |
| attack run, alerts unrelated to any attack (504 h) | 168 (0.333/h) | 0 |

### Real sshd logs: Loghub OpenSSH 2k sample

`go run ./cmd/eval -ssh bench/data/OpenSSH_2k.log` (`results/phase5/loghub-openssh-2k.md`): 2,000 lines over 4 h 9 min of log time; 8 BRUTE_FORCE and 1 CREDENTIAL_STUFFING alerts. There are no labels. On a heuristic cross-check, 6 IPs have ≥10 failures within 5 min, and all 6 were alerted.

### Live attack injection

`bench/live_attacks.sh` (`loadgen -attack all` at 2,000 ev/s against a real server): all 4 attack types alerted, with delays from attack start of 18 s (brute force), 19 s (stuffing), 0 s (privilege), 0 s (takeover). 0 raw usernames appeared in the server log. Raw: `results/phase5/live-attacks-*`.

### Cost per event in the shard (`results/phase5/microbench.txt`)

| | ns/op |
|---|---|
| non-auth event, template cached as "not auth" (the common case) | 3 |
| non-auth event, first sight of its template | 1,045 |
| auth failure through every rule | 404 |

## Phase 6: metrics, dashboard, correlator, LLM summaries (2026-10-17)

Same machine; Docker Desktop (TREMOR, Prometheus v3.6.0, Grafana 12.2.0 and loadgen in containers). Raw: `results/phase6/`.

### `docker compose up` (acceptance)

`deploy/verify_stack.sh` against the running stack, loadgen at 2,000 ev/s with error spikes and every attack type (`results/phase6/verify_stack.txt`):

| | |
|---|---|
| Dashboard queries returning data | 24/25 panels; "Notifications delivered" is empty because the demo configures no sink |
| Accepted = processed | 2,000 ev/s, 0 rejections |
| WAL fsync | p50 1.8 ms, p99 5.0 ms (inside Docker's Linux VM) |
| WAL write | p50 0.08 ms, p99 0.49 ms |
| Checkpoint lag | 0 records |
| PII redactions | about 908/s across 10 types |
| LLM request latency | p50 1.5 s, p99 1.99 s |
| Process | RSS 75 MB, Go heap 45 MB, 23 goroutines, 0.14 cores |

Incidents seen in the log during the run: brute force (sshd), credential stuffing and unusual access (auth-service), and an error-rate spike (payment-gateway). Each went opened (template) → summary (LLM) → escalated or closed. After a container rebuild, the server recovered its WAL (1.82M records, 0 to replay) in 87 ms.

### LLM incident summaries (acceptance)

`go run ./cmd/eval -summaries bench/summaries` (`results/phase6/summaries-run.txt`), `openai/gpt-oss-120b` on Groq:

| | |
|---|---|
| Paging incidents summarized | 44 (4 TREMOR scenarios + 40 attacks) |
| Final source | 44/44 LLM; 0 invalid outputs; 11 transient provider errors, all retried |
| Expected service named | 44/44 (mechanical check) |
| Tokens | 36,828 prompt + 18,688 completion |
| Human scoring | `summaries/scoring-sheet.md`, to be filled in |

With the LLM disabled, every incident gets the template summary (`TestFallbackWithLLMDisabled`).

## Phase 7: pprof-guided masker, Vector and Fluent Bit (2026-10-26)

Same machine and OS. Raw: `results/phase7/`. Docker containers from unrelated projects were running but idle (about 16% of one core in total), and this laptop's absolute numbers drift between sessions: the same build accepted 171k–329k ev/s at saturation across today's runs. Every comparison below therefore alternates its contenders within one session, and the conclusions rest on those within-session comparisons.

### Profile (`results/phase7/mask-cpu-before-top.txt`)

A CPU profile of `BenchmarkMask` over the 100,473 real fixture messages put about 70% of samples under `regexp.(*Regexp).backtrack`: the five regexp passes of the masker, as Phase 3 predicted.

### Optimisation: single-pass masker

The five regexp rules (UUID, 0x hex, long hex, IP, prefixed ID) now run as one hand-written scan; NUM stays a hand-written second pass. `internal/drain/mask.go` explains why the scan is exact rather than approximate. Checks:

- byte-identical to the regexp implementation (kept as `mask_regex_test.go`) on all 130,473 fixture inputs, non-ASCII included
- `FuzzMaskMatchesRegex`: 19.4 million fuzzed inputs, no difference (5 minutes)
- unchanged parity with Python: every ASCII input of `masks_python.jsonl.gz` identical, and identical drain3 cluster ids on both drain3 fixtures

The differential test caught one real case during development: an IP's port can be a 12+ digit run, which drain3's long-hex rule masks before the IP rule runs (`10.1.2.3:8080123456789012` → `<IP>:<HEX>`).

| benchmark (10 runs, benchstat) | regexp | single pass | change |
|---|---|---|---|
| `BenchmarkMask`, real messages | 7,843 ns ± 7% | 656 ns ± 3% | **−91.6%** (p=0.000) |
| allocations / bytes per message | 21 / 879 B | 1 / 100 B | −95% / −89% |
| `BenchmarkMaskAndAdd` (mask + Drain) | 11,691 ns | 1,069 ns ± 2% | **−90.9%** |

After the change (`mask-and-add-cpu-after-top.txt`), regexp is gone from the profile; the scan itself, OS polling and `strings.Fields` in Drain lead.

### Full pipeline, before vs after (`full-pipeline-ab-saturation.tsv`)

Old binary built from 9e5d1de, new from this change, alternated 3 times: 600,000 ev/s offered for 30 s, server and loadgen at GOMAXPROCS=4, gateway → redaction → WAL (fsync) → Drain + detection.

| | run 1 | run 2 | run 3 | mean |
|---|---|---|---|---|
| regexp masker | 121,831 | 123,255 | 125,530 | 123,539 ev/s |
| single-pass masker | 329,477 | 319,364 | 313,669 | **320,837 ev/s (+160%)** |

Max sustainable after the change (`bench/maxrate.sh`, 10k steps of 20 s, ≤1% 429): **230,000 ev/s**, p99 106 ms (`maxrate-full-pipeline.tsv`). Phase 3 measured 150,000 ev/s in an earlier session, so that pair is indicative only; the A/B above is the controlled comparison.

### TREMOR vs Vector vs Fluent Bit (`compare.tsv`, `bench/compare.sh`)

Same machine, same synthetic events from `loadgen`, 600,000 ev/s offered for 30 s, 3 runs alternating the four contenders. Each receives batches of 100 events over HTTP and writes every event to local disk. Vector and Fluent Bit get the same events as a bare JSON array (`loadgen -body array`) so that both split them into records natively. Vector runs with `--threads 4`, Fluent Bit with 4 output workers, TREMOR with GOMAXPROCS=4. "On disk" is counted after a graceful stop issued as soon as the load ends.

| | work per event | accepted ev/s (mean, range) | acked events on disk | p99 ms (mean) | peak RSS |
|---|---|---|---|---|---|
| **TREMOR** | redaction, WAL with fsync before ack, Drain, detection | **236,442** (171k–291k) | 100% | 598 | 184 MB |
| TREMOR, redaction off | the same without redaction | 296,778 (277k–335k) | 100% | 605 | 188 MB |
| Vector 0.59.0 | JSON decode, file sink, ack after write (no fsync) | 62,407 (54k–67k) | 100% | 2,493 | 211 MB |
| Fluent Bit 5.1.5 | JSON decode, file output, ack on buffering (no fsync) | 60,570 (55k–66k) | **98.4%** | 1,990 | 54 MB |

Reading this honestly:

- **The work is comparable, not identical.** TREMOR does more per event (redaction, detection, and an fsync before every acknowledgement) and still accepts about 3.8× more here. Vector and Fluent Bit run near-default configurations written for this test (`bench/compare/`), not tuned ones; a tuned deployment, a different input (OTLP, files) or another machine could narrow the gap. Vector's end-to-end acknowledgements are not what limits it: with them off it accepted 47,736 and 56,855 ev/s (`vector-acks-off.tsv`).
- **Fluent Bit acknowledges before data is durable.** Stopped right after the load, it had written 91,856 fewer events than it had acknowledged across the three runs (1.6%). At 20,000 ev/s the loss was 5–8% when stopped immediately and 0% with a 5 s pause first, so these are records still in its memory buffer at shutdown. Vector (ack after write) and TREMOR (ack after fsync) lost none.
- **Memory:** Fluent Bit is far lighter (37–54 MB); TREMOR and Vector are in the same range.

### Redaction cost, re-measured

Phase 4 found no measurable redaction cost, because the regexp masker was the bottleneck downstream. With that gone, redaction shows: in the comparison above, TREMOR accepted 236,442 ev/s with redaction and 296,778 without, about **20%**, above the plan's 15% target. The ranges overlap (171k–291k vs 277k–335k), so `bench/redact_cost.sh` should be re-run on a quieter machine before quoting a figure; redaction is the next profiling target.
