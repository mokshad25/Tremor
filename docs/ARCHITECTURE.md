# TREMOR — Architecture

> **T**rend-aware **R**eal-time **E**vent **M**onitoring & **O**utlier **R**esponse

## System Overview

```
                 ┌────────────────────────── TREMOR (FastAPI process) ───────────────────────────┐
                 │                                                                                │
 app.log ──────► │ Tailer ─► Parser ─► Template Miner ─► Window Engine ─► Baseline Store          │
 (growing,       │ (rotation- (regex/   (drain3)          (1s buckets;      (per service,        │
  rotating)      │  safe)     JSON)                        10s/1m/5m views)  hour-of-day, frozen  │
                 │                                                          during anomalies)     │
                 │                                                   │                            │
                 │                    Detector Suite ◄───────────────┘                            │
                 │     (error-rate · traffic-silence · new-pattern · latency)                     │
                 │                          │                                                     │
                 │                Alert Manager (dedup, severity, lifecycle, cooldown, silences)  │
                 │            ┌─────────────┼───────────────────┬───────────────┐                 │
                 │        SQLite/PG     WebSocket hub     CloudWatch Logs     SNS (+ metric)      │
                 └────────────┼─────────────┼───────────────────┼───────────────┼─────────────────┘
                              │             ▼                   ▼               ▼
                          History API   React dashboard   Log group        Email/SMS/Lambda
```

## Design Principles

1. **Event time, not wall time.** Windows advance on log timestamps with a small lateness tolerance (5s default).
2. **Injectable clock everywhere.** No direct `time.time()` in `core/`. Tests are deterministic.
3. **Detection never blocks on I/O.** Sinks are queue-fed background workers.
4. **Everything explainable.** Every alert stores the numbers that caused it.
5. **Graceful degradation.** AWS down, DB slow, or WS dropped: the detector keeps running.

## Component Details

_To be completed as each phase is implemented._

### Template Miner (`app/core/templates.py`, Mokshad)

Turns each redacted message into a stable template id, using [drain3](https://github.com/logpai/Drain3).

- **Masking before clustering.** In order: UUIDs, hex ids, IPs, prefixed ids (`txn_…`, `acct_…`), then numbers. Redaction placeholders (`<EMAIL>`, `<CARD>`, `<TOKEN>`, `<API_KEY>`) pass through unchanged. So `Payment failed txn_9f8a… code=502 for <EMAIL>` and `Payment failed txn_00aa… code=504 for <EMAIL>` share one template.
- **Ids.** `add_message(message, *, service, ts) -> "T12"`. The id is stable for every message of a pattern, including across `persist`/`restore`.
- **Novelty.** `is_new(id)` is the only definition of "new" in TREMOR. It is true for `novelty_ttl_s` (300 s) after either:
  - the template is first seen after warm-up (300 s from the first message), or
  - a historically rare template (below 0.1% of traffic) surges: 3 or more times in 60 s.
- **Windowed counts.** Per-service 1 s buckets back `count_in_window`, `new_templates_in_window` and `get_top_templates(window_s=…)`, for eval and the UI.
- **Bounded memory.** drain3's LRU cap (`max_clusters`, default 1000) limits clusters, and stats for evicted clusters are pruned.
- **Deterministic and clock-injected.** The same input order gives the same ids. Nothing reads wall time.
- **Persistence.** An atomic JSON envelope wraps drain3's own state and the template stats.

The pipeline calls the one shared miner once per event and hands `template_id` / `is_new` to `DetectionEngine.observe()`. Detection never calls the miner.

### Simulator (`simulator/`, Mokshad)

`LogGenerator(scenario, seed=…)` produces realistic fintech logs for `payment-gateway` (JSON, with `duration_ms`), `auth-service` and `ledger` (plain text).

- **Traffic model:**
  - Poisson arrivals per service, with an hour-of-day curve (×1.4 at 15:00, ×0.6 at 03:00)
  - 1.5–2% baseline error rates
  - lognormal latency
- **Fake PII to exercise `redact.py`:** emails, Luhn-valid test cards, bearer tokens, and `sk_test_` keys.
- **Two modes, one code path:**
  - `iter_lines()` yields `(ts, line)` in virtual time, for eval and tests.
  - `write_file(path, speed=…, rotate_at_s=…)` replays the same stream into a file, with logrotate-style rotation. It powers `python -m simulator.gen_logs`.
- **Byte-identical output for the same seed.** Each service gets its own string-seeded RNG, and the streams merge on `(ts, service, seq)`.
- **Scenarios.** `simulator/scenarios.py` defines 10 scenarios: steady, drift, burst, outage, silence, new_pattern, latency_spike, noisy_normal, rotation, malformed_flood. Each is built from:
  - per-service `RateCurve`s (volume, error rate, latency)
  - injected templates
  - `Label(start, end, signal_type, service)` windows

  Every anomaly starts after a clean 360 s prefix, and labels are built from the same constants as the curves.

### Evaluation Harness (`eval/`, Mokshad)

```
LogGenerator.iter_lines() → parse_line → TemplateMiner → detector.observe(event, arrival, tid, is_new)
                                                      FakeClock, 1 s steps → detector.tick(now) → EvalAlert
                                                                   match_alerts(alerts, labels) → aggregate
```

- **One interface for every detector,** mirroring `DetectionEngine`: `observe(...)` per line, and `tick(now)` once per virtual second, including silent seconds. The detectors are:
  - TREMOR: an adapter over `DetectionEngine`.
  - Static 5%: error rate over 30 s above 5%.
  - Rolling mean: above 2× its own rolling mean; no seasonality, no spread, no freeze.
- **Matching and metrics** (`eval/metrics.py`): see TRADEOFFS.md, "Eval matching rule". The metrics are precision, recall, F1, mean/median detection delay, FP/hour, and per-scenario correctness. They are reported overall and ERROR_RATE-only, since the baselines only detect error rate.
- `python -m eval.run --seed 42` regenerates `docs/EVAL.md` deterministically.
- The TREMOR adapter runs **one `DetectionEngine` per service**. `DetectionEngine.observe()` does not filter by `event.service`, so a single `"*"` engine cannot see one service go silent while others keep logging. It is reported twice: every incident (INFO+), and only incidents that reach WARNING (what would page someone).

## Data Flow

_To be completed in Phase 3._
