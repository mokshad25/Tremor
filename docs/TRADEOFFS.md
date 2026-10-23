# TREMOR — Tradeoffs & Design Decisions

This document records deliberate tradeoffs and design decisions made during development.

---

## Phase 0 — Foundation

### SQLite vs Postgres
- **Decision:** Start with SQLite (via `aiosqlite`) for zero-config development; schema is Postgres-compatible.
- **Tradeoff:** Concurrent writes are limited. Acceptable for a single-process deployment; if scaling, swap to Postgres via `DATABASE_URL`.

### Structlog JSON vs Console
- **Decision:** JSON output in production (`LOG_LEVEL != DEBUG`), console renderer for development.
- **Tradeoff:** JSON logs are grep-unfriendly for humans but machine-parseable for production monitoring.

### Coverage threshold (50% → 90%)
- **Decision:** Start at 50% minimum, raise to 90% for `core/` once all phases land.
- **Tradeoff:** Low initial bar lets Phase 0 pass; strict bar on `core/` ensures detection logic is proven.

---

_Each team member should add their decisions here as they implement their components._

---

## Phase 2 / Phase 6 (Mokshad)

### One drain3 tree for all services
- **Decision:** A single shared `TemplateMiner` for all services. Windowed counts are still kept per service.
- **Tradeoff:** Services that log the same message shape share a template id. That is cheaper, with one memory cap and one id space. Per-service novelty is still available via `service=` on the window queries.

### Masking before clustering
- **Decision:** Mask UUIDs, hex ids, IPs, prefixed ids (`txn_…`) and numbers before drain3 sees a message, and run PII redaction even earlier.
- **Tradeoff:** Two messages that differ only in an id always cluster together, so ids are stable. A real difference hidden inside a masked token is lost, for example two error codes that only differ numerically.

### Memory cap via LRU eviction
- **Decision:** `max_clusters` (default 1000) with drain3's LRU eviction. Stats for evicted clusters are dropped.
- **Tradeoff:** Memory stays bounded against log-injection floods. An evicted pattern that comes back gets a new id and counts as "new" again. This only happens with 1000+ live patterns.

### What "new" means
- **Decision:** A template is new when it is first seen after warm-up, or when a historically rare one (<0.1% of traffic before the surge) appears 3+ times in 60 s. The flag stays on for 300 s.
- **Tradeoff:** The new-pattern detector opens an incident per new template with no minimum count, so "rare" alone would page on every occasional line. Requiring a surge avoids that, at the cost of missing a rare line that returns only once or twice. The 300 s TTL keeps the flag stable during an incident instead of flapping.

### Template state persistence uses drain3's jsonpickle
- **Decision:** `persist`/`restore` wrap drain3's own serialized state in a versioned JSON envelope, written atomically.
- **Tradeoff:** It reuses drain3's tested (de)serializer. jsonpickle must only load files TREMOR wrote itself, so the state path must not be user-writable.

### Simulator: virtual time, mixed formats
- **Decision:** The generator works in virtual time. The file writer replays the same iterator with an injectable `sleep`. payment-gateway logs JSON with `duration_ms`; the other services log plain text.
- **Tradeoff:** Eval and tests run in seconds and are byte-reproducible. Latency only exists for payment-gateway, because the parser reads `duration_ms` from JSON only.

### Scenario labels start after warm-up
- **Decision:** Every scenario has a clean 360 s prefix (warm-up is 300 s, plus margin), and labels are built from the same constants as the rate curves. `new_pattern` injects a WARNING-level line so it does not also move the error rate.
- **Tradeoff:** Scenarios are longer (900–1200 s). A detector is never scored on an anomaly it could not have seen, and each labelled scenario tests one signal type (except `outage`, which is labelled ERROR_RATE + NEW_PATTERN on purpose).

### Eval matching rule
- **Decision:** An alert is a TP if its signal type matches a label, its service matches (or it is a whole-stream `*` alert), and it fires within `[start, end + grace]` with a 60 s grace. The first such alert detects the label, and its delay is `alert − start`.
  - Further alerts on an already-detected label are **duplicates**: they are reported, but count as neither TP nor FP.
  - Alerts outside every label are FPs.
  - Labels with no alert are FNs.
  - Precision = TP / (TP + FP), recall = detected labels / labels, micro-averaged over all scenarios.
- **Tradeoff:** The grace window credits a detector that confirms a short burst just after it ends (e.g. a 30 s burst seen by a 30 s window). Not counting duplicates as FPs means precision doesn't punish a detector for re-alerting during one long incident. Re-alerting is still visible in the duplicate count.

### Baselines cover ERROR_RATE only
- **Decision:** The static 5% and rolling-mean baselines only detect error rate. EVAL.md reports an overall table and an ERROR_RATE-only table.
- **Tradeoff:** The overall table shows what TREMOR adds (silence, new pattern, latency). The ERROR_RATE-only table is the apples-to-apples comparison.

### Eval reports TREMOR at INFO+ and WARNING+
- **Decision:** EVAL.md shows TREMOR twice. The first column counts every incident. The second, "TREMOR (WARNING+)", counts an incident only from its first alert at WARNING or above.
- **Tradeoff:** INFO incidents (z ≥ 2–3) are informational, not pages, and scoring them as pages would overstate the noise. Showing both views keeps the INFO noise visible instead of hiding it; the baselines have no severity, so every alert they raise counts.

### One detection engine per service
- **Decision:** Eval (and the production pipeline) route each event to its own service's `DetectionEngine`.
- **Tradeoff:** Baselines are learned per service, and a single quiet service is detectable. The cost is N engines instead of one. A whole-stream engine misses single-service silence entirely.
