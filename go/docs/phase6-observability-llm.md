# Phase 6: observability, alert correlation, LLM incident summaries

## Results

| Measured | Result | Source |
|---|---|---|
| `docker compose up` (TREMOR + Prometheus + Grafana + demo load) | every dashboard query returns data except "Notifications delivered" (no sink configured in the demo) | `bench/results/phase6/verify_stack.txt` |
| Live stack at 2,000 ev/s | 0 rejections, WAL fsync p50 1.8 ms / p99 5.0 ms, write p99 0.49 ms, checkpoint lag 0, RSS 75 MB, 0.14 cores | same |
| LLM summaries, 10 TREMOR scenarios + 21-day attack simulation | 44 paging incidents (4 + 40), see "Summary quality" below | `bench/summaries/`, `bench/results/phase6/summaries-run.txt` |
| LLM disabled | every incident still pages with a deterministic template summary (`TestFallbackWithLLMDisabled`) | `internal/summarize` |
| LLM returns invalid JSON / cites an alert that isn't in the incident / errors / times out | template summary, counted in `tremor_summary_fallbacks_total` (tests for each) | `internal/summarize` |
| Raw PII in what leaves the process | none in the prompt (`TestIncidentReachesWebhookWithLLMSummary` searches the prompt for every raw value) | `internal/server` |

## Pipeline position

```
shards ──alerts──▶ correlator ──incident events──▶ notifier ──▶ dispatcher ──▶ webhook / Slack
                    (groups,        (page now with a template;     (bounded queue per sink,
                     dedupes)        LLM summary DelayS later)      retries, never blocks)
```

The correlator and notifier run in one goroutine fed by the shards' alert channel. LLM calls run on a separate worker goroutine (one at a time, so an incident's summary always goes out before its close), so a slow provider never stalls alerts.

## Metrics (`:2112/metrics`)

Every stage exports Prometheus metrics through `client_golang` (the one Phase 6 dependency: the exposition format and histograms are not worth reimplementing). Labels are bounded enums only: stage, shard number, redaction type, alert type, severity, outcome. No label ever carries a service name from the wire, a user, an IP or a message, so neither raw PII nor unbounded cardinality can reach Prometheus.

| Metric | Type | Labels |
|---|---|---|
| `tremor_ingest_requests_total` | counter | `result` (accepted, rejected_429, rejected_503, bad_request, …) |
| `tremor_events_accepted_total`, `_processed_total`, `_replayed_total` | counter | |
| `tremor_queue_depth` | gauge | `stage` |
| `tremor_ingest_inflight_batches`, `tremor_ingest_capacity_batches` | gauge | |
| `tremor_shard_queue_depth`, `tremor_shard_events_processed_total` | gauge, counter | `shard` |
| `tremor_wal_write_seconds`, `tremor_wal_fsync_seconds` | histogram | |
| `tremor_wal_last_seq`, `tremor_checkpoint_min_seq`, `tremor_checkpoint_lag_records` | gauge | |
| `tremor_wal_segments`, `_records_total`, `_bytes_total`, `_sync_errors_total`, `_segments_removed_total` | gauge, counter | |
| `tremor_redactions_total` | counter | `type` (email, ip, card, …) — counts only |
| `tremor_alerts_total` | counter | `type`, `severity` |
| `tremor_ingest_to_alert_seconds` | histogram | | gateway receive time of an alert's newest line to the alert leaving detection (OPEN/ESCALATED, not silence; Phase 7) |
| `tremor_incidents_total`, `tremor_incidents_open` | counter, gauge | `event` (opened, paged, closed) |
| `tremor_llm_request_seconds` | histogram | |
| `tremor_llm_requests_total`, `tremor_llm_tokens_total`, `tremor_summary_fallbacks_total` | counter | `result`, `kind` (prompt, completion) |
| `tremor_notifications_total` | counter | `sink`, `result` |

Counters that already existed as atomics (Phases 1–5) are exported by a custom collector that reads them at scrape time, so the hot path did not change. The only new hot-path work is two histogram observations per WAL group commit.

## Dashboard and compose

```bash
cd go/deploy
export TREMOR_LLM_API_KEY=...          # optional: without it, summaries are template-only
GRAFANA_PORT=3001 docker compose up -d # GRAFANA_PORT defaults to 3000
open http://localhost:3001/d/tremor    # anonymous viewer; admin/admin to edit
./verify_stack.sh                      # evaluates every panel query in Prometheus
docker compose down -v
```

- The compose file builds the image from `go/Dockerfile` (static binary, non-root uid 10001, WAL on a volume) and also starts Prometheus (5 s scrape), Grafana with a provisioned datasource and dashboard, and a `loadgen` demo producer: 2,000 ev/s, error spikes, and every attack type.
- The dashboard is generated from `deploy/grafana/gen_dashboard.py`, so every PromQL query is reviewable as code. It has 25 panels in six rows: overview, ingest and backpressure, durability, privacy and detection, LLM, and process.
- Secrets come only from the environment (`TREMOR_LLM_API_KEY`, `TREMOR_WEBHOOK_SECRET`, `TREMOR_SLACK_WEBHOOK_URL`). `TREMOR_HMAC_KEY` has a demo default that is labelled as such; set a real one outside the demo.

## Alert correlator

- **Dedup:** an alert ID seen before (for example after a WAL replay) is ignored. Seen IDs are kept for 4 windows.
- **Anomalies** (error rate, latency, volume, silence, new template) join any open anomaly incident updated within `window_s` (300 s), across services: a dependency failure that breaks three services is one incident.
- **Security alerts** join an open security incident only if they share a tokenized user, a tokenized source, or the same service and alert type. Two unrelated brute-force attacks on different services stay separate.
- **Incident ID:** `inc-` + the first 12 hex characters of sha256("incident|" + the first alert's ID). Alert IDs are deterministic (Phase 3), so a replay after a crash produces the same incident IDs. The LLM cache and the receivers' dedup rely on this.
- **Lifecycle:** opened → updated or escalated (when severity rises) → closed when nothing arrives for `window_s`. A RESOLVED alert is attached to the incident that raised it but does not keep it open. `max_alerts` (200) caps memory; extra alerts are counted as `truncated`.
- **Deploy context:** a line matching deploy words ("deployed", "rolled out", "new version", …) produces a NOTICE (at most one per service per minute). Notices never open incidents; they are attached to an incident on the same service if the deploy happened within `deploy_lookback_s` (1800 s) before it. This gives the summary its most common real trigger without letting free text drive detection.

## LLM summarizer

### The LLM never decides

Detection, severity, grouping, paging and closing are all done by the deterministic code above **before** any model is involved. The summary is text attached to notifications and nothing more:

- The incident has already paged, with a template summary, before the model is asked. The LLM summary arrives `delay_s` (20 s) later as an `incident.summary` follow-up.
- Nothing reads the model's output back into the pipeline. There is no code path from a summary to an alert, an incident state or a threshold.
- A broken, slow, malicious or absent model therefore costs one paragraph of prose, never a missed or invented alert.

### Interface

```go
type Summarizer interface {
    Summarize(ctx context.Context, in Incident) (Summary, error)
}
```

- `OpenAICompatible` speaks the OpenAI chat-completions API. Groq is the default (`https://api.groq.com/openai/v1`, `openai/gpt-oss-120b`), but the endpoint and model come from config, so any compatible provider or a local server works. It uses JSON mode, temperature 0, and a 1,200-token cap.
- `Template` is the deterministic fallback. It builds the same five fields from the alerts and has a suggested next check per alert type.
- `Guarded` wraps both. It is the only one the server uses.

### What `Guarded` enforces

| Guard | Why |
|---|---|
| **Input is redacted data only** | The incident is built from alerts made from events that were redacted at the gateway. The prompt is then passed through the redactor a second time (`Scrub`) right before it leaves the process. This is defence in depth for anything a future detector might put in a reason string. |
| **Strict output schema** | Exactly `summary`, `likely_trigger`, `affected_services`, `suggested_next_check`, `cited_alert_ids`; unknown fields are rejected (`DisallowUnknownFields`); every field is required, and the text fields are length-capped. |
| **Citations checked** | Every `cited_alert_ids` entry must be an alert in the incident, and every `affected_services` entry must be one of the incident's services. A model that invents an alert or a service is rejected, not trusted. |
| **Cache per incident ID** | One model call per incident (1,000 entries, oldest evicted first). Only final answers are cached: a timeout or provider error can be retried later, but an invalid output is not retried, so a model that misbehaves on an input doesn't get unlimited attempts. |
| **Rate limit** | Token bucket, 20 calls/minute by default. An alert storm cannot run up a bill or exhaust the provider quota; the excess gets template summaries. |
| **Timeout** | 20 s per call. |
| **Fallback** | Every failure above (disabled, rate-limited, timeout, HTTP error, invalid JSON, failed validation) returns the template summary with a `fallback_reason`. `Summarize` never returns an error for a real incident. |

### Prompt injection

Log lines are attacker-influenced: a username or a URL can be any string. The defences, in order:

1. Templates and identities reach the model only after redaction and Drain masking, so most free text is already `<*>`, `usr_<hex>` or a mask.
2. The system prompt states that every string is data, never instructions.
3. If a model follows injected text anyway, the worst it can do is word one summary badly. Its output cannot cite alerts that don't exist, name services outside the incident, or change any decision, because nothing reads it back.

### What the model sees

`BuildInput` sends at most 40 alerts per incident with: the alert ID, type, severity, service, ATT&CK IDs, tokenized user and source, value, the baseline (anomalies) or threshold (security rules), z-score, window, the top templates, and deploy notices. It also sends `observed_is`, a one-line meaning of the value. This was added after an early run where the model described one unusual login as "30 login attempts": the 30 was the user's count of previous logins, not an attempt count. The same review renamed the security rules' threshold field from `baseline` to `threshold` after the model wrote "at baseline" for a threshold crossing.

## Notifications

- `incident.opened` (template summary, immediately) → `incident.escalated` (template, on severity rise) → `incident.summary` (LLM or fallback, after `delay_s`) → `incident.closed` (with the final summary). Only incidents at `min_severity` (WARNING) or above notify.
- **Webhook:** JSON POST with `X-Tremor-Event` and `X-Tremor-Signature: sha256=<HMAC of the body>` when `TREMOR_WEBHOOK_SECRET` is set.
- **Slack:** incoming-webhook message, with every interpolated value mrkdwn-escaped so a log string can't add links or mentions.
- **Dispatcher:** one bounded queue per sink, retries after 1, 2 and 4 s, and drops (counted) when a queue is full. A dead receiver can never back up into detection.
- The demo compose config sets no sink, so incidents appear in TREMOR's log (`incident.*` lines) and on the dashboard; "Notifications delivered" stays empty until `TREMOR_WEBHOOK_URL` or `TREMOR_SLACK_WEBHOOK_URL` is set.

## Silence detector change (deviation from Python)

Python's silence detector pages HIGH on any 10 s gap once a service has warmed up. On the 21-day attack simulation this produced **498 of 542** paging incidents: low-volume and diurnal services (quiet at night) paged all night. The Go detector now treats a gap as silence only if the service was busy just before it (≥ `min_events` lines in the 30 s window that ends at its last line, about 0.67 lines/s, where a 10 s gap under normal traffic has a probability below 0.2%). Every Python scenario runs at 1.5–8 lines/s, so parity with Python on the 10 labelled scenarios is unchanged (the eval still matches alert by alert). After the change, the simulation produces 44 paging incidents: 4 from the TREMOR scenarios and 40 from attacks.

## Summary quality

`go run ./cmd/eval -summaries bench/summaries` replays the 10 TREMOR scenarios and the attack simulation through the production processor and correlator, summarizes every paging incident with the guarded summarizer, and writes:

- one JSON file per incident with the exact model input and output, and the ground truth (expected service and trigger);
- `scoring-sheet.md` / `.csv` with blank **Right service?** / **Right trigger?** columns for a human to fill in. The `auto` column is only a mechanical check (an expected service appears in `affected_services`), not a judgement of the text.

Run on 2026-10-17 with `openai/gpt-oss-120b` on Groq (`bench/results/phase6/summaries-run.txt`):

| | |
|---|---|
| Paging incidents | 44 (TREMOR: drift, burst, outage, silence; attacks: 40). steady, noisy_normal, rotation and malformed_flood produced none, as expected. new_pattern and latency_spike also produced no WARNING-or-higher incident in this replay, so they have no summary. |
| Final summary source | 44/44 LLM, 0 invalid outputs (every schema, service and citation check passed) |
| Transient provider errors | 11 of 55 calls (Groq free-tier 429/5xx), each retried successfully |
| Expected service named (`auto`) | 44/44 |
| Tokens | 36,828 prompt + 18,688 completion (about 1,260 per incident) |

The human columns (right service, right trigger) are left blank for review: `bench/summaries/scoring-sheet.md`.

## Config

```yaml
server:
  metrics_addr: ":2112"          # TREMOR_METRICS_ADDR; "" disables
correlator:
  window_s: 300
  max_alerts: 200
  deploy_lookback_s: 1800
llm:
  enabled: true                  # TREMOR_LLM_ENABLED; also needs TREMOR_LLM_API_KEY
  provider: groq
  endpoint: https://api.groq.com/openai/v1
  model: openai/gpt-oss-120b
  max_tokens: 1200
  temperature: 0
  timeout_s: 20
  rate_per_minute: 20
  cache_size: 1000
  delay_s: 20
notify:
  min_severity: WARNING
  queue_length: 100
  # TREMOR_WEBHOOK_URL, TREMOR_WEBHOOK_SECRET, TREMOR_SLACK_WEBHOOK_URL (env only)
```

## Limitations

- Correlation is time and identity based, with no topology. Two unrelated anomalies on different services within 5 minutes are merged into one incident. This is deliberate (one page rather than two during an outage), but it can mix causes.
- The quality numbers are from one model on simulated incidents, and the "auto" check is mechanical. The human scoring sheet is the real measure.
- The Groq free tier returned transient 429/5xx errors on 11–14 of 44 calls per run. The eval retries them; the live server falls back to the template, and a later notification for the same incident can still get the LLM summary because transient failures are not cached.
- Benchmarks that use `config.example.yaml` bind :8080, :2112, :4317 and :4318, so stop the compose stack before running `bench/*.sh`.
