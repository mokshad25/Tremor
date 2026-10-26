# TREMOR at Scale (Go)

A crash-safe, privacy-first security log pipeline: an individual Go rebuild of TREMOR, which began as a 4-person team project (Acentra Health Build to Care). The Python app, the React UI and their compose setup in the parent directory are unchanged.

**Status: Phase 7 of 7, in progress.** Done so far:
- ingestion over HTTP JSON and OTLP (HTTP and gRPC)
- PII redaction before disk
- a write-ahead log with ack-after-fsync and crash recovery
- consistent-hash sharding
- a Drain port that matches drain3
- TREMOR's adaptive baselines
- security rules mapped to MITRE ATT&CK: brute force, credential stuffing, privilege change, unusual access
- Prometheus metrics for every stage and a provisioned Grafana dashboard (`docker compose up`)
- an alert correlator that groups alerts into incidents, with webhook and Slack notifications
- LLM incident summaries (Groq or any OpenAI-compatible API) that only explain: validated, cited, cached, rate-limited, with a deterministic fallback
- a pprof-guided single-pass masker (mask + Drain 10.9 µs → 1.1 µs per message), CI for the Go tests, and a reproducible comparison with Vector and Fluent Bit (`bench/compare.sh`)

Still open in Phase 7: the redaction stage now costs about 20% of full-pipeline throughput (above the 15% target), p99 ingest-to-alert latency is not yet measured, and the LLM summary scoring sheet is not yet filled in.

```
producers ──HTTP / OTLP──▶ gateway ──▶ PII redaction ──▶ WAL (fsync, ack) ──▶ ring ──▶ shards ──▶ correlator ──▶ notifier ──▶ webhook / Slack
 :8080 /ingest            (429 when full)  (mask, HMAC-                      (service)  (Drain,      (incidents)   (template now,
 :4318 /v1/logs                             tokenize)                                   baselines,                 LLM summary later)
 :4317 gRPC                                                                             security)
 :2112 /metrics
```

| Claim | Measured (bench/results.md) |
|---|---|
| Paging alerts on TREMOR's labelled scenarios | 100% ERROR_RATE recall, 0.00 false alarms/hour (static 5% threshold: 7.74/hour) |
| Zero acknowledged events lost | 0 lost across 150 kill -9 crashes (3 runs of 50) |
| Throughput, full pipeline, 4 cores | 230,000 ev/s sustained (≤1% 429), with PII redaction on; +160% at saturation from the single-pass masker |
| Same machine vs Vector 0.59 and Fluent Bit 5.1.5 (HTTP in, disk out) | TREMOR 236k ev/s with redaction, WAL fsync and detection; Vector 62k; Fluent Bit 61k and 1.6% of acknowledged events not on disk after shutdown (near-default configs; caveats in bench/results.md) |
| OpenTelemetry Collector, config only | 20,000/20,000 over OTLP/HTTP and gRPC; 50,000/50,000 under forced overload |
| Raw PII on disk | 0 values; redaction recall 100% / precision 94.9% on a 4,734-value labelled set |
| Security rules (simulated 21 days, 45 attacks) | every brute-force, stuffing and privilege attack paged; 0 paging false alarms in 504 attack-free hours (16 with the NAT guards off) |
| Real sshd attacks (Loghub OpenSSH sample) | all 6 heavy-failure IPs alerted |
| LLM summaries never decide | incidents page with a template before any model call, and nothing reads a summary back; invalid or uncited output falls back to the template (tested, including with the LLM disabled) |
| `docker compose up` | TREMOR + Prometheus + Grafana; 24 of 25 panels verified with live data at 2,000 ev/s (notifications is empty until a sink is configured) |

## Quick start

```bash
cd go
make check            # go vet, gofmt, go test -race ./...
TREMOR_HMAC_KEY=$(openssl rand -hex 32) make run   # :8080 /ingest, :4318/:4317 OTLP, debug on 127.0.0.1:6060
make loadgen          # 20k ev/s, 10 services, 30 s
make chaos            # 50 x kill -9 under load; verifies zero acknowledged events lost
bench/compare.sh      # vs Vector and Fluent Bit on this machine (needs both on PATH; see the script header)
deploy/otel-collector/verify.sh   # OpenTelemetry Collector -> TREMOR over OTLP/HTTP and gRPC (needs Docker)
go run ./cmd/eval     # replay TREMOR's 10 labelled scenarios; compares with Python alert by alert
go run ./cmd/eval -security                          # attack simulator: detection rate, false alarms/hour
go run ./cmd/eval -ssh bench/data/OpenSSH_2k.log     # replay public Loghub sshd logs
bench/live_attacks.sh                                # live server + loadgen -attack all
go run ./cmd/eval -summaries bench/summaries         # LLM summaries for every paging incident + scoring sheet
```

### Dashboard (Docker)

```bash
cd go/deploy
export TREMOR_LLM_API_KEY=...            # optional; without it summaries use the template
GRAFANA_PORT=3001 docker compose up -d   # TREMOR, Prometheus, Grafana, demo load with attacks
open http://localhost:3001/d/tremor      # Grafana (GRAFANA_PORT defaults to 3000)
./verify_stack.sh                        # checks every panel query returns data
docker compose down -v
```

```bash
curl -s -XPOST localhost:8080/ingest -H 'Content-Type: application/json' \
  -d '{"events":[{"service":"auth-service","level":"warn","message":"Login failed user=alice"}]}'
# {"accepted":1,"first_seq":1,"last_seq":1}   (the message is stored as "Login failed user=usr_<hmac>")
curl -s 127.0.0.1:6060/debug/vars | jq .tremor
```

## API

`POST /ingest` takes `{"events":[{"service","timestamp?","level?","message","attributes?"}]}`.

| Status | Meaning | Producer should |
|---|---|---|
| 200 `{"accepted":n,"first_seq","last_seq"}` | batch fsynced to the WAL as seqs first..last | forget the batch |
| 429 + `Retry-After` | queue full | retry after Retry-After, with jitter |
| 503 + `Retry-After` | draining, ack timed out, or WAL failed | retry after Retry-After, with jitter |
| 400 `{"error","index"}` | invalid JSON or invalid event at `index` (whole batch rejected) | fix and resend |
| 413 / 415 | body > 1 MiB, more than 5000 events, or not JSON | split or fix |

`GET /healthz` reports liveness. `GET /readyz` returns 503 while draining.

## Benchmarks

The scripts are in `bench/`, and real results with machine specs are in [bench/results.md](bench/results.md).

```bash
bench/maxrate.sh      # step the offered load up until the gateway sheds (>1% 429)
bench/overload.sh     # 2x max for 10 min: all rejections explicit, memory flat
bench/chaos.sh        # 50 x kill -9: zero acknowledged events lost
bench/fsync.sh        # fsync interval vs throughput and ack latency
```

## Docs

- [docs/phase1-gateway.md](docs/phase1-gateway.md): event struct, channel layout, queue sizing, 429 semantics, shutdown, and trade-offs
- [docs/phase2-wal.md](docs/phase2-wal.md): record format, pipelined group commit, the fsync trade-off (measured), checkpoints, recovery, and the chaos test
- [docs/phase3-detection.md](docs/phase3-detection.md): consistent hashing, the Drain port and its drain3 verification, baselines, the eval, and the warm-up trade-off
- [docs/phase4-otlp-redaction.md](docs/phase4-otlp-redaction.md): OTLP mapping and status codes, the redaction design, measured accuracy and throughput, and dependencies
- [docs/phase5-security.md](docs/phase5-security.md): the rules and their defaults, how a busy NAT is kept from looking like credential stuffing, the attack simulator, the Loghub replay, and limitations
- [docs/phase6-observability-llm.md](docs/phase6-observability-llm.md): metrics, the dashboard and compose, correlation rules, the LLM guards (why it never decides), notifications, and the silence-detector change
- [docs/ui-contract.md](docs/ui-contract.md): the WebSocket contract the Go server will serve so the existing UI works unchanged
