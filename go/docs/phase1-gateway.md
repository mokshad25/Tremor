# Phase 1: gateway and backpressure

## What the gateway promises

1. **Bounded memory, whatever the offered load.** At most `queue_capacity` batches exist anywhere between "body read" and "acked". Worst case is `queue_capacity × max_body_bytes` of raw bodies, 256 MiB with the defaults, plus their decoded form. Nothing in the pipeline buffers without a limit.
2. **Every rejected request is told so.** A full queue returns `429` with `Retry-After`. Draining, a closed queue or an ack timeout returns `503` with `Retry-After`. Bad input returns `400`/`413`/`415` with a JSON error body. Nothing is dropped silently.
3. **A 200 means the batch was handed off.** In Phase 1 that means "consumed by the last stage". From Phase 2 it means "fsynced to the WAL". The handler's code doesn't change; only the stage that calls `Ack` does.

## Event struct

`internal/event.Event`: `Seq, Service, Timestamp (unix ns), ReceivedAt (unix ns), Level, Message, Attrs`.

| Decision | Why |
|---|---|
| Timestamps are `int64` unix nanoseconds, not `time.Time` | 8 bytes instead of 24, no location pointer, and trivially serialisable into the WAL record in Phase 2. |
| `ReceivedAt` is separate from `Timestamp` | Producer clocks lie. Detection windows (Phase 3) and ingest-to-alert latency (Phase 7) need the gateway's clock. |
| `Level` is a `uint8` enum | Normalisation is the same as the Python parser (`WARN→WARNING`, `FATAL/CRITICAL→ERROR`, `TRACE→DEBUG`, unknown→`INFO`), so detection results stay comparable. |
| Numeric timestamps are interpreted by magnitude | Above 1e17 is ns, above 1e14 is µs, above 2e9 is ms (the Python rule), otherwise seconds. Producers send all four in practice. |
| Attribute values are flattened to strings | Numbers and bools keep their JSON text. Rejecting `"attempts": 3` would be hostile, and the rules only compare strings. |
| Messages are capped at 2048 bytes + `...`, without splitting UTF-8 | Same cap as Python. Per-event size limits are what make the byte bound real. |

## Channel layout

```
POST /ingest
   │
   ├─ draining?                     → 503 + Retry-After
   ├─ queue.Acquire() (non-blocking)
   │     full                       → 429 + Retry-After   (body never read)
   ├─ read body (MaxBytesReader)    → 413 if > max_body_bytes
   ├─ decode + validate all events  → 400 with offending index (all-or-nothing)
   ├─ queue.Submit(batch)           (never blocks: a slot is already held)
   └─ wait on batch.Done()          → 200 {"accepted": n}
                                      503 ack_timeout after ack_timeout

ingestQ: chan *Batch, cap = queue_capacity ──▶ worker(s) ──▶ batch.Ack(err) ──▶ slot released
```

### Admission before the body (the key decision)

A naive gateway reads and decodes the body and only then tries a non-blocking send on the channel. Under overload it does the most expensive work (reading and JSON-decoding up to 1 MiB) for exactly the requests it will reject, and the bodies being decoded aren't counted against any limit.

Here a request must win an **admission slot** (a buffered `chan struct{}` used as a semaphore) before the body is read. The slot is held through decode, queue and processing, and is released only by `Batch.Ack`. Because the channel capacity equals the slot count, `Submit` can never block or fail while a slot is held, and the memory bound covers every in-flight batch, not just queued ones.

One subtlety: on a 429, the body sits unread in the socket. Go's `net/http` then discards up to 256 KiB of it after the handler returns so the keep-alive connection can be reused. That's a cheap memcpy, and it's why a 429 costs far less than a 200, though not zero (see results).

### All-or-nothing batches

One invalid event rejects the whole batch with its index. With partial acceptance, a producer retrying after a timeout couldn't tell which half had already been accepted, and at-least-once delivery would turn into "some events twice, others never".

### Ack timeout keeps the slot

If a batch isn't acked within `ack_timeout`, the producer gets a 503 and will retry. The batch is still queued and may be processed later, so the retry can create a duplicate. That's the at-least-once contract, and from Phase 2 duplicates are dropped downstream by sequence number. The slot is **not** released on timeout, only on ack. Releasing it early would let the gateway admit more work than it can hold.

### Producer disconnects

If the client goes away mid-wait, the handler returns, but the batch is still processed and acked. Its slot is freed then.

## Queue size

Default `queue_capacity = 256` batches, with 1 MiB max body and ≤5000 events per batch.

- **Memory:** 256 × 1 MiB = 256 MiB raw worst case. A realistic batch (100 events) is about 25 KB, so a full queue normally holds about 6 MB.
- **Latency:** with a fast consumer the queue is almost always empty. Its job is to absorb bursts, not to hold a standing backlog. A deeper queue under sustained overload only adds latency (Little's law: wait = depth / throughput) before the same 429 arrives.
- **Producer concurrency:** the slot count is also the maximum number of producer requests the server will work on at once. Requests beyond it are rejected cheaply instead of piling up as goroutines holding bodies.

## 429 behaviour and what producers should do

- `Retry-After` is in whole seconds (default 1). Producers should wait at least that long and add **jitter**, so a crowd of rejected producers doesn't retry in lock-step. `cmd/loadgen -retry` waits `Retry-After × 2^attempt`, scaled by a random factor in [0.5, 1.5).
- `429` means "the server is healthy but full". `503` means "draining, or your batch wasn't confirmed in time". The producer response to both is the same: keep the batch and retry later. Never treat either as success.
- OTLP clients (Phase 4) already retry 429/503 with backoff, which is why these status codes were chosen.

## Graceful shutdown

On SIGINT or SIGTERM:

1. `SetDraining()`: new batches get 503 and `/readyz` returns 503.
2. `http.Server.Shutdown`: stop accepting, then wait for in-flight handlers, which are waiting for their acks.
3. `queue.Close()`: closing is guarded by a mutex and a `closed` flag, so a late `Submit` gets `ErrClosed` instead of panicking with a send on a closed channel.
4. Workers `range` over the channel until it's drained, acking everything.
5. The final log line reports `events_accepted` vs `events_processed`.

All of this is bounded by `shutdown_timeout` (30 s). `TestGracefulShutdownDrainsInFlight` cancels the server under load from 32 concurrent producers and checks that every 200 a client saw corresponds to processed events.

## Load generator design

- **Open loop.** Requests are scheduled at fixed times (`start + i × batch/rate`). If every worker is busy and the small buffer is full, the request is counted as `client_dropped`, not sent late. A closed-loop generator slows down when the server slows down and hides overload ("coordinated omission").
- **Latency is measured from the scheduled send time**, so time spent waiting for a free worker counts against the system.
- **Realistic messages:** the message catalogue is ported from `simulator/gen_logs.py` (payment-gateway, auth-service and ledger, plus generic `svc-NN`). It uses seeded `math/rand/v2` PCG streams, a 1.5–2% baseline error rate, and optional rotating error spikes whose windows are written to the summary as ground-truth labels. The fake PII (emails, test cards, JWTs, `sk_test_` keys) is there on purpose, for the Phase 4 redaction stage.
- **`-pregen N`** builds N bodies up front and cycles them. It's for throughput benches on a single machine, where generating events would otherwise steal CPU from the server under test. It has no spikes and fixed timestamps.

## Dependencies

- `gopkg.in/yaml.v3`: the standard library has no YAML parser, and the config format was specified as YAML. It's the de-facto standard Go YAML library and has no transitive runtime dependencies.
- Metrics in Phase 1 use the standard library's `expvar` (`/debug/vars`) and `net/http/pprof`, both on a separate loopback-only listener. Prometheus `client_golang` arrives in Phase 6 with the same counter names.
