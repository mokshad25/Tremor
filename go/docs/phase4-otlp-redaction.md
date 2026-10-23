# Phase 4: OTLP ingestion and PII redaction

## Results

| Claim | Measured | Evidence |
|---|---|---|
| An OpenTelemetry Collector delivers logs end to end, by config only | 20,000/20,000 events over OTLP/HTTP **and** over OTLP/gRPC (Collector-contrib 0.136.0, filelog → batch → otlphttp/otlp, gzip), 0 raw PII values in the WAL | `deploy/otel-collector/verify.sh`, `bench/results/phase4/otel-collector-e2e.txt` |
| Overload makes the Collector retry, not drop | With a single admission slot: OTLP/HTTP got 9 × 429, the Collector retried, **50,000/50,000** delivered. OTLP/gRPC delivered 50,000/50,000 with backpressure applied as HTTP/2 stream limits (see below) | `OVERLOAD=1 N=50000 verify.sh`, `bench/results/phase4/otel-collector-e2e-overload.txt` |
| Raw PII never reaches disk | 0 of 5,655 (20k run) and 0 of 12,282 (50k run) distinct raw values found in the WAL after the Collector runs; 0 raw values in any file after native, OTLP/HTTP and OTLP/gRPC ingest (`TestRawPIINeverReachesDisk` scans every byte TREMOR wrote) | tests + verify.sh |
| Redaction accuracy, labelled synthetic set | **recall 100%** (4,734/4,734), **precision 94.9%**, 0 values leaked verbatim (updated in Phase 5: role accounts like `root` are no longer counted as personal data; first measurement was 94.5% on 4,713) | `bench/results/phase4/pii-precision-recall.md` |
| Throughput cost of redaction (full pipeline, 4 cores) | **none measurable at this stage**: 150k ev/s sustained with redaction vs 140k without; at saturation 169.8k vs 156.7k ev/s accepted (mean of 3 alternating runs) | `bench/results/phase4/` |

## OTLP receivers (`internal/ingest/otlp*.go`)

- **Endpoints:** OTLP/HTTP `POST /v1/logs` on `:4318` (protobuf or JSON, optional gzip) and OTLP/gRPC `LogsService/Export` on `:4317` (gzip registered). Both use the official generated protos (`go.opentelemetry.io/proto/otlp`).
- **One path for every receiver.** Native JSON, OTLP/HTTP and OTLP/gRPC all go: admission slot → decode → redact → WAL queue → wait for the fsync ack (`ingest.Gateway`). Backpressure, redaction-before-disk and ack-after-fsync can't drift between protocols.

**Mapping:**

| OTLP | TREMOR event |
|---|---|
| resource attribute `service.name` | `Service`, the shard key (missing: `unknown_service`, the SDK default) |
| `time_unix_nano`, else `observed_time_unix_nano`, else receive time | `Timestamp` |
| `severity_number` (1–8 DEBUG, 9–12 INFO, 13–16 WARN, 17–24 ERROR), else `severity_text` | `Level` |
| `body` (strings as-is; scalars as text; arrays/maps as compact JSON) | `Message` |
| log attributes; other resource attributes as `resource.<key>`; trace/span IDs as hex | `Attrs` |

Oversized fields are **clamped**, not rejected: an OTLP client can't fix one bad record, and rejecting the batch would drop every good record with it.

**Status codes (so exporters retry correctly):**

| Situation | OTLP/HTTP | OTLP/gRPC | Exporter behaviour |
|---|---|---|---|
| Queue full (backpressure) | 429 + `Retry-After` + `google.rpc.Status` body | `RESOURCE_EXHAUSTED` + `RetryInfo` | retry with backoff |
| Draining, WAL failure, ack timeout | 503 + `Retry-After` | `UNAVAILABLE` + `RetryInfo` | retry with backoff |
| Malformed, too many records | 400 (413 for an oversized body) + Status | `INVALID_ARGUMENT` | drop (not retryable) |
| Empty export | 200 | OK | — |

Successful responses carry `X-Tremor-Seq: first-last` (HTTP header or gRPC metadata) for debugging.

- **OTLP/JSON** needed its own small decoder. The OTLP spec encodes `traceId`/`spanId` as **hex**, while protobuf's canonical JSON (`protojson`) expects base64, so `protojson` would reject valid OTLP/JSON. The decoder also accepts 64-bit integers as strings or numbers and severity as a number or enum name, and it produces the same proto request as the binary path.
- **Memory bounds:**
  - OTLP/HTTP reserves the admission slot *before* reading the body, exactly like `/ingest`.
  - gzip bodies are limited **after** decompression too, so a small gzip bomb can't expand past `max_body_bytes` (tested).
  - gRPC decodes before our handler runs, so `MaxRecvMsgSize` is set to the same body limit and `MaxConcurrentStreams` to the admission capacity.
- **How gRPC backpressure actually showed up.** In the live overload run, the gRPC leg delivered everything without a single `RESOURCE_EXHAUSTED`. `MaxConcurrentStreams` equals the admission capacity (1 in that run), so the Collector's one connection queued its calls at the HTTP/2 layer: backpressure as flow control, before a request could even be rejected. With more client connections than slots, or bursts across connections, the explicit `RESOURCE_EXHAUSTED` + `RetryInfo` path applies. That path is covered by `TestOTLPGRPCOverloadAndInvalid` with a real gRPC client, not by the live run.
- **Collector batch size.** TREMOR rejects requests with more than 5,000 records (or 1 MiB). The Collector's `batch` processor would happily send 8,192, and a 400 is permanent. So the example config sets `send_batch_max_size: 2000`. This is a real operational coupling and is documented next to the setting.

## PII redaction (`internal/redact`)

**Where.** In the gateway, after decoding and **before** the batch is queued for the WAL. Nothing downstream (WAL, Drain templates, alerts, metrics, logs, the Phase 6 LLM) ever sees raw values. It runs in the request goroutines, so it parallelises across cores, and it's applied to the message and **every attribute value**.

**What:**

| Kind | Detection | Replacement |
|---|---|---|
| Email | expand around `@`, domain with a 2+ letter TLD | `<EMAIL>` |
| Indian mobile | 10 digits starting 6–9, or `+91`/`91`/`0` prefixed; groupings `5-5`, `3-3-4`, `4-3-3`; skipped right after an id word (order, invoice, txn, ref, `#`) | `<PHONE>` |
| Aadhaar | 12 digits (or `4-4-4`), first digit 2–9, valid **Verhoeff** check digit | `<AADHAAR>` |
| PAN | `[A-Z]{5}[0-9]{4}[A-Z]` **and** 4th letter is a valid holder type (`PCHFATBLJG`) | `<PAN>` |
| Card | 13–19 digits (or `4-4-4-4`, Amex `4-6-5`), **Luhn** valid **and** a real issuer prefix (Visa, MC, Amex, RuPay, Discover, JCB, Diners, UnionPay, Maestro) | `<CARD>` |
| API key | ~25 known prefixes (Stripe `sk_live_`, AWS `AKIA`, GitHub `ghp_`, Slack `xoxb-`, Google `AIza`, Groq `gsk_`, GitLab `glpat-`, ...) | `<API_KEY>` |
| Token | `Bearer`/`Basic` credentials, JWTs (`eyJ…` with two dots) | `<TOKEN>` |
| Secret | value of `password=`, `token:`, `"secret":`, ...; or any 24+ character string with mixed case, digits and Shannon entropy ≥ 4.2 bits/char | `<SECRET>` |
| IP (v4/v6) | `netip`-validated, port kept (`10.0.0.1:8080`) | `ip_<hmac>` (**tokenized**) |
| Username | `user=`, `username:`, `login=`, … and sshd/PAM phrases (`Failed password for [invalid user] X`, `session opened for user X`) | `usr_<hmac>` (**tokenized**) |

**Why some values are tokenized instead of deleted.** The Phase 5 security rules need "20 failures for *one user* from *one source*". `ip_<hmac>`/`usr_<hmac>` keep identity and drop the value:

- the token is `HMAC-SHA256(key, domain ‖ 0x00 ‖ value)` truncated to 48 bits;
- the same value always yields the same token, so counting works;
- without the key the token can't be reversed. A plain SHA-256 of an IPv4 address *can* be: there are only 2³² addresses to try;
- the domain separator stops `admin` the username and `admin` the hostname from sharing a token;
- IPs are canonicalised first (`::ffff:1.2.3.4` = `1.2.3.4`), and email-style usernames are lowercased;
- 48 bits keeps the chance of any collision under 1% up to about 2 million distinct values per domain.

The key comes only from `TREMOR_HMAC_KEY`, never from the YAML file. Without it the server generates a random key and warns that tokens will change on restart, which would break the cross-restart correlation the security rules want.

**Email used as a login.** In `user=alice@example.com` the value is a *username* (`usr_…`), not `<EMAIL>`: identity is preserved for brute-force detection. Overlaps are resolved by priority: secrets > usernames > email > card > Aadhaar > phone > PAN > IP.

**Attributes.** Keys choose the treatment:

- keys containing `password`/`token`/`authorization`/`cookie`/`secret`/… are masked whatever the value looks like (`db.password: "x"` → `<SECRET>`);
- user keys (`user`, `enduser.id`, `user.name`, …) are tokenized whole;
- a value that is exactly an IP is tokenized;
- everything else goes through the message scanner.

The service name isn't redacted: it's configuration, and it's the shard key.

**Templates stay meaningful.** Before Drain, `ip_<hex12>`/`usr_<hex12>` become `<IP>`/`<USER>` (`drain.MaskTokens`), so `upstream=ip_3f2a…` mines as `upstream=<IP>`, not `<*>`. This is a separate step from TREMOR's masker, so drain3 parity is still tested on the unchanged ruleset.

**Implementation.** Hand-written single-pass scanners, not regexps: Go's `regexp` cost about 10 µs per message in Phase 3. The scanners lowercase the line once and use `strings.Index` (SIMD) for keyword search.

- First version: 11.2 µs per line. After lowercasing once: 3.0 µs. With cheap length/character guards: **2.4 µs** per line on the benchmark lines, 1.9 µs on loadgen's mix.
- Allocations are about 700 B per line.
- The card-leak fuzz test (`FuzzRedactNeverLeaksCards`) puts a card number between arbitrary text and requires it never survives.

### Accuracy on the labelled synthetic set

`internal/redact/testdata/pii_labelled.jsonl` has 5,000 lines in 31 formats (sshd, PAM, nginx, app/JSON, payments, KYC, support, CI, k8s). 60% carry PII (4,713 labelled values) and 40% carry none. The generator (`testdata/gen`) **shares no code with the redactor**: it has its own Luhn and Verhoeff and its own formats.

Scoring is strict. A label counts as found only if a finding of the **same kind** covers the whole value. Any finding that covers no label of its kind is a false positive.

| kind | precision | recall | TP | FP | FN |
|---|---|---|---|---|---|
| api_key | 100.0% | 100.0% | 263 | 0 | 0 |
| token | 100.0% | 100.0% | 156 | 0 | 0 |
| secret | 100.0% | 100.0% | 276 | 0 | 0 |
| username | 100.0% | 100.0% | 863 | 0 | 0 |
| email | 100.0% | 100.0% | 602 | 0 | 0 |
| card | 92.1% | 100.0% | 279 | 24 | 0 |
| aadhaar | 77.3% | 100.0% | 259 | 76 | 0 |
| phone | 77.5% | 100.0% | 604 | 175 | 0 |
| pan | 100.0% | 100.0% | 259 | 0 | 0 |
| ip | 100.0% | 100.0% | 1,152 | 0 | 0 |
| **all** | **94.5%** | **100.0%** | 4,713 | 275 | 0 |

**Read this honestly:**

- **The set is synthetic and I wrote the generator.** Recall of 100% means the detector handles every format the generator produces. It doesn't mean every real-world format. Real logs will contain formats neither of us thought of.
- **The 275 false positives are deliberate.** Hard negatives (12-digit order IDs, 16-digit tracking numbers starting with 4, 10-digit `mem=`/`plan_hash=` values) are generated at random and **not filtered**. About 1 in 10 random digit strings passes Luhn or Verhoeff, and any 10-digit number starting 6–9 looks like a mobile. That's the inherent cost of checksum-only detection, and it's the right trade for a privacy control: masking an order ID costs a little debuggability, while missing an Aadhaar number is a compliance breach (DPDPA).
- **I fixed exactly two rules after seeing the first numbers**, both genuine bugs rather than tuning to the test:
  - `uid=0` was being tokenized as a username (uid is a numeric account ID);
  - SSH key fingerprints (`SHA256:<base64>`) were flagged as high-entropy secrets (they're public).

  That took precision from 89.2% to 94.5%. I deliberately did **not** add context words matched to the generator's negative templates, because that would inflate precision on a set I wrote.
- **Known gaps:** non-Indian phone formats, names and addresses in free text (no NER), PII split across attributes, and secrets shorter than 24 characters outside a `key=value` context.

## Throughput: redaction costs nothing measurable, for now

Measured on the full pipeline (WAL with fsync, Drain + detection), Apple M2, tremor and loadgen at GOMAXPROCS=4, 10 services, loadgen messages carrying emails, cards, JWTs, IPs and keys:

| | redaction on | redaction off |
|---|---|---|
| Max sustainable (≤1% 429, 10k steps) | **150,000 ev/s** | 140,000 ev/s |
| Accepted at saturation (300k offered, 3 alternating 30 s runs) | 173,466 / 169,846 / 166,202 → mean **169,838** | 159,620 / 152,332 / 158,212 → mean **156,721** |

Redaction-on runs are *faster*. That's surprising, so I tested why instead of just reporting it.

- **Redaction moves work off the bottleneck.** It costs about 1.9 µs per event, but in the gateway goroutines, which run in parallel on all cores. The bottleneck is the shards' Drain masking (Phase 3: 10.7 µs per message, regex-bound).
- **And it makes that bottleneck cheaper.** Redaction shortens messages before they reach it: emails, 16-digit cards and JWTs become short placeholders. Measured on 5,000 loadgen messages, shard masking costs **7,506 ns raw vs 6,705 ns redacted (−10.7%)**.
- **Caveats:**
  - A coarse 25k-step sweep first showed 125k vs 150k. That was noise from a borderline step (1.02% 429), and the 10k-step sweep and the saturation runs both contradict it.
  - Redaction-on runs had noisier p99 (occasional 90–120 ms spikes vs ~17 ms off), likely GC from ~700 B of allocations per event.
  - Once Phase 7 speeds up the shard masker, redaction's own 1.9 µs per event will become visible. It must be re-measured then, so "no cost" is a statement about this build, not a property of redaction.

## Dependencies added in this phase

| module | why |
|---|---|
| `go.opentelemetry.io/proto/otlp` | the official generated OTLP protobuf types; required to be wire-compatible with every OTel SDK and Collector |
| `google.golang.org/grpc` | OTLP/gRPC (port 4317) |
| `google.golang.org/protobuf` | protobuf encoding for OTLP/HTTP and for `google.rpc.Status` error bodies |
| `google.golang.org/genproto/googleapis/rpc` | `google.rpc.Status` and `RetryInfo`, which the OTLP spec uses for errors and retry hints |

I deliberately did not use the Collector's own `pdata` library. It handles OTLP/JSON quirks, but it would pull in a large part of the Collector. The ~150-line JSON decoder here covers the logs schema and is tested against the spec's encodings.

## Reproduce

```bash
go test ./internal/redact/ ./internal/ingest/ ./internal/server/
deploy/otel-collector/verify.sh
OVERLOAD=1 N=50000 deploy/otel-collector/verify.sh
bench/redact_cost.sh
go run ./internal/redact/testdata/gen > internal/redact/testdata/pii_labelled.jsonl
```

In order, these run the precision/recall test, the raw-PII disk scan and the OTLP receiver tests; the Collector check (needs Docker, pulls Collector-contrib 0.136.0); the Collector check under forced overload; the throughput cost at saturation; and regeneration of the PII set (deterministic).
