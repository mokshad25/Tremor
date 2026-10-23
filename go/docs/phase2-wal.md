# Phase 2: write-ahead log and crash recovery

## The guarantee

**At-least-once.** A producer gets `200 {"accepted":n,"first_seq":a,"last_seq":b}` only after records `a..b` have been fsynced to the WAL. Every acknowledged event is processed by its shard at least once, including across `kill -9`. Duplicates can happen, both from replay after a crash and from producer retries after a timeout. Replay duplicates are dropped by sequence number at the shard; the alert stage (Phase 6) dedups the rest.

```
gateway ─▶ ingest queue ─▶ committer ─▶ syncer ─────────▶ dispatcher ─▶ shards ─▶ checkpointer
 (429)      (bounded)     append, flush   fsync, ack, in     route by      process,    persist cps,
                          close groups    seq order          service      advance cp   delete segments
```

## On-disk format

```
data/wal/
  00000000000000000001.wal     segment, named by its first seq
  00000000000004718213.wal
  checkpoint.json              {"version":1,"router":"mod-fnv1a/8","shards":[...]}
```

Each segment starts with the 8-byte magic `TRMWAL01`, followed by records:

```
length u32 │ crc32c u32 │ seq u64 │ payload (event.AppendBinary)
           └── covers seq + payload ──┘
```

- **Length first:** a reader can frame records without decoding them, and an absurd length (above 1 MiB, far beyond any real event) is recognised as garbage straight away.
- **The CRC covers the seq:** a torn write can't produce a valid-looking record with a stale sequence number.
- **CRC-32C (Castagnoli):** it has hardware support on arm64 and amd64, and it's the checksum used by ext4, iSCSI and many databases' WALs.
- **The payload is a compact binary format:** a version byte, varints, length-prefixed strings and attributes sorted by key. Encoding is deterministic. The decoder is fuzzed (`FuzzDecodeBinary`) and rejects truncated or trailing bytes.
- **Rotation:** a new segment starts when the active one would exceed `segment_bytes` (64 MiB). The old segment is fsynced before it's closed, and the directory is fsynced after the new file is created, so the file's existence is durable too.

## Group commit (and why it's pipelined)

A group of batches closes when `sync_every_records` (10,000) records are pending, or `sync_interval` (10 ms) after its first record, whichever comes first. Then:

1. **Committer goroutine:** `Flush()` writes the group to the OS (`write`, page cache) and passes it to the syncer through a channel bounded at 4 groups.
2. **Syncer goroutine:** fsyncs, acks every batch in the group, and dispatches the events to the shards, strictly in order.

The first version did all of this synchronously in one goroutine. Measured on this machine (`bench/results/phase2/maxrate-wal-*.tsv`), it sustained **400k ev/s with p99 92 ms** and already had 0.75% 429s at that rate. `F_FULLFSYNC` averages about 2.5 ms but has spikes up to about 90 ms, and while the committer was blocked in fsync, the 256 ingest admission slots filled up. Pipelined, the next group keeps filling during a slow fsync, so a stall produces a bigger next group instead of 429s. The pipelined committer sustains **550k ev/s, with p99 18 ms at 400k**.

Rotation and fsync can race: the syncer may be about to fsync a file that a rotation is closing. Every segment has a generation number. Rotation fsyncs and closes the old file under `syncMu` and records `closedGen`. A later fsync request for a generation ≤ `closedGen` is already satisfied. `TestPipelinedCommitAcrossRotations` drives this hard with 4 KiB segments.

## The fsync trade-off

Measured with `bench/fsync.sh`: Apple M2 internal SSD, macOS 26.3, tremor and loadgen each at GOMAXPROCS=4, 100-event batches, 20 s per point. On macOS, Go's `File.Sync` issues `F_FULLFSYNC`, which flushes the drive's own write cache. Plain `fsync(2)` on macOS doesn't, so it would be faster but not durable.

| setting | saturated accepted ev/s | ack p50 @ 50k ev/s | ack p99 @ 50k ev/s | fsyncs in 20 s @ 50k | avg / max fsync |
|---|---|---|---|---|---|
| no fsync (page cache only; **not durable**) | 975,381 | 6.96 ms | 13.16 ms | 1,762 | 0.00 / 0.14 ms |
| fsync, 1 ms interval | 785,752 | 4.83 ms | 16.12 ms | 7,716 | 2.11 / 33.16 ms |
| fsync, 5 ms interval | 721,870 | 7.43 ms | 13.62 ms | 2,950 | 2.48 / 24.29 ms |
| **fsync, 10 ms interval (default)** | 659,291 | 9.78 ms | 19.45 ms | 1,690 | 2.78 / 51.86 ms |
| fsync, 50 ms interval | 775,924 | 30.32 ms | 56.09 ms | 387 | 3.09 / 8.09 ms |
| fsync, 50 ms or 1,000 records | 617,216 | 13.04 ms | 23.09 ms | 1,000 | 2.75 / 12.15 ms |

(Raw: `bench/results/phase2/fsync-pipelined-committer.tsv`. Latency is measured from the scheduled send time, so it includes HTTP and loadgen overhead, about 2 ms.)

What the numbers say:

- **Latency ≈ interval/2 + fsync time + ~2 ms.** That's the cost producers feel for durability. At 50k ev/s even the 1 ms setting forms groups, because 1 ms is still about 50 events.
- **Durability costs roughly 20–35% of saturated throughput** here (975k without fsync vs 620k–790k with). The spread between the fsync rows is mostly run-to-run noise on a laptop; there's no clean monotonic trend, so I'm not claiming one.
- **The record trigger matters more than the interval under saturation.** With the old synchronous committer, capping groups at 1,000 records hit the predicted ceiling `1000 / 3.15 ms ≈ 317k` (measured 357k). Pipelining raised it to 617k, because a later fsync finds little left to flush once an earlier one has covered its data.
- **Choice: 10 ms / 10,000 records.** TREMOR's latency budget is p99 ingest-to-alert under 500 ms, so ≤10 ms of group wait is negligible. 10 ms does about half as many fsyncs as 5 ms (less I/O and less SSD wear) for a few milliseconds of p50. If a deployment needs lower ack latency, 5 ms is the next step.

### What can be lost, and when

| Failure | fsync on (default) | fsync off |
|---|---|---|
| Process crash (`kill -9`, panic, OOM) | Nothing acked. Records written but not yet acked survive in the page cache and are replayed (they become duplicates if the producer retries). | Same: the page cache survives a process crash. |
| OS crash / power loss | Nothing acked. At most the in-flight groups (≤ 4 + 1, each ≤ 10,000 records or 10 ms of traffic) of **unacked** records, which producers still hold and will retry. | **Acked data can be lost**: anything the kernel hadn't written back yet. |
| Failed fsync (EIO) | The log enters a sticky failed state, rejects every batch with 503, and is never retried. After a failed fsync Linux may have marked the dirty pages clean, so a retry can "succeed" without the data being on disk (the 2018 PostgreSQL "fsyncgate"). Recovery happens from what is known to be durable. | n/a |

## Checkpoints

Each shard keeps a checkpoint `cp`: every event routed to it with `seq ≤ cp` has been processed. Events reach a shard in seq order (one dispatcher, FIFO channels), so one number per shard is enough.

**Watermarks.** Each dispatch sends every shard a message, even shards that get no events in it, carrying the group's highest seq. After handling it, the shard sets `cp = watermark`. Without this, a quiet service's shard would never advance its checkpoint and would pin every WAL segment forever.

**Persisting.** Every `checkpoint.interval` (1 s) and at shutdown, the checkpointer:

1. reads every shard's `cp` (atomic loads);
2. flushes every shard's processor (`Processor.Flush`; in Phase 2 that's the test-only processed log);
3. writes `checkpoint.json` atomically: temp file, fsync, rename, then fsync the directory;
4. deletes segments whose last record ≤ min(persisted cps).

The order of 1 and 2 matters. Reading the checkpoints first guarantees that everything they cover was processed before the flush, and so is included in it. Flushing first would leave a window where a checkpoint claims work whose effects were never flushed.

**Routing changes.** The checkpoint stores the router's identity (`mod-fnv1a/8`). If the shard count or algorithm changes between runs, a service may now belong to a different shard, so the per-shard values no longer mean anything. Every shard then restarts from the **minimum**: that can cause duplicates, never skips (`TestShardCountChangeDoesNotSkip`).

## Recovery (startup order)

1. **Open the WAL.** Scan only the **last** segment, and stop at the first record that is short, has an impossible length, fails its CRC, or breaks the seq sequence. Truncate there and fsync. A last segment whose header is missing or torn (a crash during rotation) is reset to an empty segment. Earlier segments aren't scanned at open; they were fsynced and closed at rotation.
2. **Load `checkpoint.json`** and map it onto the current shard layout.
3. **Start the shards** with their restored checkpoints.
4. **Replay** from `min(checkpoints) + 1` through the normal dispatch path, in chunks with watermarks. Each shard skips events with `seq ≤` its own restored checkpoint: that's the "dedup by sequence number" for replay overlap. Corruption found during replay in any segment **other than the tail** is a hard error. A hole in the middle of the log means acknowledged data is gone, and quietly skipping it would turn a durability bug into silent data loss.
5. **Start the committer, the checkpointer and the gateway.** Producers can't connect until recovery is done, and new seqs continue from the last valid record.

Measured recovery time (open + checkpoint load + replay) across 100 chaos crashes: **at most 14 ms**, replaying at most 25,700 records. With a 1 s checkpoint interval the replay backlog is about one second of traffic.

## Graceful shutdown order

Draining (503) → `http.Server.Shutdown` (in-flight handlers get their acks) → close the ingest queue → committer closes the last group and the syncer fsyncs, acks and dispatches it → shards drain → final checkpoint (flush, then save) → close processors → close the WAL. After a clean shutdown the next start replays **zero** records (`TestCleanRestartReplaysNothing`).

## Chaos test

`cmd/chaos` (run with `bench/chaos.sh`) uses the real binary:

- 16 producers send continuously and record the `first_seq..last_seq` of every 200.
- Each cycle starts the server and SIGKILLs it at a random time: uniform in [0, 3 s], and with 20% probability in the first 50 ms so kills land inside recovery and replay. Readiness is watched concurrently, so probing never delays the kill.
- With 30% probability, 1–64 random bytes are appended to the last segment to imitate a torn write.
- After 50 cycles, one clean start and SIGTERM flush everything. Then it checks:
  - every acked seq appears in the processed logs (**lost = 0**);
  - no seq was acked twice (no seq reuse after truncation);
  - the final shutdown was clean.

Results (2 runs × 50 crashes; `bench/results/phase2/chaos-50-seed*.json`):

| seed | acked events | lost | seq reuse | killed before ready | torn tails injected / truncated on recovery | duplicates (replay overlap) | max recovery |
|---|---|---|---|---|---|---|---|
| 20261014 | 3,585,450 | **0** | 0 | 11 | 17 / 16 | 50,700 | 10.3 ms |
| 7 | 4,544,900 | **0** | 0 | 6 | 15 / 13 | 29,150 | 14.0 ms |

Two runs had fewer truncations than injections. That happens when two injections stack (the start in between was killed before it logged "recovery complete"), so one truncation removes both.

**What this test does not prove.** `kill -9` kills the process, not the machine: the OS page cache survives. This test proves the *ordering* logic: acks after the WAL has the data, checkpoints after processing, correct replay, and safe tail truncation. It can't prove that fsync really reaches stable storage on power loss. That needs a VM that can be hard-reset, or a power-cut rig, and is listed as future work.

## Memory bound, updated

- Ingest admission: `queue_capacity × max_body_bytes` (256 MiB worst case).
- WAL: at most 5 groups in flight (the one filling plus 4 closed), each ≤ `sync_every_records` (10,000) events.
- Shards: `shards.queue_capacity` (16) dispatch messages per shard, each at most one group's share.

A 2-minute 2× overload with the WAL on (`bench/results/phase2/overload-wal-2x-120s*`) offered 1.2M ev/s and accepted 825k. The other 449,636 requests got explicit 429s, with 0 other errors and 0 client drops. RSS stayed between 110 and 126 MB.
