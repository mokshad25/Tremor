#!/usr/bin/env bash
# Phase 2 acceptance: kill -9 the server CYCLES times under load and verify
# that every acknowledged event was processed.
#
# Env: CYCLES (50) MAX_UP (3s) GARBAGE (0.3) EARLY (0.2) PRODUCERS (16) SEED (random)
source "$(dirname "$0")/lib.sh"
trap - EXIT

CYCLES="${CYCLES:-50}"
MAX_UP="${MAX_UP:-3s}"
GARBAGE="${GARBAGE:-0.3}"
EARLY="${EARLY:-0.2}"
PRODUCERS="${PRODUCERS:-16}"
SEED="${SEED:-$(date +%s)}"

stamp="$(date +%Y%m%d-%H%M%S)"
build
(cd "$ROOT" && go build -o bin/chaos ./cmd/chaos)
"$ROOT/bin/chaos" -server "$ROOT/bin/tremor" -cycles "$CYCLES" -max-up "$MAX_UP" \
	-garbage "$GARBAGE" -early "$EARLY" -producers "$PRODUCERS" -seed "$SEED" \
	-out "$OUT/chaos-$stamp.json" >/dev/null
status=$?
jq '{seed, cycles, killed_before_ready, garbage_injections, recoveries_that_truncated_a_tail,
     acked_events, processed_unique_seqs, seqs_processed_more_than_once, processed_but_never_acked,
     lost_acked_events, overlapping_acked_ranges, max_recovery_ms, max_replayed_records,
     final_shutdown_clean, elapsed_s, pass}' "$OUT/chaos-$stamp.json"
echo "raw: $OUT/chaos-$stamp.json"
exit $status
