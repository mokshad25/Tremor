#!/usr/bin/env bash
# The fsync trade-off: for each group-commit setting, measure
#   (a) saturated throughput: offer far more than the server can take and
#       record what it accepts, and
#   (b) ack latency at a fixed moderate load (what a producer waits for its
#       200, which now means "fsynced").
# plus the fsync count and average fsync time from the server's own metrics.
#
# Env: SAT_RATE (1200000) LAT_RATE (50000) STEP_DUR (20s) BATCH (100)
#      SERVICES (10) SERVER_PROCS (4) LOADGEN_PROCS (4)
source "$(dirname "$0")/lib.sh"

SAT_RATE="${SAT_RATE:-1200000}"
LAT_RATE="${LAT_RATE:-50000}"
STEP_DUR="${STEP_DUR:-20s}"
BATCH="${BATCH:-100}"
SERVICES="${SERVICES:-10}"

# fsync sync_interval sync_every_records label
SETTINGS=(
	"false 10ms 10000 no-fsync (page cache only; NOT durable)"
	"true 1ms 10000 fsync, 1ms interval"
	"true 5ms 10000 fsync, 5ms interval"
	"true 10ms 10000 fsync, 10ms interval (default)"
	"true 50ms 10000 fsync, 50ms interval"
	"true 50ms 1000 fsync, 50ms or 1000 records"
)

stamp="$(date +%Y%m%d-%H%M%S)"
tsv="$OUT/fsync-$stamp.tsv"
build
printf "setting\tsat_accepted_eps\tsat_429\tlat_p50_ms\tlat_p99_ms\tlat_syncs\tlat_avg_fsync_ms\tlat_max_fsync_ms\tsat_events_per_sync\n" | tee "$tsv"

for s in "${SETTINGS[@]}"; do
	read -r fsync interval every label <<<"$s"
	walDir="$OUT/wal-fsync-$stamp"
	rm -rf "$walDir"
	export TREMOR_WAL_DIR="$walDir" TREMOR_WAL_FSYNC="$fsync" TREMOR_WAL_SYNC_INTERVAL="$interval" TREMOR_WAL_SYNC_EVERY_RECORDS="$every"

	# (b) latency at a moderate, sustainable load
	start_server "$OUT/fsync-$stamp-server.log"
	loadgen -rate "$LAT_RATE" -duration "$STEP_DUR" -batch "$BATCH" -services "$SERVICES" \
		-concurrency 64 -pregen 1024 -progress 0 -out "$OUT/fsync-$stamp-lat.json" >/dev/null
	lat_vars=$(curl -sf "$DEBUG_URL" | jq '.tremor')
	stop_server

	# (a) saturated throughput
	rm -rf "$walDir"
	start_server "$OUT/fsync-$stamp-server.log"
	loadgen -rate "$SAT_RATE" -duration "$STEP_DUR" -batch "$BATCH" -services "$SERVICES" \
		-concurrency 512 -pregen 1024 -progress 0 -out "$OUT/fsync-$stamp-sat.json" >/dev/null
	sat_vars=$(curl -sf "$DEBUG_URL" | jq '.tremor')
	stop_server
	rm -rf "$walDir"

	printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$label" \
		"$(jq '.accepted_eps|floor' "$OUT/fsync-$stamp-sat.json")" \
		"$(jq '.rejected_429' "$OUT/fsync-$stamp-sat.json")" \
		"$(jq '.ok_latency_ms.p50*100|round/100' "$OUT/fsync-$stamp-lat.json")" \
		"$(jq '.ok_latency_ms.p99*100|round/100' "$OUT/fsync-$stamp-lat.json")" \
		"$(jq '.wal_syncs_total' <<<"$lat_vars")" \
		"$(jq 'if .wal_syncs_total > 0 then (.wal_sync_nanos_total/.wal_syncs_total/1e4|round/100) else 0 end' <<<"$lat_vars")" \
		"$(jq '.wal_sync_max_nanos/1e4|round/100' <<<"$lat_vars")" \
		"$(jq 'if .wal_syncs_total > 0 then (.wal_records_appended_total/.wal_syncs_total|floor) else 0 end' <<<"$sat_vars")" | tee -a "$tsv"
done
unset TREMOR_WAL_DIR TREMOR_WAL_FSYNC TREMOR_WAL_SYNC_INTERVAL TREMOR_WAL_SYNC_EVERY_RECORDS
echo "results: $tsv"
