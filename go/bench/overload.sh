#!/usr/bin/env bash
# Phase 1 acceptance: offer 2x the max sustainable rate for 10 minutes and
# check that (a) every request the server did not accept got an explicit
# 429/503 (no timeouts, resets or other statuses), and (b) memory stays flat.
#
# Env: RATE (default 2 x bench/out/max_rate.txt) DURATION (600s) BATCH (100)
#      SERVICES (10) CONCURRENCY (1024) PREGEN (1024) SAMPLE_EVERY (5)
source "$(dirname "$0")/lib.sh"

if [[ -z "${RATE:-}" ]]; then
	[[ -f "$OUT/max_rate.txt" ]] || { echo "run bench/maxrate.sh first or set RATE" >&2; exit 1; }
	RATE=$(($(cat "$OUT/max_rate.txt") * 2))
fi
DURATION="${DURATION:-600s}"
BATCH="${BATCH:-100}"
SERVICES="${SERVICES:-10}"
CONCURRENCY="${CONCURRENCY:-1024}"
SAMPLE_EVERY="${SAMPLE_EVERY:-5}"
PREGEN="${PREGEN:-1024}"

stamp="$(date +%Y%m%d-%H%M%S)"
csv="$OUT/overload-$stamp-mem.csv"
json="$OUT/overload-$stamp.json"
build
start_server "$OUT/overload-$stamp-server.log"

# Sample server memory while the load runs.
echo "t_s,rss_mb,heap_inuse_mb,heap_sys_mb,queue_inflight,requests_429_total" >"$csv"
(
	t0=$(date +%s)
	while kill -0 "$SERVER_PID" 2>/dev/null; do
		rss_kb=$(ps -o rss= -p "$SERVER_PID" | tr -d ' ')
		vars=$(curl -sf "$DEBUG_URL" || echo '{}')
		echo "$(($(date +%s) - t0)),$((rss_kb / 1024)),$(jq -r '[(.memstats.HeapInuse/1048576|floor), (.memstats.HeapSys/1048576|floor), .tremor.queue_inflight, .tremor.requests_429_total] | join(",")' <<<"$vars")" >>"$csv"
		sleep "$SAMPLE_EVERY"
	done
) &
sampler=$!

echo "offering $RATE ev/s for $DURATION (concurrency $CONCURRENCY)..."
loadgen -rate "$RATE" -duration "$DURATION" -batch "$BATCH" -services "$SERVICES" \
	-concurrency "$CONCURRENCY" -pregen "$PREGEN" -progress 30s -out "$json" >/dev/null
sleep "$SAMPLE_EVERY"
stop_server
wait "$sampler" 2>/dev/null || true

python3 - "$csv" "$json" <<'EOF'
import csv, json, sys
rows = [r for r in csv.DictReader(open(sys.argv[1])) if r["rss_mb"]]
s = json.load(open(sys.argv[2]))
dur = s["duration_s"]
warm = min(60, dur / 5)  # skip warm-up (heap growing to its working size)
run = [r for r in rows if warm <= int(r["t_s"]) <= dur]
rss = [int(r["rss_mb"]) for r in run]
q = max(1, len(rss) // 4)
early = max(rss[:q])          # peak in the first quarter after warm-up
late = max(rss[-q:])         # peak in the last quarter
n = len(run)
ts = [int(r["t_s"]) for r in run]
mt, mr = sum(ts) / n, sum(rss) / n
slope = sum((t - mt) * (r - mr) for t, r in zip(ts, rss)) / sum((t - mt) ** 2 for t in ts)  # MB/s
flat = late <= early * 1.10 + 5
explicit = s["all_rejections_explicit"]
print(f"offered {s['offered_eps']:.0f} ev/s, accepted {s['accepted_eps']:.0f} ev/s")
print(f"requests {s['requests']}: ok {s['ok']}, 429 {s['rejected_429']}, 503 {s['rejected_503']}, "
      f"other {s['other_status']}, transport errors {s['transport_errors']}, client dropped {s['client_dropped']}")
print(f"RSS after warm-up: min {min(rss)} MB, max {max(rss)} MB; first-quarter peak {early} MB, "
      f"last-quarter peak {late} MB; trend {slope*60:+.2f} MB/min")
print(f"every rejection explicit (429/503): {'PASS' if explicit else 'FAIL'}")
print(f"memory flat (last-quarter peak <= 1.10 x first-quarter peak + 5 MB): {'PASS' if flat else 'FAIL'}")
sys.exit(0 if (explicit and flat) else 1)
EOF
echo "raw: $json $csv"
