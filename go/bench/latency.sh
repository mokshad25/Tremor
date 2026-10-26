#!/usr/bin/env bash
# Ingest-to-alert latency (plan target: p99 under 500 ms). For each offered
# rate, a fresh server takes loadgen traffic with periodic error spikes
# (ERROR_RATE alerts at the 1 s tick) and every attack type injected
# (security alerts right after the line). Each OPEN/ESCALATED alert logs
# ingest_to_alert_ms: from the gateway receive time of the alert's newest
# line to the alert leaving detection (see Server.stampIngestToAlert), so it
# covers redaction, the WAL fsync and ack, routing, Drain and detection.
# Percentiles are exact, computed from every alert in the server log.
#
# The privilege rule needs its learning period to end before the attack, so
# this run sets detect.security.privilege_learn_s to 20 s (as live_attacks.sh).
#
# Env: RATES ("10000 50000 150000") DUR (6m) SERVICES (6)
source "$(dirname "$0")/lib.sh"
RATES="${RATES:-10000 50000 150000}"
DUR="${DUR:-6m}"
SERVICES="${SERVICES:-6}"
stamp="$(date +%Y%m%d-%H%M%S)"
cfg="$OUT/latency-$stamp.yaml"
sed 's/privilege_learn_s: [0-9]*/privilege_learn_s: 20/' "$ROOT/config.example.yaml" >"$cfg"
grep -q "privilege_learn_s: 20" "$cfg" || {
	echo "could not patch config" >&2
	exit 1
}
build
export TREMOR_WAL_DIR="$OUT/wal-latency"
export TREMOR_HMAC_KEY="${TREMOR_HMAC_KEY:-latency-bench-key-0123456789abcdef}"
tsv="$OUT/latency-$stamp.tsv"

# pct FILE Q: the Q-quantile (nearest rank) of the sorted numbers in FILE.
pct() { awk -v q="$2" '{v[NR] = $1} END {if (NR == 0) {print "-"; exit} i = int(q * NR + 0.999999); if (i < 1) i = 1; printf "%.1f", v[i]}' "$1"; }

printf "rate\taccepted_eps\tgroup\talerts\tp50_ms\tp90_ms\tp99_ms\tmax_ms\n" | tee "$tsv"
for rate in $RATES; do
	rm -rf "$TREMOR_WAL_DIR"
	log="$OUT/latency-$stamp-$rate-server.log"
	GOMAXPROCS="$SERVER_PROCS" "$ROOT/bin/tremor" -config "$cfg" 2>"$log" &
	SERVER_PID=$!
	until curl -sf "$DEBUG_URL" >/dev/null; do
		kill -0 "$SERVER_PID" 2>/dev/null || {
			echo "server exited; see $log" >&2
			exit 1
		}
		sleep 0.2
	done
	json="$OUT/latency-$stamp-$rate.json"
	loadgen -rate "$rate" -duration "$DUR" -services "$SERVICES" -concurrency 256 \
		-spike-every 40s -spike-len 10s -spike-error-rate 0.5 \
		-attack all -attack-at 30s -attack-gap 90s -progress 0 -out "$json" >/dev/null
	sleep 2
	stop_server
	acc=$(jq '.accepted_eps|floor' "$json")
	grep '"msg":"alert"' "$log" | jq -r 'select(.ingest_to_alert_ms > 0) | "\(.type)\t\(.ingest_to_alert_ms)"' >"$log.lat"
	for group in all ERROR_RATE security; do
		case "$group" in
		all) cut -f2 "$log.lat" ;;
		ERROR_RATE) awk -F'\t' '$1 == "ERROR_RATE" {print $2}' "$log.lat" ;;
		security) awk -F'\t' '$1 ~ /BRUTE|STUFF|PRIV|UNUSUAL/ {print $2}' "$log.lat" ;;
		esac | sort -g >"$log.$group"
		printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$rate" "$acc" "$group" "$(wc -l <"$log.$group" | tr -d ' ')" \
			"$(pct "$log.$group" 0.50)" "$(pct "$log.$group" 0.90)" "$(pct "$log.$group" 0.99)" "$(pct "$log.$group" 1)" | tee -a "$tsv"
	done
done
rm -rf "$TREMOR_WAL_DIR"
echo "results: $tsv"
