#!/usr/bin/env bash
# Throughput cost of PII redaction on the full pipeline: offer far more than
# the server can take (SAT_RATE) and record what it accepts, alternating
# redaction on/off RUNS times so drift on a shared laptop hits both alike.
#
# Env: SAT_RATE (300000) DUR (30s) RUNS (3) BATCH (100) SERVICES (10)
source "$(dirname "$0")/lib.sh"
SAT_RATE="${SAT_RATE:-300000}"
DUR="${DUR:-30s}"
RUNS="${RUNS:-3}"
BATCH="${BATCH:-100}"
SERVICES="${SERVICES:-10}"
stamp="$(date +%Y%m%d-%H%M%S)"
tsv="$OUT/redact-cost-$stamp.tsv"
build
printf "run\tredact\taccepted_eps\t429\tredactions_total\n" | tee "$tsv"
for ((i = 1; i <= RUNS; i++)); do
	for red in true false; do
		export TREMOR_REDACT=$red TREMOR_WAL_DIR="$OUT/wal-redact-cost"
		rm -rf "$TREMOR_WAL_DIR"
		start_server "$OUT/redact-cost-$stamp-server.log"
		loadgen -rate "$SAT_RATE" -duration "$DUR" -batch "$BATCH" -services "$SERVICES" \
			-concurrency 512 -pregen 1024 -progress 0 -out "$OUT/redact-cost-$stamp.json" >/dev/null
		reds=$(curl -sf "$DEBUG_URL" | jq '[.tremor | to_entries[] | select(.key|startswith("redactions_")) | .value] | add // 0')
		stop_server
		printf "%d\t%s\t%s\t%s\t%s\n" "$i" "$red" "$(jq '.accepted_eps|floor' "$OUT/redact-cost-$stamp.json")" \
			"$(jq .rejected_429 "$OUT/redact-cost-$stamp.json")" "$reds" | tee -a "$tsv"
	done
done
rm -rf "$OUT/wal-redact-cost"
unset TREMOR_REDACT TREMOR_WAL_DIR
awk -F'\t' 'NR>1 {s[$2]+=$3; n[$2]++} END {on=s["true"]/n["true"]; off=s["false"]/n["false"];
  printf "mean accepted: redaction on %.0f ev/s, off %.0f ev/s, cost %.1f%%\n", on, off, (1-on/off)*100}' "$tsv"
echo "results: $tsv"
