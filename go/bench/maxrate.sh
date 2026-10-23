#!/usr/bin/env bash
# Find TREMOR's max sustainable ingest rate: raise the offered load step by
# step until the gateway starts shedding load (429s > 1% of requests). The max
# is the highest step where the server accepted >= 99% of what was offered.
#
# If the load generator itself cannot keep up (client_dropped > 1%), the run
# stops and says so: then the number is a loadgen limit, not a server limit.
#
# Env: START (20000) STEP (20000) MAX_RATE (600000) STEP_DUR (20s)
#      BATCH (100) SERVICES (10) CONCURRENCY (512) PREGEN (1024) SERVER_PROCS LOADGEN_PROCS
source "$(dirname "$0")/lib.sh"

START="${START:-20000}"
STEP="${STEP:-20000}"
MAX_RATE="${MAX_RATE:-600000}"
STEP_DUR="${STEP_DUR:-20s}"
BATCH="${BATCH:-100}"
SERVICES="${SERVICES:-10}"
CONCURRENCY="${CONCURRENCY:-512}" # > queue_capacity so the server, not the client, is the limit
PREGEN="${PREGEN:-1024}"          # pre-built bodies: keeps loadgen CPU off the shared cores

stamp="$(date +%Y%m%d-%H%M%S)"
tsv="$OUT/maxrate-$stamp.tsv"
build
start_server "$OUT/maxrate-$stamp-server.log"

printf "target_eps\toffered_eps\taccepted_eps\tok\t429\t503\tother\ttransport\tdropped\tp50_ms\tp99_ms\n" | tee "$tsv"
best=0
verdict="reached MAX_RATE=$MAX_RATE without shedding load; raise MAX_RATE"
for ((rate = START; rate <= MAX_RATE; rate += STEP)); do
	json="$OUT/maxrate-$stamp-$rate.json"
	loadgen -rate "$rate" -duration "$STEP_DUR" -batch "$BATCH" -services "$SERVICES" \
		-concurrency "$CONCURRENCY" -pregen "$PREGEN" -progress 0 -out "$json" >/dev/null
	jq -r '[.target_eps, (.offered_eps|floor), (.accepted_eps|floor), .ok, .rejected_429, .rejected_503,
	        .other_status, .transport_errors, .client_dropped, .ok_latency_ms.p50, .ok_latency_ms.p99] | @tsv' "$json" | tee -a "$tsv"

	read -r req r429 dropped accepted offered <<<"$(jq -r '[.requests, .rejected_429, .client_dropped, .accepted_eps, .offered_eps] | @tsv' "$json")"
	scheduled=$((req + dropped))
	reasons=()
	((r429 * 100 > req)) && reasons+=("429s >1% of requests")
	awk -v a="$accepted" -v o="$offered" 'BEGIN{exit !(a < 0.99*o)}' && reasons+=("accepted <99% of offered")
	((dropped * 100 > scheduled)) && reasons+=("loadgen dropped >1% (client-bound)")
	if ((${#reasons[@]} > 0)); then
		verdict="stopped at $rate ev/s: $(IFS=';'; echo "${reasons[*]}")"
		break
	fi
	best=$rate
done
stop_server

echo
echo "max sustainable rate: $best ev/s ($verdict)"
echo "$best" >"$OUT/max_rate.txt"
echo "results: $tsv"
