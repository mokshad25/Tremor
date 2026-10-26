#!/usr/bin/env bash
# TREMOR vs Vector vs Fluent Bit on the same machine, same events, same load.
#
# Each tool receives loadgen's synthetic events over HTTP and writes them to
# local disk, at a saturating offered rate, alternating tools RUNS times so
# drift on a shared machine hits all of them alike. Reported per run:
# accepted ev/s and p99 latency (loadgen), events on disk after a graceful
# stop, and peak RSS.
#
# The work is comparable, not identical, and the comparison says so:
#   tremor           redaction + WAL (fsync before ack) + Drain + detection
#   tremor-noredact  the same with TREMOR_REDACT=false
#   vector           http_server -> file sink, ack after write (no fsync)
#   fluent-bit       http input -> file output, ack on buffering (no fsync)
# Configs: bench/compare/. Needs vector and fluent-bit on PATH (macOS:
# brew install fluent-bit; Vector from github.com/vectordotdev/vector/releases
# or brew tap vectordotdev/brew && brew install vector).
#
# Env: SAT_RATE (600000) DUR (30s) RUNS (3) BATCH (100) SERVICES (10)
#      TOOLS ("tremor tremor-noredact vector fluent-bit") SETTLE (0)
source "$(dirname "$0")/lib.sh"
SAT_RATE="${SAT_RATE:-600000}"
DUR="${DUR:-30s}"
RUNS="${RUNS:-3}"
BATCH="${BATCH:-100}"
SERVICES="${SERVICES:-10}"
TOOLS="${TOOLS:-tremor tremor-noredact vector fluent-bit}"
SETTLE="${SETTLE:-0}" # seconds between the end of the load and the stop signal
VECTOR_URL="http://127.0.0.1:18081/ingest"
FLUENT_URL="http://127.0.0.1:18082/ingest"

stamp="$(date +%Y%m%d-%H%M%S)"
tsv="$OUT/compare-$stamp.tsv"
export COMPARE_DIR="$OUT/compare-$stamp"
export FB_WORKERS="$SERVER_PROCS"
mkdir -p "$COMPARE_DIR"
sed "s#COMPARE_DIR#$COMPARE_DIR#g" "$BENCH_DIR/compare/vector.toml" >"$COMPARE_DIR/vector.toml"
build

for t in $TOOLS; do
	case "$t" in
	vector | fluent-bit)
		command -v "$t" >/dev/null || {
			echo "$t not found on PATH (see the header of this script)" >&2
			exit 1
		}
		;;
	esac
done

# timed runs a server under /usr/bin/time so its peak RSS lands in $1. It
# execs, so when called with & the background PID is time's and the server
# is its only child.
timed() {
	local rss="$1"
	shift
	if [[ "$(uname)" == "Darwin" ]]; then
		exec /usr/bin/time -l -o "$rss" "$@"
	else
		exec /usr/bin/time -v -o "$rss" "$@"
	fi
}

peak_rss_mb() {
	if [[ "$(uname)" == "Darwin" ]]; then
		awk '/maximum resident set size/ {printf "%.0f", $1 / 1048576}' "$1"
	else
		awk -F: '/Maximum resident set size/ {printf "%.0f", $2 / 1024}' "$1"
	fi
}

wait_http() { # any HTTP answer means the listener is up
	for _ in $(seq 1 100); do
		[[ "$(curl -s -o /dev/null -w '%{http_code}' -XPOST -d '[]' "$1" || true)" != "000" ]] && return 0
		sleep 0.1
	done
	echo "no listener at $1" >&2
	return 1
}

{
	echo "# TREMOR vs Vector vs Fluent Bit ($stamp)"
	machine_specs
	echo "- vector: $(command -v vector >/dev/null && vector --version | head -1 || echo n/a)"
	echo "- fluent-bit: $(command -v fluent-bit >/dev/null && fluent-bit --version | head -1 || echo n/a)"
	echo "- offered $SAT_RATE ev/s for $DUR, batch $BATCH, $SERVICES services, $RUNS runs per tool"
} | tee "$OUT/compare-$stamp.md"

# Refuse to start if a listener is already up: load would go to the wrong process.
for u in "$INGEST_URL" "$VECTOR_URL" "$FLUENT_URL"; do
	if [[ "$(curl -s -o /dev/null -w '%{http_code}' -XPOST -d '[]' "$u" || true)" != "000" ]]; then
		echo "something is already listening at $u; stop it first" >&2
		exit 1
	fi
done

printf "run\ttool\taccepted_eps\tp99_ms\taccepted_events\ton_disk_events\tpeak_rss_mb\n" | tee "$tsv"
for ((i = 1; i <= RUNS; i++)); do
	for t in $TOOLS; do
		rm -rf "$COMPARE_DIR"/{wal,vector-data,vector-out.jsonl,fluent-bit-out.jsonl}
		mkdir -p "$COMPARE_DIR/vector-data"
		rss="$COMPARE_DIR/$t.rss"
		body=array url="$VECTOR_URL"
		case "$t" in
		tremor | tremor-noredact)
			body=events url="$INGEST_URL"
			red=true
			[[ "$t" == tremor-noredact ]] && red=false
			TREMOR_REDACT=$red TREMOR_WAL_DIR="$COMPARE_DIR/wal" GOMAXPROCS="$SERVER_PROCS" \
				timed "$rss" "$ROOT/bin/tremor" -config "$ROOT/config.example.yaml" 2>"$COMPARE_DIR/$t.log" &
			pid=$!
			for _ in $(seq 1 100); do curl -sf "$DEBUG_URL" >/dev/null 2>&1 && break; sleep 0.1; done
			curl -sf "$DEBUG_URL" >/dev/null || {
				echo "tremor did not start; see $COMPARE_DIR/$t.log" >&2
				exit 1
			}
			;;
		vector)
			timed "$rss" vector --quiet --threads "$SERVER_PROCS" --config "$COMPARE_DIR/vector.toml" \
				>"$COMPARE_DIR/$t.log" 2>&1 &
			pid=$!
			wait_http "$url"
			;;
		fluent-bit)
			url="$FLUENT_URL"
			timed "$rss" fluent-bit -c "$BENCH_DIR/compare/fluent-bit.conf" >"$COMPARE_DIR/$t.log" 2>&1 &
			pid=$!
			wait_http "$url"
			;;
		esac
		rm -f "$COMPARE_DIR"/{vector-out.jsonl,fluent-bit-out.jsonl} # drop readiness probes
		json="$COMPARE_DIR/$t-$i.json"
		GOMAXPROCS="$LOADGEN_PROCS" "$ROOT/bin/loadgen" -url "$url" -body "$body" -rate "$SAT_RATE" -duration "$DUR" \
			-batch "$BATCH" -services "$SERVICES" -concurrency 512 -pregen 1024 -progress 0 -out "$json" >/dev/null
		sleep "$SETTLE"
		# Graceful stop, so each tool flushes what it accepted. Signal the
		# server itself: /usr/bin/time does not forward signals, and killing
		# it would orphan the server on its port.
		pkill -TERM -P "$pid" || true
		wait "$pid" 2>/dev/null || true
		case "$t" in
		tremor*) disk=$(jq '.events_accepted' "$json") ;; # acked only after fsync to the WAL
		vector) disk=$(wc -l <"$COMPARE_DIR/vector-out.jsonl" 2>/dev/null || echo 0) ;;
		fluent-bit) disk=$(wc -l <"$COMPARE_DIR/fluent-bit-out.jsonl" 2>/dev/null || echo 0) ;;
		esac
		printf "%d\t%s\t%s\t%s\t%s\t%s\t%s\n" "$i" "$t" "$(jq '.accepted_eps|floor' "$json")" \
			"$(jq '.ok_latency_ms.p99|floor' "$json")" "$(jq '.events_accepted' "$json")" \
			"$(echo "$disk" | tr -d ' ')" "$(peak_rss_mb "$rss")" | tee -a "$tsv"
	done
done
rm -rf "$COMPARE_DIR"/{wal,vector-data,vector-out.jsonl,fluent-bit-out.jsonl}

awk -F'\t' 'NR > 1 {s[$2] += $3; n[$2]++; r[$2] = (r[$2] > $7 ? r[$2] : $7)}
	END {for (t in s) printf "%-16s mean accepted %8.0f ev/s, peak RSS %s MB\n", t, s[t] / n[t], r[t]}' "$tsv" |
	sort | tee -a "$OUT/compare-$stamp.md"
echo "results: $tsv"
