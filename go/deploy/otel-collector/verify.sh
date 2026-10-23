#!/usr/bin/env bash
# End-to-end check: an OpenTelemetry Collector (config only) delivers logs
# to TREMOR over OTLP/HTTP and OTLP/gRPC. For each exporter it:
#   1. starts TREMOR with a fresh WAL,
#   2. has the collector tail N generated log lines (with PII),
#   3. waits until TREMOR has acknowledged all N events,
#   4. checks that no raw email, card number, IP or key from the input
#      file appears anywhere in TREMOR's WAL.
# With OVERLOAD=1, TREMOR gets a single admission slot, so it rejects most
# requests (HTTP 429 / gRPC RESOURCE_EXHAUSTED + RetryInfo): the run then
# also proves the collector backs off and retries until everything lands.
#
# Env: N (20000) OVERLOAD (0)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
ROOT="$(cd ../.. && pwd)"
N="${N:-20000}"
WORK="$(mktemp -d)"
trap 'docker compose down -t 2 >/dev/null 2>&1 || true; [[ -n "${PID:-}" ]] && kill -TERM "$PID" 2>/dev/null; rm -rf "$WORK"' EXIT

(cd "$ROOT" && go build -o bin/tremor ./cmd/tremor && go build -o bin/loadgen ./cmd/loadgen)
mkdir -p "$WORK/logs"
"$ROOT/bin/loadgen" -to-file "$WORK/logs/app.jsonl" -count "$N" -services 6 -rate 5000
# Raw values that must never reach TREMOR's disk.
PII_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}|4111111111111111|5555 5555 5555 4444|10\.[0-9]+\.[0-9]+\.[0-9]+|sk_test_[A-Za-z0-9]+'
grep -aohE "$PII_RE" "$WORK/logs/app.jsonl" | sort -u > "$WORK/raw-pii.txt"
echo "input: $N lines, $(wc -l < "$WORK/raw-pii.txt" | tr -d ' ') distinct raw PII values"

for exporter in otlphttp/tremor otlp/tremor; do
	rm -rf "$WORK/wal"
	qcap=256
	[[ "${OVERLOAD:-0}" == 1 ]] && qcap=1
	TREMOR_QUEUE_CAPACITY=$qcap TREMOR_WAL_DIR="$WORK/wal" TREMOR_HMAC_KEY="${TREMOR_HMAC_KEY:-$(openssl rand -hex 32)}" \
		"$ROOT/bin/tremor" -config "$ROOT/config.example.yaml" 2>"$WORK/tremor.log" &
	PID=$!
	until curl -sf http://127.0.0.1:6060/debug/vars >/dev/null; do sleep 0.2; done

	start=$(date +%s)
	LOG_DIR="$WORK/logs" TREMOR_EXPORTER="$exporter" docker compose up -d --quiet-pull >/dev/null 2>&1
	got=0
	for _ in $(seq 1 600); do
		got=$(curl -sf http://127.0.0.1:6060/debug/vars | jq '.tremor.events_accepted_total')
		[[ "$got" -ge "$N" ]] && break
		sleep 0.5
	done
	took=$(( $(date +%s) - start ))
	vars=$(curl -sf http://127.0.0.1:6060/debug/vars | jq -c '.tremor | {events_accepted_total, requests_total, requests_429_total, requests_503_total, redactions_email_total, redactions_card_total, redactions_ip_total, redactions_api_key_total, redactions_username_total}')
	docker compose down -t 2 >/dev/null 2>&1
	kill -TERM "$PID"; wait "$PID" 2>/dev/null || true; PID=""

	# Linear leak check: pull every PII-shaped string out of the WAL with the
	# same pattern, and intersect with the raw values from the input.
	# (grep -F with thousands of patterns is pathologically slow on macOS.)
	(grep -aohE "$PII_RE" "$WORK"/wal/*.wal || true) | sort -u > "$WORK/wal-pii.txt"
	leaks=$(comm -12 "$WORK/raw-pii.txt" "$WORK/wal-pii.txt" | wc -l | tr -d ' ')
	status=PASS
	[[ "$got" -eq "$N" && "$leaks" -eq 0 ]] || status=FAIL
	echo "$exporter: delivered $got/$N events in ${took}s; raw PII values found in the WAL: $leaks -> $status"
	echo "  $vars"
	[[ "$status" == PASS ]] || { tail -5 "$WORK/tremor.log"; exit 1; }
done
