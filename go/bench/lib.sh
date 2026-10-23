# Shared helpers for bench scripts. Source, don't execute.
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$BENCH_DIR/.." && pwd)"
OUT="$BENCH_DIR/out"
mkdir -p "$OUT"

SERVER_PROCS="${SERVER_PROCS:-4}"   # GOMAXPROCS for tremor (plan target: 4 cores)
LOADGEN_PROCS="${LOADGEN_PROCS:-4}" # GOMAXPROCS for loadgen (same machine)
DEBUG_URL="${DEBUG_URL:-http://127.0.0.1:6060/debug/vars}"
INGEST_URL="${INGEST_URL:-http://127.0.0.1:8080/ingest}"

build() {
	(cd "$ROOT" && go build -o bin/tremor ./cmd/tremor && go build -o bin/loadgen ./cmd/loadgen)
}

machine_specs() {
	if [[ "$(uname)" == "Darwin" ]]; then
		echo "- CPU: $(sysctl -n machdep.cpu.brand_string) ($(sysctl -n hw.ncpu) cores: $(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null || echo ?) performance + $(sysctl -n hw.perflevel1.physicalcpu 2>/dev/null || echo ?) efficiency)"
		echo "- RAM: $(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024)) GiB"
		echo "- OS: macOS $(sw_vers -productVersion)"
	else
		echo "- CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) ($(nproc) cores)"
		echo "- RAM: $(awk '/MemTotal/ {printf "%d GiB", $2/1024/1024}' /proc/meminfo)"
		echo "- OS: $(uname -sr)"
	fi
	echo "- Go: $(go version | awk '{print $3}')"
	echo "- tremor GOMAXPROCS=$SERVER_PROCS, loadgen GOMAXPROCS=$LOADGEN_PROCS (same machine)"
}

SERVER_PID=""
start_server() {
	local log="$1"
	GOMAXPROCS="$SERVER_PROCS" "$ROOT/bin/tremor" -config "$ROOT/config.example.yaml" 2>"$log" &
	SERVER_PID=$!
	for _ in $(seq 1 50); do
		curl -sf "$DEBUG_URL" >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	echo "server did not start; see $log" >&2
	return 1
}

stop_server() {
	if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill -TERM "$SERVER_PID"
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	SERVER_PID=""
}
trap stop_server EXIT

loadgen() {
	GOMAXPROCS="$LOADGEN_PROCS" "$ROOT/bin/loadgen" -url "$INGEST_URL" "$@"
}
