#!/usr/bin/env bash
# Live attack demo: a real server under normal loadgen traffic, with every
# attack type injected by `loadgen -attack all`. Checks that each attack's
# alert type shows up in the server's alert stream after the attack starts.
#
# The privilege rule needs its learning period to end before the attack, so
# this run sets detect.security.privilege_learn_s to 20 s (default: 24 h).
source "$(dirname "$0")/lib.sh"
RATE="${RATE:-2000}"
DUR="${DUR:-6m}"
stamp="$(date +%Y%m%d-%H%M%S)"
cfg="$OUT/live-attacks-$stamp.yaml"
sed 's/^detect:$/detect:\n  security:\n    privilege_learn_s: 20/' "$ROOT/config.example.yaml" > "$cfg"
grep -q "privilege_learn_s: 20" "$cfg" || { echo "could not patch config" >&2; exit 1; }
build
export TREMOR_WAL_DIR="$OUT/wal-live-attacks" TREMOR_HMAC_KEY="live-attack-demo-key-0123456789ab"
rm -rf "$TREMOR_WAL_DIR"
log="$OUT/live-attacks-$stamp-server.log"
GOMAXPROCS="$SERVER_PROCS" "$ROOT/bin/tremor" -config "$cfg" 2>"$log" &
SERVER_PID=$!
until curl -sf "$DEBUG_URL" >/dev/null; do sleep 0.2; done
loadgen -rate "$RATE" -duration "$DUR" -services 6 -attack all -attack-at 30s -attack-gap 90s \
	-progress 0 -out "$OUT/live-attacks-$stamp.json" >/dev/null
sleep 3
stop_server
rm -rf "$TREMOR_WAL_DIR"
echo "ground truth:"
jq -r '.attacks[] | "  \(.type)/\(.variant) at \(.start[11:19])"' "$OUT/live-attacks-$stamp.json"
echo "alerts (security types):"
grep '"msg":"alert"' "$log" | jq -r 'select(.type|test("BRUTE|STUFF|PRIV|UNUSUAL")) | "  \(.time[11:19]) \(.type) \(.severity) \(.mitre_attack|tostring) user=\(.user) source=\(.source): \(.reason)"'
fail=0
for t in BRUTE_FORCE CREDENTIAL_STUFFING PRIVILEGE_CHANGE UNUSUAL_ACCESS; do
	n=$(grep '"msg":"alert"' "$log" | jq -r "select(.type==\"$t\") | .type" | wc -l | tr -d ' ')
	echo "$t: $n alert(s)"
	[[ "$n" -ge 1 ]] || fail=1
done
leak=$(grep -cE 'meera\.nair|intern\.dev|ops\.admin' "$log" || true)
echo "raw usernames in server log: $leak"
[[ $fail -eq 0 && "$leak" -eq 0 ]] && echo PASS || { echo FAIL; exit 1; }
