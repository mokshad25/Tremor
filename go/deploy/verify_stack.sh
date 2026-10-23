#!/usr/bin/env bash
# Verify a running `docker compose up` stack: Prometheus scrapes TREMOR,
# every Grafana panel query returns data, Grafana serves the provisioned
# dashboard, and incidents were summarized.
#
# Env: PROM (http://localhost:9090) GRAFANA (http://localhost:3000)
set -uo pipefail
cd "$(dirname "$0")"
PROM="${PROM:-http://localhost:9090}"
GRAFANA="${GRAFANA:-http://localhost:3000}"
fail=0

echo "== Prometheus targets"
curl -sf "$PROM/api/v1/targets" | jq -r '.data.activeTargets[] | "  \(.labels.job): \(.health)"'

echo "== Dashboard panels (each query evaluated in Prometheus)"
# Unit-separator delimited: an empty legend must not shift the fields.
jq -r '.panels[] | select(.type != "row") | .title as $t | .targets[] | [$t, .legendFormat, .expr] | join("\u001f")' grafana/dashboards/tremor.json |
while IFS=$'\x1f' read -r title legend expr; do
	n=$(curl -sf --get "$PROM/api/v1/query" --data-urlencode "query=$expr" | jq '.data.result | length')
	v=$(curl -sf --get "$PROM/api/v1/query" --data-urlencode "query=$expr" | jq -r '[.data.result[] | .value[1] | tonumber] | add // "none"')
	status=OK
	[[ "$n" -gt 0 ]] || status=EMPTY
	printf "  %-5s %-40s %-45s series=%s sum=%s\n" "$status" "${title:0:40}" "${legend:0:45}" "$n" "$v"
done

echo "== Grafana"
curl -sf "$GRAFANA/api/health" | jq -c .
curl -sf "$GRAFANA/api/dashboards/uid/tremor" | jq -r '"  dashboard: \(.dashboard.title), \(.dashboard.panels | map(select(.type != "row")) | length) panels, folder \(.meta.folderTitle)"' || { echo "  dashboard NOT found"; fail=1; }

echo "== Incidents and summaries (from TREMOR's log)"
docker compose logs tremor 2>/dev/null | grep '"msg":"incident"' | sed 's/^[^{]*//' |
	jq -r '"  \(.time[11:19]) \(.kind) \(.severity) \(.services|join(",")) [\(.summary_source)\(if .fallback_reason != "" then " " + .fallback_reason else "" end)] \(.summary[0:140])"' | tail -25
exit $fail
