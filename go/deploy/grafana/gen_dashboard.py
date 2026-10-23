"""Generate the provisioned Grafana dashboard (deploy/grafana/dashboards/tremor.json).

    python3 deploy/grafana/gen_dashboard.py

Every panel's PromQL is here, so the dashboard is reviewed as code.
"""

import json
from pathlib import Path

DS = {"type": "prometheus", "uid": "prometheus"}
panels = []
y = 0
pid = 0


def nid():
    global pid
    pid += 1
    return pid


def row(title):
    global y
    panels.append({"type": "row", "title": title, "id": nid(), "collapsed": False,
                   "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []})
    y += 1


def targets(exprs):
    return [{"datasource": DS, "expr": e, "legendFormat": l, "refId": chr(65 + i)} for i, (e, l) in enumerate(exprs)]


def ts(title, exprs, x, w=8, h=8, unit="short", desc="", stack=False):
    panels.append({
        "type": "timeseries", "title": title, "description": desc, "id": nid(), "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": targets(exprs),
        "fieldConfig": {"defaults": {"unit": unit, "custom": {"lineWidth": 2, "fillOpacity": 10,
                                                                "stacking": {"mode": "normal" if stack else "none"}}},
                        "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
    })


def stat(title, expr, x, w=4, unit="short", desc="", thresholds=None):
    panels.append({
        "type": "stat", "title": title, "description": desc, "id": nid(), "datasource": DS,
        "gridPos": {"h": 4, "w": w, "x": x, "y": y},
        "targets": targets([(expr, "")]),
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 2 if unit in ("s", "percentunit") else 0,
                                     "thresholds": {"mode": "absolute", "steps": thresholds or [{"color": "green", "value": None}]}},
                        "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "area"},
    })


def nexty(h):
    global y
    y += h


# ── overview ──────────────────────────────────────────────────────────
row("Overview")
stat("Events accepted /s", "sum(rate(tremor_events_accepted_total[1m]))", 0)
stat("429 rejections /s", 'sum(rate(tremor_ingest_requests_total{result="rejected_429"}[1m]))', 4,
     thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}])
stat("WAL fsync p99", "histogram_quantile(0.99, sum by (le) (rate(tremor_wal_fsync_seconds_bucket[5m])))", 8, unit="s",
     thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 0.05}, {"color": "red", "value": 0.2}])
stat("Checkpoint lag (records)", "max(tremor_checkpoint_lag_records)", 12,
     thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 100000}])
stat("Open incidents", "max(tremor_incidents_open)", 16,
     thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
stat("PII redactions /s", "sum(rate(tremor_redactions_total[5m]))", 20)
nexty(4)

# ── ingest ────────────────────────────────────────────────────────────
row("Ingest and backpressure")
ts("Events per second", [
    ("sum(rate(tremor_events_accepted_total[1m]))", "accepted (fsynced, acked)"),
    ("sum(rate(tremor_events_processed_total[1m]))", "processed by shards"),
], 0, unit="short", desc="Accepted = acknowledged to producers after fsync. Processed = consumed by the shards.")
ts("Rejected requests per second", [
    ('sum by (result) (rate(tremor_ingest_requests_total{result!="accepted"}[1m]))', "{{result}}"),
], 8, desc="429 = queue full (producers retry with backoff); 503 = draining or WAL failure; bad_request = invalid input.")
ts("Ingest admission slots", [
    ("max(tremor_ingest_inflight_batches)", "in flight (decoding, queued, awaiting fsync)"),
    ('max(tremor_queue_depth{stage="ingest"})', "queued for the WAL"),
    ("max(tremor_ingest_capacity_batches)", "capacity"),
], 16, desc="When in-flight reaches capacity the gateway answers 429.")
nexty(8)
ts("Shard queue depth", [("max by (shard) (tremor_shard_queue_depth)", "shard {{shard}}")], 0, w=12,
   desc="Dispatch messages waiting per shard. A rising line is a shard falling behind (a hot service).")
ts("Events per second per shard", [("sum by (shard) (rate(tremor_shard_events_processed_total[1m]))", "shard {{shard}}")], 12, w=12, stack=True)
nexty(8)

# ── durability ────────────────────────────────────────────────────────
row("Durability (WAL)")
ts("WAL fsync latency", [
    ("histogram_quantile(0.5, sum by (le) (rate(tremor_wal_fsync_seconds_bucket[1m])))", "p50"),
    ("histogram_quantile(0.99, sum by (le) (rate(tremor_wal_fsync_seconds_bucket[1m])))", "p99"),
], 0, unit="s", desc="One fsync per group commit. Producers are acked only after it.")
ts("WAL write latency", [
    ("histogram_quantile(0.5, sum by (le) (rate(tremor_wal_write_seconds_bucket[1m])))", "p50"),
    ("histogram_quantile(0.99, sum by (le) (rate(tremor_wal_write_seconds_bucket[1m])))", "p99"),
], 8, unit="s", desc="Writing a group to the OS page cache, before the fsync.")
ts("Checkpoint lag and WAL throughput", [
    ("max(tremor_checkpoint_lag_records)", "records not yet checkpointed (replay size after a crash)"),
    ("sum(rate(tremor_wal_records_total[1m]))", "records appended /s"),
], 16)
nexty(8)

# ── privacy & detection ───────────────────────────────────────────────
row("Privacy and detection")
ts("PII redactions per second, by type", [("sum by (type) (rate(tremor_redactions_total[5m]))", "{{type}}")], 0, stack=True,
   desc="Counts only: values are never exported.")
ts("Alerts by type", [('sum by (type) (increase(tremor_alerts_total{severity!="RESOLVED"}[5m]))', "{{type}}")], 8, stack=True,
   desc="Alert notifications per 5 minutes (anomaly and security rules).")
ts("Alerts by severity", [('sum by (severity) (increase(tremor_alerts_total{severity!="RESOLVED"}[5m]))', "{{severity}}")], 16, stack=True)
nexty(8)
ts("Incidents", [('sum by (event) (increase(tremor_incidents_total[5m]))', "{{event}}"), ("max(tremor_incidents_open)", "open now")], 0, w=12,
   desc="opened = correlated groups of alerts; paged = reached the notification threshold (WARNING+).")
ts("Notifications delivered", [('sum by (sink, result) (increase(tremor_notifications_total[5m]))', "{{sink}} {{result}}")], 12, w=12)
nexty(8)

# ── LLM ──────────────────────────────────────────────────────────────
row("LLM incident summaries")
ts("LLM request latency", [
    ("histogram_quantile(0.5, sum by (le) (rate(tremor_llm_request_seconds_bucket[10m])))", "p50"),
    ("histogram_quantile(0.99, sum by (le) (rate(tremor_llm_request_seconds_bucket[10m])))", "p99"),
], 0, unit="s", desc="Off the paging path: incidents page immediately with a template summary; the LLM summary follows.")
ts("LLM tokens per minute", [('sum by (kind) (rate(tremor_llm_tokens_total[5m])) * 60', "{{kind}}")], 8, stack=True)
ts("LLM outcomes", [('sum by (result) (increase(tremor_llm_requests_total[10m]))', "{{result}}"),
                    ("sum(increase(tremor_summary_fallbacks_total[10m]))", "template fallback")], 16,
   desc="invalid_output = failed schema or citation validation; every fallback still sends a deterministic summary.")
nexty(8)

# ── process ──────────────────────────────────────────────────────────
row("Process")
ts("Memory", [("process_resident_memory_bytes", "RSS"), ("go_memstats_heap_inuse_bytes", "Go heap in use")], 0, unit="bytes")
ts("Goroutines", [("go_goroutines", "goroutines")], 8)
ts("CPU", [("rate(process_cpu_seconds_total[1m])", "cores used")], 16)
nexty(8)

dash = {
    "title": "TREMOR at Scale", "uid": "tremor", "version": 1, "schemaVersion": 39, "editable": False,
    "time": {"from": "now-30m", "to": "now"}, "refresh": "10s", "tags": ["tremor"], "timezone": "browser",
    "annotations": {"list": []}, "templating": {"list": []}, "panels": panels,
}
out = Path(__file__).parent / "dashboards" / "tremor.json"
out.write_text(json.dumps(dash, indent=1) + "\n")
print(f"{len([p for p in panels if p['type'] != 'row'])} panels -> {out}")
