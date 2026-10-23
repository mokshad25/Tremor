# UI contract the Go server must keep

The existing React dashboard (`TREMOR/frontend/`) must keep working **with zero
frontend changes** once the Go pipeline replaces the Python backend. This file
records exactly what the UI depends on, taken from the Python source, so the
Go implementation (Phase 3/6) can reproduce it byte-for-byte.

Phase 1 does not serve any of this yet. The Go gateway runs on `:8080` and
leaves `:8000` to the Python app.

## What the UI actually uses

The only backend dependency is a single WebSocket:

```
ws://localhost:8000/ws/alerts          (hard-coded, frontend/src/Dashboard.tsx:105)
```

The UI makes no REST calls. Ack and Silence only change local state.

## Envelope (`app/sinks/ws.py`)

```json
{"type": "snapshot" | "alert" | "metric" | "heartbeat", "ts": <unix float seconds>, "data": {...}}
```

| type | sent when | `data` |
|---|---|---|
| `snapshot` | on connect | `{"alerts": [<last ≤50 alert dicts>], "tick": <last tick or null>}` |
| `metric` | every second, per service | Tick (below) |
| `alert` | an alert is opened or escalated | Alert (below) |
| `heartbeat` | every 15 s | no `data` key |

Behaviour to keep: slow clients are dropped after a 2 s send timeout, and a ring buffer holds the last 50 alerts for snapshots.

## Tick (`app/core/engine.py` `Tick.to_dict`)

```json
{"ts": "<UTC ISO 8601 string>", "error_rate": 0.0-1.0 | null, "baseline": float | null,
 "z": float | null, "lines": int, "state": "learning"|"insufficient"|"active"|"incident",
 "severity": "INFO"|"WARNING"|"HIGH"|"CRITICAL"|null, "is_anomaly": bool}
```

## Alert (`app/core/alerts.py` `Alert.to_dict`)

```json
{"id": str, "service": str, "signal_type": "ERROR_RATE"|"SILENCE"|"NEW_PATTERN"|"LATENCY",
 "status": "OPEN"|"ESCALATED"|"ACKED"|"SILENCED"|"RESOLVED", "severity": str,
 "explanation": str, "created_at": <unix float>, "updated_at": <unix float>,
 "incident_id": str, "value": float, "baseline": float, "z_score": float,
 "lines": int, "errors": int, "reason": str, "template_id": str | null}
```

The UI reads these fields from the alert: `id, incident_id, severity, signal_type, value, baseline, z_score, reason, status, created_at`. It upserts alerts by `id` and keeps 10. `status == "OPEN"` sets the incident banner and `"RESOLVED"` clears it. `severity.toLowerCase()` becomes a CSS class.

New Go-only fields (ATT&CK ID, source sequence numbers, LLM summary) are **added** to the dict. Existing keys are never renamed or retyped, so the UI ignores the extras.

## Existing quirks, kept on purpose

Changing any of these would change what the UI shows, so the Go server reproduces them as they are. They're listed here so they can be fixed together with the UI later, as a deliberate change.

- `tick.ts` is an ISO string, but the UI does `new Date(tick.ts * 1000)`, so chart labels show "Invalid Date".
- The UI's `Severity` type is `LOW|MEDIUM|HIGH|CRITICAL`, but the backend emits `INFO|WARNING|HIGH|CRITICAL`.
- `error_rate` is a 0–1 fraction, but the UI labels it "%" without multiplying.
- Ticks carry no `service` field, so the single chart interleaves all services.
- `created_at` is a unix float over the WebSocket but ISO in the REST API.
