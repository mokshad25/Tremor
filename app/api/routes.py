"""
TREMOR — API routes.

Endpoints:
- WS  /ws/alerts              Live alert feed + metrics
- GET  /api/alerts             Alert history (filterable)
- GET  /api/alerts/{id}        Alert detail with timeline
- POST /api/alerts/{id}/ack    Acknowledge alert
- POST /api/alerts/{id}/silence  Silence alert for a duration
- GET  /api/metrics/current    Current window metrics per service
- GET  /api/baseline           Baseline state per service/slot
- GET  /api/templates          Top templates and rarity
- POST /api/sim/inject         Demo-only scenario injection
- GET  /health                 Component health status

Owner: Varad (pipeline integration)
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect

from app.sinks.ws import ws_manager

router = APIRouter()


# ── Health ────────────────────────────────────────────────────────────

@router.get("/health", tags=["ops"])
async def health(request: Request) -> dict:
    """Component health check."""
    engines = getattr(request.app.state, "engines", {})
    tailers = getattr(request.app.state, "tailers", [])
    sink_workers = getattr(request.app.state, "sink_workers", [])

    return {
        "status": "healthy",
        "version": "0.1.0",
        "components": {
            "tailer": f"running ({len(tailers)} files)",
            "detector": f"active ({len(engines)} services)",
            "sinks": f"running ({len(sink_workers)} workers)",
            "database": "connected",
            "websocket": f"connected ({len(ws_manager._connections)} clients)",
        },
    }


# ── WebSocket ─────────────────────────────────────────────────────────

@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket) -> None:
    """Live alert feed via WebSocket."""
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep the connection alive by reading (client can send acks)
            data = await ws.receive_text()
            # Future: handle client commands (ack, silence via WS)
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)


# ── Alert endpoints ──────────────────────────────────────────────────

@router.get("/api/alerts", tags=["alerts"])
async def list_alerts(
    request: Request,
    service: str | None = Query(None),
    signal_type: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict:
    """List alerts with optional filters."""
    repo = request.app.state.alert_repo
    alerts = await repo.list_alerts(
        service=service,
        signal_type=signal_type,
        status=status,
        limit=limit,
        offset=offset,
    )
    total = await repo.count(service=service, signal_type=signal_type, status=status)
    return {
        "alerts": [_record_to_dict(a) for a in alerts],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/api/alerts/{alert_id}", tags=["alerts"])
async def get_alert(request: Request, alert_id: str) -> dict:
    """Get alert detail with timeline and explanation."""
    repo = request.app.state.alert_repo
    record = await repo.get(alert_id)
    if record is None:
        return {"error": "not_found"}
    return _record_to_dict(record)


@router.post("/api/alerts/{alert_id}/ack", tags=["alerts"])
async def ack_alert(request: Request, alert_id: str) -> dict:
    """Acknowledge an alert."""
    engines: dict = request.app.state.engines
    now = time.time()
    # Find the incident across all engines
    for engine in engines.values():
        try:
            alert = engine.ack(alert_id, now)
            repo = request.app.state.alert_repo
            await repo.save(alert)
            return alert.to_dict()
        except KeyError:
            continue
    return {"error": "not_found", "detail": "No open incident with that ID"}


@router.post("/api/alerts/{alert_id}/silence", tags=["alerts"])
async def silence_alert(
    request: Request,
    alert_id: str,
    duration_s: int = Query(3600, ge=60, le=86400),
) -> dict:
    """Silence an alert for a specified duration."""
    engines: dict = request.app.state.engines
    now = time.time()
    until = now + duration_s
    for engine in engines.values():
        try:
            alert = engine.silence(alert_id, until, now)
            repo = request.app.state.alert_repo
            await repo.save(alert)
            return alert.to_dict()
        except KeyError:
            continue
    return {"error": "not_found", "detail": "No open incident with that ID"}


# ── Metrics / State endpoints ────────────────────────────────────────

@router.get("/api/metrics/current", tags=["metrics"])
async def current_metrics(request: Request) -> dict:
    """Current window metrics per service (polling fallback)."""
    engines: dict = getattr(request.app.state, "engines", {})
    services = {}
    for svc, engine in engines.items():
        services[svc] = {
            "warmed_up": engine.warmed_up,
            "baselines": {
                k: {"mu": v.mu, "sigma": v.sigma, "seeded": v.seeded}
                for k, v in engine.baselines.states().items()
            },
        }
    return {"services": services}


@router.get("/api/baseline", tags=["metrics"])
async def baseline_state(request: Request) -> dict:
    """Baseline state per service/slot."""
    engines: dict = getattr(request.app.state, "engines", {})
    baselines = {}
    for svc, engine in engines.items():
        states = engine.baselines.states()
        baselines[svc] = {
            f"{k[0]}:{k[1]}": {
                "mu": v.mu,
                "sigma": v.sigma,
                "seeded": v.seeded,
                "warmup_count": v.warmup_count,
            }
            for k, v in states.items()
        }
    return {"baselines": baselines}


@router.get("/api/templates", tags=["metrics"])
async def templates(request: Request) -> dict:
    """Top templates and rarity."""
    miner = getattr(request.app.state, "miner", None)
    if miner is None:
        return {"templates": []}

    infos = miner.top(limit=50)
    return {
        "templates": [
            {
                "id": t.id,
                "template": t.template,
                "count": t.count,
                "rarity": t.rarity,
                "sample": t.sample,
            }
            for t in infos
        ]
    }


# ── Demo endpoint ────────────────────────────────────────────────────

@router.post("/api/sim/inject", tags=["demo"])
async def inject_scenario(request: Request) -> dict:
    """Inject a scenario (demo mode only)."""
    from app.config import settings
    if not settings.demo_mode:
        return {"error": "demo_mode_disabled"}
    # Future: integrate with simulator
    return {"status": "scenario_injected"}


# ── Active alerts (live, from engine memory) ─────────────────────────

@router.get("/api/alerts/active", tags=["alerts"])
async def active_alerts(request: Request) -> dict:
    """Get currently active (open) alerts from engine memory."""
    engines: dict = getattr(request.app.state, "engines", {})
    now = time.time()
    active = []
    for engine in engines.values():
        active.extend(a.to_dict() for a in engine.active(now))
    return {"alerts": active, "total": len(active)}


# ── Helpers ──────────────────────────────────────────────────────────

def _record_to_dict(record) -> dict:
    """Convert an AlertRecord ORM object to a JSON-serializable dict."""
    return {
        "id": record.id,
        "incident_id": record.incident_id,
        "service": record.service,
        "signal_type": record.signal_type,
        "status": record.status,
        "severity": record.severity,
        "reason": record.reason,
        "value": record.value,
        "baseline": record.baseline,
        "z_score": record.z_score,
        "lines": record.lines,
        "errors": record.errors,
        "template_id": record.template_id,
        "explanation": record.explanation,
        "timeline": record.timeline,
        "samples": record.samples,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }
