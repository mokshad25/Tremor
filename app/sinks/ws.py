"""
TREMOR — WebSocket connection manager.

Responsibilities:
- Broadcast to all connected clients
- Drop slow consumers rather than blocking
- Server heartbeat every 15s
- On connect: snapshot of last 50 alerts + current state
- Message envelope: { "type": "snapshot|metric|alert|alert_update", "ts": ..., "data": {...} }

Owner: Varad (pipeline integration)
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from typing import Any

import structlog
from fastapi import WebSocket, WebSocketDisconnect

log = structlog.get_logger()

# Maximum alerts kept in the ring buffer for new-connection snapshots.
SNAPSHOT_SIZE = 50
# Heartbeat interval in seconds.
HEARTBEAT_INTERVAL = 15.0
# Per-client send timeout — drop slow consumers.
SEND_TIMEOUT = 2.0


class ConnectionManager:
    """Manages WebSocket connections and broadcasts."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._alert_history: deque[dict[str, Any]] = deque(maxlen=SNAPSHOT_SIZE)
        self._last_tick: dict[str, Any] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the heartbeat loop."""
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        await log.ainfo("ws.manager.started")

    async def stop(self) -> None:
        """Stop the heartbeat loop and close all connections."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        for ws in list(self._connections):
            try:
                await ws.close()
            except Exception:
                pass
        self._connections.clear()
        await log.ainfo("ws.manager.stopped")

    async def connect(self, ws: WebSocket) -> None:
        """Accept a new WebSocket connection and send the snapshot."""
        await ws.accept()
        self._connections.add(ws)
        await log.ainfo("ws.client.connected", total=len(self._connections))

        # Send snapshot of recent alerts
        snapshot = {
            "type": "snapshot",
            "ts": time.time(),
            "data": {
                "alerts": list(self._alert_history),
                "tick": self._last_tick,
            },
        }
        try:
            await asyncio.wait_for(ws.send_json(snapshot), timeout=SEND_TIMEOUT)
        except Exception:
            pass

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a disconnected client."""
        self._connections.discard(ws)

    async def broadcast_alert(self, alert_dict: dict[str, Any]) -> None:
        """Broadcast an alert to all connected clients and save to history."""
        self._alert_history.append(alert_dict)
        envelope = {"type": "alert", "ts": time.time(), "data": alert_dict}
        await self._broadcast(envelope)

    async def broadcast_tick(self, tick_dict: dict[str, Any]) -> None:
        """Broadcast a tick (metric update) to all connected clients."""
        self._last_tick = tick_dict
        envelope = {"type": "metric", "ts": time.time(), "data": tick_dict}
        await self._broadcast(envelope)

    async def _broadcast(self, message: dict[str, Any]) -> None:
        """Send a message to every connected client. Drop slow consumers."""
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await asyncio.wait_for(ws.send_json(message), timeout=SEND_TIMEOUT)
            except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
                dead.append(ws)

        for ws in dead:
            self._connections.discard(ws)
            try:
                await ws.close()
            except Exception:
                pass

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to keep connections alive."""
        while True:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                heartbeat = {"type": "heartbeat", "ts": time.time()}
                await self._broadcast(heartbeat)
            except asyncio.CancelledError:
                break
            except Exception as e:
                await log.aerror("ws.heartbeat.error", error=str(e))


# Singleton instance
ws_manager = ConnectionManager()
