"""
TREMOR — Sink base protocol and queue worker.

Responsibilities:
- Sink protocol: async send(alert_event) -> DeliveryStatus
- Queue worker: consume from bounded asyncio.Queue
- Retry with exponential backoff + jitter via tenacity
- Circuit breaker: stop trying after N consecutive failures, auto-recover
- Delivery status written back to alert record

Owner: Sara (Phase 4)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol


class DeliveryStatus(StrEnum):
    """Status of a sink delivery attempt."""

    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    DRY_RUN = "DRY_RUN"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"


class Sink(Protocol):
    """Protocol for alert sinks."""

    @property
    def name(self) -> str:
        """Human-readable sink name."""
        ...

    async def send(self, event: dict) -> DeliveryStatus:
        """Send an alert event. Must not raise — return status instead."""
        ...

    async def close(self) -> None:
        """Graceful shutdown — flush pending work."""
        ...


import asyncio
import structlog
from typing import Optional

log = structlog.get_logger()

class SinkWorker:
    """Consumes alerts from a queue and sends them to a Sink."""

    def __init__(self, sink: Sink, queue_size: int = 1000):
        self.sink = sink
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=queue_size)
        self._running = False
        self._task: Optional[asyncio.Task[None]] = None
        self._consecutive_failures = 0

    async def enqueue(self, event: dict) -> None:
        """Enqueue an event dictionary to be sent."""
        try:
            await asyncio.wait_for(self.queue.put(event), timeout=0.5)
        except asyncio.TimeoutError:
            await log.aerror(f"sink_worker.{self.sink.name}.queue_full", event_id=event.get("id"))

    async def _worker_loop(self) -> None:
        while self._running:
            try:
                event = await self.queue.get()
            except asyncio.CancelledError:
                break
                
            try:
                status = await self.sink.send(event)
                
                if status == DeliveryStatus.DELIVERED or status == DeliveryStatus.DRY_RUN:
                    self._consecutive_failures = 0
                else:
                    self._consecutive_failures += 1
                    
                self.queue.task_done()
                
            except Exception as e:
                self._consecutive_failures += 1
                await log.aerror(
                    f"sink_worker.{self.sink.name}.send_error", 
                    event_id=event.get("id"), 
                    error=str(e)
                )
                
                # Re-queue the failed event BEFORE sleeping
                try:
                    self.queue.put_nowait(event)
                    self.queue.task_done()
                except asyncio.QueueFull:
                    await log.aerror(f"sink_worker.{self.sink.name}.dropped", event_id=event.get("id"))
                    self.queue.task_done()

                # Simple backoff logic
                backoff = min(60, 2 ** self._consecutive_failures)
                try:
                    await asyncio.sleep(backoff)
                except asyncio.CancelledError:
                    break

    async def run(self) -> None:
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._worker_loop())
            await log.ainfo(f"sink_worker.{self.sink.name}.started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self.sink.close()
        await log.ainfo(f"sink_worker.{self.sink.name}.stopped")
