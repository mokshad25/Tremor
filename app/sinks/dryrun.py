"""
TREMOR — Dry-run sink (local log-only).

Responsibilities:
- Log what would be sent (to structlog) without making real AWS calls
- Mark delivery status as DRY_RUN
- Active when DRY_RUN=true
- Enables demo without AWS credentials or network

Owner: Sara (Phase 4)
"""

from __future__ import annotations

import structlog

from app.sinks.base import Sink, DeliveryStatus

log = structlog.get_logger()

class DryRunSink:
    """A sink that simply logs the alert to stdout (useful for local dev/testing)."""

    @property
    def name(self) -> str:
        return "dryrun"

    async def send(self, event: dict) -> DeliveryStatus:
        """Log the alert event."""
        log.info(
            "sink.dryrun.delivered",
            alert_id=event.get("id"),
            service=event.get("service"),
            severity=event.get("severity"),
            signal=event.get("signal_type")
        )
        return DeliveryStatus.DRY_RUN

    async def close(self) -> None:
        """Nothing to close for dryrun."""
        pass
