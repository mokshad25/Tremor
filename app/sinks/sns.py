"""
TREMOR — SNS sink.

Responsibilities:
- Publish HIGH and CRITICAL alerts on open, escalation to CRITICAL, and resolution
- Set MessageAttributes: severity (String), service (String) for subscriber filtering
- Uses asyncio.to_thread for boto3 calls

Owner: Varad (Phase 4)
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import boto3
import structlog

from app.sinks.base import DeliveryStatus

log = structlog.get_logger()

# Only publish alerts at these severity levels
PUBLISHABLE_SEVERITIES = {"HIGH", "CRITICAL"}


class SNSSink:
    """
    Publishes alert events to an SNS topic for push notifications.
    Filters by severity — only HIGH and CRITICAL alerts are published.
    Uses MessageAttributes for subscriber-side filtering.
    """

    def __init__(
        self,
        topic_arn: str,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
    ) -> None:
        self._topic_arn = topic_arn
        self._region = region
        self._endpoint_url = endpoint_url or None
        self._client = None

    @property
    def name(self) -> str:
        return "sns"

    def _get_client(self) -> None:
        kwargs: dict = {"region_name": self._region}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        self._client = boto3.client("sns", **kwargs)

    def _sync_publish(self, event: dict) -> None:
        """Blocking SNS publish call."""
        if self._client is None:
            self._get_client()

        assert self._client is not None

        severity = event.get("severity", "INFO")
        service = event.get("service", "unknown")
        alert_id = event.get("id", "unknown")
        signal_type = event.get("signal_type", "UNKNOWN")
        status = event.get("status", "UNKNOWN")

        subject = f"[TREMOR][{severity}] {service} — {signal_type}"
        # SNS subject is capped at 100 chars
        subject = subject[:100]

        # Extract relevant detection fields for the email details
        details = {
            k: v for k, v in event.items() 
            if k in {"value", "baseline", "z_score", "lines", "errors", "reason", "template_id"} 
            and v is not None
        }

        message_body = {
            "default": json.dumps(event, default=str),
            "email": (
                f"TREMOR Alert: {severity}\n"
                f"Service: {service}\n"
                f"Signal: {signal_type}\n"
                f"Status: {status}\n"
                f"Alert ID: {alert_id}\n\n"
                f"Details:\n{json.dumps(details, indent=2, default=str)}"
            ),
        }

        self._client.publish(
            TopicArn=self._topic_arn,
            Subject=subject,
            Message=json.dumps(message_body, default=str),
            MessageStructure="json",
            MessageAttributes={
                "severity": {
                    "DataType": "String",
                    "StringValue": severity,
                },
                "service": {
                    "DataType": "String",
                    "StringValue": service,
                },
                "signal_type": {
                    "DataType": "String",
                    "StringValue": signal_type,
                },
            },
        )

    async def send(self, event: dict) -> DeliveryStatus:
        """
        Publish to SNS if severity is HIGH or CRITICAL.
        Lower severities are silently skipped (returned as DELIVERED).
        """
        severity = event.get("severity", "INFO")

        if severity not in PUBLISHABLE_SEVERITIES:
            # Skip non-critical alerts silently
            return DeliveryStatus.DELIVERED

        try:
            await asyncio.to_thread(self._sync_publish, event)
            await log.ainfo(
                "sink.sns.published",
                alert_id=event.get("id"),
                severity=severity,
            )
            return DeliveryStatus.DELIVERED
        except Exception as e:
            await log.aerror(
                "sink.sns.publish_error",
                error=str(e),
                alert_id=event.get("id"),
            )
            raise  # Let SinkWorker handle retry/backoff

    async def close(self) -> None:
        """Nothing to explicitly close for boto3."""
        await log.ainfo("sink.sns.closed")
