"""
TREMOR — CloudWatch Logs sink.

Responsibilities:
- put_log_events with structured JSON for every alert lifecycle event
- Create log group and stream on startup if missing
- No sequence token needed (modern API)
- Also publishes ErrorRate custom metric via put_metric_data

Owner: Varad (Phase 4)
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

import boto3
import structlog

from app.sinks.base import DeliveryStatus

log = structlog.get_logger()


class CloudWatchSink:
    """
    Sends alert events as structured JSON to CloudWatch Logs,
    and publishes custom metrics to CloudWatch Metrics.
    Uses asyncio.to_thread() for blocking boto3 calls.
    """

    def __init__(
        self,
        log_group: str = "/tremor/alerts",
        log_stream: str = "default",
        namespace: str = "Tremor",
        region: str = "us-east-1",
        endpoint_url: str | None = None,
    ) -> None:
        self._log_group = log_group
        self._log_stream = log_stream
        self._namespace = namespace
        self._region = region
        self._endpoint_url = endpoint_url or None

        # Lazy-init clients
        self._logs_client = None
        self._cw_client = None
        self._initialized = False

    @property
    def name(self) -> str:
        return "cloudwatch"

    def _get_clients(self) -> None:
        """Create boto3 clients (must be called from thread)."""
        kwargs: dict = {"region_name": self._region}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url

        self._logs_client = boto3.client("logs", **kwargs)
        self._cw_client = boto3.client("cloudwatch", **kwargs)

    def _ensure_log_group(self) -> None:
        """Create the CloudWatch log group and stream if they don't exist."""
        if self._initialized:
            return

        assert self._logs_client is not None

        try:
            self._logs_client.create_log_group(logGroupName=self._log_group)
        except self._logs_client.exceptions.ResourceAlreadyExistsException:
            pass

        try:
            self._logs_client.create_log_stream(
                logGroupName=self._log_group,
                logStreamName=self._log_stream,
            )
        except self._logs_client.exceptions.ResourceAlreadyExistsException:
            pass

        self._initialized = True

    def _put_log_event(self, event: dict) -> None:
        """Blocking call to put_log_events."""
        assert self._logs_client is not None

        self._logs_client.put_log_events(
            logGroupName=self._log_group,
            logStreamName=self._log_stream,
            logEvents=[
                {
                    "timestamp": int(time.time() * 1000),
                    "message": json.dumps(event, default=str),
                }
            ],
        )

    def _put_metric(self, event: dict) -> None:
        """Publish a custom metric for the alert severity."""
        assert self._cw_client is not None

        severity = event.get("severity", "INFO")
        service = event.get("service", "unknown")

        self._cw_client.put_metric_data(
            Namespace=self._namespace,
            MetricData=[
                {
                    "MetricName": "AlertCount",
                    "Dimensions": [
                        {"Name": "Service", "Value": service},
                        {"Name": "Severity", "Value": severity},
                    ],
                    "Value": 1,
                    "Unit": "Count",
                }
            ],
        )

    def _sync_send(self, event: dict) -> None:
        """All blocking boto3 calls in one sync method (run in thread)."""
        if self._logs_client is None:
            self._get_clients()
        self._ensure_log_group()
        self._put_log_event(event)
        self._put_metric(event)

    async def send(self, event: dict) -> DeliveryStatus:
        """Send alert event to CloudWatch (async wrapper over boto3)."""
        try:
            await asyncio.to_thread(self._sync_send, event)
            return DeliveryStatus.DELIVERED
        except Exception as e:
            await log.aerror(
                "sink.cloudwatch.send_error",
                error=str(e),
                alert_id=event.get("id"),
            )
            raise  # Let SinkWorker handle retry/backoff

    async def close(self) -> None:
        """Nothing to explicitly close for boto3."""
        await log.ainfo("sink.cloudwatch.closed")
