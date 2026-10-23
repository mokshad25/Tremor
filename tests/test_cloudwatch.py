"""
TREMOR — CloudWatch sink tests (using moto mock).
"""

from __future__ import annotations

import asyncio
import json
import pytest
import boto3
from moto import mock_aws

from app.sinks.cloudwatch import CloudWatchSink
from app.sinks.base import DeliveryStatus


@pytest.fixture
def mock_event() -> dict:
    return {
        "id": "alert-001",
        "service": "payment-gateway",
        "signal_type": "ERROR_RATE",
        "status": "OPEN",
        "severity": "HIGH",
        "explanation": {"z_score": 4.2, "error_rate": 0.35},
        "created_at": 1704067200.0,
    }


@mock_aws
def test_cloudwatch_send_creates_group_and_puts_event(mock_event: dict) -> None:
    """Test that CW sink creates log group/stream and puts a log event."""
    sink = CloudWatchSink(
        log_group="/tremor/test",
        log_stream="test-stream",
        namespace="TremorTest",
        region="us-east-1",
    )

    status = asyncio.get_event_loop().run_until_complete(sink.send(mock_event))
    assert status == DeliveryStatus.DELIVERED

    # Verify via boto3 that the log group exists
    client = boto3.client("logs", region_name="us-east-1")
    groups = client.describe_log_groups(logGroupNamePrefix="/tremor/test")
    assert len(groups["logGroups"]) == 1

    # Verify log events were written
    events = client.get_log_events(
        logGroupName="/tremor/test",
        logStreamName="test-stream",
    )
    assert len(events["events"]) == 1

    # Parse the message back
    message = json.loads(events["events"][0]["message"])
    assert message["id"] == "alert-001"
    assert message["severity"] == "HIGH"


@mock_aws
def test_cloudwatch_puts_custom_metric(mock_event: dict) -> None:
    """Test that CW sink publishes a custom metric."""
    sink = CloudWatchSink(
        log_group="/tremor/metric-test",
        log_stream="test",
        namespace="TremorMetricTest",
        region="us-east-1",
    )

    asyncio.get_event_loop().run_until_complete(sink.send(mock_event))

    # Verify metric was published
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    metrics = cw.list_metrics(Namespace="TremorMetricTest")
    assert len(metrics["Metrics"]) >= 1
    assert metrics["Metrics"][0]["MetricName"] == "AlertCount"


@mock_aws
def test_cloudwatch_idempotent_group_creation(mock_event: dict) -> None:
    """Calling send twice should not fail on already-exists."""
    sink = CloudWatchSink(
        log_group="/tremor/idem-test",
        log_stream="test",
        region="us-east-1",
    )

    loop = asyncio.get_event_loop()
    loop.run_until_complete(sink.send(mock_event))
    loop.run_until_complete(sink.send(mock_event))

    client = boto3.client("logs", region_name="us-east-1")
    events = client.get_log_events(
        logGroupName="/tremor/idem-test",
        logStreamName="test",
    )
    assert len(events["events"]) == 2
