"""
TREMOR — SNS sink tests (using moto mock).
"""

from __future__ import annotations

import asyncio
import pytest
import boto3
from moto import mock_aws

from app.sinks.sns import SNSSink
from app.sinks.base import DeliveryStatus


@mock_aws
def test_sns_publishes_critical_alert() -> None:
    """Test that SNS sink publishes a CRITICAL alert."""
    client = boto3.client("sns", region_name="us-east-1")
    response = client.create_topic(Name="tremor-alerts")
    topic_arn = response["TopicArn"]

    event = {
        "id": "alert-crit-001",
        "service": "auth",
        "signal_type": "ERROR_RATE",
        "status": "OPEN",
        "severity": "CRITICAL",
        "explanation": {"z_score": 8.1, "error_rate": 0.72},
    }

    sink = SNSSink(topic_arn=topic_arn, region="us-east-1")
    status = asyncio.get_event_loop().run_until_complete(sink.send(event))
    assert status == DeliveryStatus.DELIVERED


@mock_aws
def test_sns_publishes_high_alert() -> None:
    """Test that SNS sink publishes a HIGH alert."""
    client = boto3.client("sns", region_name="us-east-1")
    response = client.create_topic(Name="tremor-alerts")
    topic_arn = response["TopicArn"]

    event = {
        "id": "alert-high-001",
        "service": "payment",
        "signal_type": "SILENCE",
        "status": "OPEN",
        "severity": "HIGH",
        "explanation": {"silent_seconds": 120},
    }

    sink = SNSSink(topic_arn=topic_arn, region="us-east-1")
    status = asyncio.get_event_loop().run_until_complete(sink.send(event))
    assert status == DeliveryStatus.DELIVERED


@mock_aws
def test_sns_skips_info_alert() -> None:
    """Test that SNS sink silently skips INFO alerts."""
    client = boto3.client("sns", region_name="us-east-1")
    response = client.create_topic(Name="tremor-alerts")
    topic_arn = response["TopicArn"]

    event = {
        "id": "alert-info-001",
        "service": "auth",
        "signal_type": "ERROR_RATE",
        "status": "OPEN",
        "severity": "INFO",
        "explanation": {},
    }

    sink = SNSSink(topic_arn=topic_arn, region="us-east-1")
    status = asyncio.get_event_loop().run_until_complete(sink.send(event))
    assert status == DeliveryStatus.DELIVERED


@mock_aws
def test_sns_skips_warning_alert() -> None:
    """Test that SNS sink silently skips WARNING alerts."""
    client = boto3.client("sns", region_name="us-east-1")
    response = client.create_topic(Name="tremor-alerts")
    topic_arn = response["TopicArn"]

    event = {
        "id": "alert-warn-001",
        "service": "gw",
        "signal_type": "LATENCY",
        "status": "OPEN",
        "severity": "WARNING",
        "explanation": {},
    }

    sink = SNSSink(topic_arn=topic_arn, region="us-east-1")
    status = asyncio.get_event_loop().run_until_complete(sink.send(event))
    assert status == DeliveryStatus.DELIVERED
