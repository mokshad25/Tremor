"""
TREMOR — SinkWorker tests.
"""

from __future__ import annotations

import asyncio
import pytest

from app.sinks.base import SinkWorker, Sink, DeliveryStatus


class MockSink:
    def __init__(self, name: str, should_fail: bool = False):
        self._name = name
        self.should_fail = should_fail
        self.sent: list[dict] = []
        self.closed = False

    @property
    def name(self) -> str:
        return self._name

    async def send(self, event: dict) -> DeliveryStatus:
        if self.should_fail:
            raise Exception("Simulated failure")
        self.sent.append(event)
        return DeliveryStatus.DELIVERED

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_sink_worker_success() -> None:
    sink = MockSink("mock")
    worker = SinkWorker(sink)
    await worker.run()

    await worker.enqueue({"id": "123", "msg": "test"})
    # wait for loop to process
    await asyncio.sleep(0.1)

    assert len(sink.sent) == 1
    assert sink.sent[0]["id"] == "123"

    await worker.stop()
    assert sink.closed


@pytest.mark.asyncio
async def test_sink_worker_backoff() -> None:
    sink = MockSink("mock", should_fail=True)
    worker = SinkWorker(sink)
    
    # Speed up sleep in the test by patching asyncio.sleep? 
    # Or just wait a tiny bit to see it enqueue back.
    # We will just verify it requeues.
    await worker.run()

    await worker.enqueue({"id": "fail-test"})
    await asyncio.sleep(0.05)
    
    # It failed, so it should have re-queued the event
    assert worker.queue.qsize() == 1
    
    await worker.stop()
