"""
TREMOR — Shared test fixtures.
"""

from __future__ import annotations

import pytest

from app.clock import FakeClock


@pytest.fixture
def fake_clock() -> FakeClock:
    """Provide a FakeClock starting at Unix epoch 1_000_000."""
    return FakeClock(start=1_000_000.0)
