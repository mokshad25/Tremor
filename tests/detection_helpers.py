"""
TREMOR — Helpers shared by the detection tests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.config import Settings
from app.core.arrivals import ArrivalWindow
from app.core.detectors.base import Observation, TickContext

if TYPE_CHECKING:
    from app.core.alerts import SignalType


def make_settings(**overrides: Any) -> Settings:
    """Settings from code defaults only, so a developer's .env cannot change test results."""
    return Settings(_env_file=None, **overrides)


def obs(arrival: float, level: str = "INFO", **kwargs: Any) -> Observation:
    return Observation(arrival=arrival, level=level, **kwargs)


def ctx(
    now: float,
    *,
    warmed_up: bool = True,
    window: ArrivalWindow | None = None,
    open_keys: frozenset[tuple[SignalType, str | None]] = frozenset(),
) -> TickContext:
    return TickContext(
        now=now,
        window=window or ArrivalWindow(30),
        warmed_up=warmed_up,
        is_open=lambda sig, template_id: (sig, template_id) in open_keys,
    )
