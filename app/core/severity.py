"""
TREMOR — Severity scoring engine.

Severity levels (thresholds from config):
- INFO:     z >= z_info (3)
- WARNING:  z >= z_warn (5)
- HIGH:     z >= z_high (8)
- CRITICAL: error rate > rate_ceiling (50%) with n >= min_events, whatever z says

Pure function: no state, no clock. Escalation and hysteresis live in alerts.py.

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.config import Settings


class Severity(IntEnum):
    """Alert severity levels, ordered for comparison."""

    INFO = 1
    WARNING = 2
    HIGH = 3
    CRITICAL = 4


def score(
    z: float | None,
    cfg: Settings,
    *,
    rate: float | None = None,
    n: int = 0,
) -> Severity | None:
    """Severity for one tick. Pass `rate` and `n` only for signals with a CRITICAL rule."""
    if rate is not None and n >= cfg.min_events and rate > cfg.rate_ceiling:
        return Severity.CRITICAL
    if z is None:
        return None
    if z >= cfg.z_high:
        return Severity.HIGH
    if z >= cfg.z_warn:
        return Severity.WARNING
    if z >= cfg.z_info:
        return Severity.INFO
    return None
