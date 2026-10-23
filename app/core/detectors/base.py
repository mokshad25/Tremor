"""
TREMOR — Detector protocol and the per-event / per-tick inputs every detector receives.

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.core.alerts import Signal, SignalType
    from app.core.arrivals import ArrivalWindow


@dataclass(frozen=True, slots=True)
class Observation:
    """One parsed line as detection sees it. Built by DetectionEngine.observe()."""

    arrival: float  # when TREMOR received the line (not the timestamp inside it)
    level: str  # normalized parser level; "ERROR" is the error signal
    duration_ms: float | None = None
    template_id: str | None = None  # from the shared TemplateMiner, e.g. "T12"
    is_new_template: bool = False  # the miner created this template on this line
    warmed_up: bool = False  # error-rate baseline was seeded when the line arrived


@dataclass(frozen=True, slots=True)
class TickContext:
    """Everything a detector may read on a tick. Detection never reads a clock."""

    now: float
    window: ArrivalWindow  # lines that arrived in (now - detection_window_s, now]
    warmed_up: bool  # error-rate baseline seeded before this tick
    is_open: Callable[[SignalType, str | None], bool]  # (signal, template_id) -> incident open?


class TemplateMinerLike(Protocol):
    """
    What the pipeline needs from the shared TemplateMiner (app/core/templates.py).
    Detection never calls it; the pipeline passes its answers to DetectionEngine.observe().
    """

    def add_message(
        self, message: str, *, service: str = "_global", ts: float | None = None
    ) -> str:
        """Template id for this message, e.g. "T12", stable per pattern for the whole run."""
        ...

    def is_new(self, template_id: str) -> bool:
        """True iff the most recent add_message() call created `template_id`."""
        ...


class Detector(Protocol):
    """
    A detector is built as `Detector(cfg: Settings, service: str = "*")`.
    The engine calls observe() for every line and evaluate() once per tick, and hands
    the returned Signals to the AlertManager.
    """

    signal_type: SignalType

    def observe(self, obs: Observation) -> None:
        """Record one line. Must be cheap: called for every event."""
        ...

    def evaluate(self, ctx: TickContext) -> list[Signal]:
        """This tick's verdicts, one Signal per key (usually one)."""
        ...
