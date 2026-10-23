"""
TREMOR — Eval metrics: match alerts to labelled windows and score a detector.

Matching rule (see docs/TRADEOFFS.md):
- An alert matches a label when the signal type is the same, the service is the same
  (an alert for the whole stream, service ``"*"``, matches any service), and
  ``label.start <= alert.ts <= label.end + grace``.
- The first alert matching a still-undetected label is a true positive. Its delay
  is ``alert.ts - label.start``.
- Further alerts matching only already-detected labels are duplicates: they are
  neither TP nor FP, and are reported separately.
- An alert matching no label is a false positive.
- A label with no matching alert is a false negative.

Precision = TP / (TP + FP), recall = detected labels / labels. All times are
scenario-relative seconds.

Owner: Mokshad (Phase 6)
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

WHOLE_STREAM = "*"
DEFAULT_GRACE_S = 60.0


@dataclass(frozen=True, slots=True)
class LabelWindow:
    """Ground truth: ``service`` should raise ``signal_type`` in ``[start, end]``."""

    start: float
    end: float
    signal_type: str
    service: str


@dataclass(frozen=True, slots=True)
class EvalAlert:
    """An alert opening, as seen by eval: when, what and for which service."""

    ts: float
    signal_type: str
    service: str


@dataclass(frozen=True, slots=True)
class ScenarioOutcome:
    """Matching result for one scenario and one detector."""

    scenario: str
    duration_s: float
    labels: int
    true_positives: int
    false_positives: int
    duplicates: int
    delays: tuple[float, ...]  # one per detected label, in label order

    @property
    def detected(self) -> int:
        """Labels with at least one matching alert."""
        return len(self.delays)

    @property
    def false_negatives(self) -> int:
        """Labels no alert matched."""
        return self.labels - self.detected

    @property
    def correct(self) -> bool:
        """Every label detected and no false positives."""
        return self.false_negatives == 0 and self.false_positives == 0


@dataclass(frozen=True, slots=True)
class EvalResult:
    """Aggregate score for one detector over many scenarios (micro-averaged)."""

    detector: str
    precision: float | None  # None when the detector raised no TP or FP alerts
    recall: float | None  # None when there were no labels
    f1: float | None  # None when precision or recall is undefined
    mean_delay_s: float | None
    median_delay_s: float | None
    false_positives_per_hour: float
    true_positives: int
    false_positives: int
    false_negatives: int
    duplicates: int
    scenarios: tuple[ScenarioOutcome, ...]


def _matches(alert: EvalAlert, label: LabelWindow, grace_s: float) -> bool:
    return (
        alert.signal_type == label.signal_type
        and alert.service in (label.service, WHOLE_STREAM)
        and label.start <= alert.ts <= label.end + grace_s
    )


def match_alerts(
    scenario: str,
    alerts: Iterable[EvalAlert],
    labels: Sequence[LabelWindow],
    *,
    duration_s: float,
    grace_s: float = DEFAULT_GRACE_S,
) -> ScenarioOutcome:
    """Apply the matching rule to one scenario's alerts."""
    first_hit: dict[int, float] = {}
    tp = fp = dup = 0
    for alert in sorted(alerts, key=lambda a: a.ts):
        candidates = [i for i, lb in enumerate(labels) if _matches(alert, lb, grace_s)]
        if not candidates:
            fp += 1
            continue
        fresh = [i for i in candidates if i not in first_hit]
        if fresh:
            target = min(fresh, key=lambda i: (labels[i].start, i))
            first_hit[target] = alert.ts - labels[target].start
            tp += 1
        else:
            dup += 1
    return ScenarioOutcome(
        scenario=scenario,
        duration_s=duration_s,
        labels=len(labels),
        true_positives=tp,
        false_positives=fp,
        duplicates=dup,
        delays=tuple(first_hit[i] for i in sorted(first_hit)),
    )


def aggregate(detector: str, outcomes: Sequence[ScenarioOutcome]) -> EvalResult:
    """Micro-average scenario outcomes into one ``EvalResult``."""
    tp = sum(o.true_positives for o in outcomes)
    fp = sum(o.false_positives for o in outcomes)
    fn = sum(o.false_negatives for o in outcomes)
    labels = sum(o.labels for o in outcomes)
    detected = sum(o.detected for o in outcomes)
    delays = [d for o in outcomes for d in o.delays]
    hours = sum(o.duration_s for o in outcomes) / 3600

    precision = tp / (tp + fp) if tp + fp else None
    recall = detected / labels if labels else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)

    return EvalResult(
        detector=detector,
        precision=precision,
        recall=recall,
        f1=f1,
        mean_delay_s=statistics.fmean(delays) if delays else None,
        median_delay_s=statistics.median(delays) if delays else None,
        false_positives_per_hour=fp / hours if hours else 0.0,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        duplicates=sum(o.duplicates for o in outcomes),
        scenarios=tuple(outcomes),
    )


def restrict(
    outcome_inputs: Iterable[tuple[str, Sequence[EvalAlert], Sequence[LabelWindow]]],
    signal_type: str,
) -> list[tuple[str, list[EvalAlert], list[LabelWindow]]]:
    """Keep only one signal type's alerts and labels, e.g. for an ERROR_RATE-only table."""
    return [
        (
            name,
            [a for a in alerts if a.signal_type == signal_type],
            [lb for lb in labels if lb.signal_type == signal_type],
        )
        for name, alerts, labels in outcome_inputs
    ]
