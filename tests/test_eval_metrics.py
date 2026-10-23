"""
TREMOR — Eval metric tests. Every expected number is computed by hand in comments.
"""

from __future__ import annotations

import pytest

from eval.metrics import EvalAlert, LabelWindow, aggregate, match_alerts, restrict

ER, SIL, NEW, LAT = "ERROR_RATE", "SILENCE", "NEW_PATTERN", "LATENCY"
PG, AUTH, LEDGER = "payment-gateway", "auth-service", "ledger"

LABELS = [
    LabelWindow(100, 130, ER, PG),
    LabelWindow(200, 260, SIL, AUTH),
    LabelWindow(300, 400, NEW, LEDGER),
]
ALERTS = [
    EvalAlert(110, ER, PG),  # TP for label 0, delay 10
    EvalAlert(185, ER, PG),  # inside 130 + 60 grace, label 0 already hit -> duplicate
    EvalAlert(191, ER, PG),  # past 190 -> FP
    EvalAlert(210, SIL, PG),  # right type, wrong service -> FP
    EvalAlert(220, LAT, AUTH),  # right service, wrong type -> FP
    EvalAlert(230, SIL, "*"),  # whole-stream alert matches label 1 -> TP, delay 30
]  # label 2 never alerted -> FN


def test_worked_example_outcome() -> None:
    out = match_alerts("mixed", ALERTS, LABELS, duration_s=3600, grace_s=60)
    assert (out.true_positives, out.false_positives, out.duplicates) == (2, 3, 1)
    assert (out.detected, out.false_negatives) == (2, 1)
    assert out.delays == (10, 30)
    assert not out.correct


def test_worked_example_aggregate() -> None:
    result = aggregate("x", [match_alerts("mixed", ALERTS, LABELS, duration_s=3600)])
    assert result.precision == pytest.approx(2 / 5)  # TP / (TP + FP); duplicate excluded
    assert result.recall == pytest.approx(2 / 3)
    # F1 = 2 * 0.4 * 0.6667 / (0.4 + 0.6667) = 0.5
    assert result.f1 == pytest.approx(0.5)
    assert result.mean_delay_s == pytest.approx(20)
    assert result.median_delay_s == pytest.approx(20)
    assert result.false_positives_per_hour == pytest.approx(3.0)  # 3 FP in 1 h
    assert (result.true_positives, result.false_positives) == (2, 3)
    assert (result.false_negatives, result.duplicates) == (1, 1)


def test_order_of_alerts_does_not_matter() -> None:
    forward = match_alerts("s", ALERTS, LABELS, duration_s=3600)
    backward = match_alerts("s", list(reversed(ALERTS)), LABELS, duration_s=3600)
    assert forward == backward


@pytest.mark.parametrize(
    ("ts", "tp", "fp"),
    [
        (99.999, 0, 1),  # before the window
        (100.0, 1, 0),  # exactly at start, delay 0
        (190.0, 1, 0),  # exactly end + grace
        (190.001, 0, 1),  # just past the grace
    ],
)
def test_window_edges(ts: float, tp: int, fp: int) -> None:
    out = match_alerts("e", [EvalAlert(ts, ER, PG)], [LABELS[0]], duration_s=600, grace_s=60)
    assert (out.true_positives, out.false_positives) == (tp, fp)


def test_zero_grace() -> None:
    out = match_alerts("g", [EvalAlert(131, ER, PG)], [LABELS[0]], duration_s=600, grace_s=0)
    assert out.false_positives == 1


def test_overlapping_labels_each_get_their_own_alert() -> None:
    labels = [LabelWindow(100, 200, ER, PG), LabelWindow(150, 250, ER, PG)]
    alerts = [EvalAlert(160, ER, PG), EvalAlert(170, ER, PG), EvalAlert(180, ER, PG)]
    out = match_alerts("o", alerts, labels, duration_s=600)
    # 160 -> earliest-starting undetected label (100), delay 60
    # 170 -> label 150 still undetected, delay 20
    # 180 -> both detected -> duplicate
    assert out.delays == (60, 20)
    assert (out.true_positives, out.duplicates, out.false_positives) == (2, 1, 0)
    assert out.correct


def test_no_alerts_no_labels_is_correct_but_undefined() -> None:
    out = match_alerts("steady", [], [], duration_s=900)
    assert out.correct
    result = aggregate("x", [out])
    assert result.precision is None and result.recall is None and result.f1 is None
    assert result.mean_delay_s is None and result.median_delay_s is None
    assert result.false_positives_per_hour == 0.0


def test_missed_everything() -> None:
    result = aggregate("x", [match_alerts("m", [], LABELS, duration_s=900)])
    assert result.precision is None  # no alerts at all
    assert result.recall == 0.0
    assert result.f1 is None
    assert result.false_negatives == 3


def test_only_false_positives() -> None:
    alerts = [EvalAlert(10, ER, PG), EvalAlert(20, ER, AUTH)]
    result = aggregate("x", [match_alerts("n", alerts, [], duration_s=1800)])
    assert result.precision == 0.0
    assert result.recall is None
    assert result.false_positives_per_hour == pytest.approx(4.0)  # 2 FP in 0.5 h


def test_micro_average_across_scenarios() -> None:
    a = match_alerts("a", [EvalAlert(110, ER, PG)], [LABELS[0]], duration_s=1800)
    b = match_alerts(
        "b",
        [EvalAlert(250, SIL, AUTH), EvalAlert(500, ER, PG)],
        [LABELS[1], LABELS[2]],
        duration_s=1800,
    )
    result = aggregate("x", [a, b])
    # TP 2 (a:1, b:1), FP 1 (b), labels 3, detected 2, delays [10, 50]
    assert result.precision == pytest.approx(2 / 3)
    assert result.recall == pytest.approx(2 / 3)
    assert result.f1 == pytest.approx(2 / 3)
    assert result.mean_delay_s == pytest.approx(30)
    assert result.median_delay_s == pytest.approx(30)
    assert result.false_positives_per_hour == pytest.approx(1.0)  # 1 FP in 1 h
    assert [o.correct for o in result.scenarios] == [True, False]


def test_median_with_odd_count() -> None:
    labels = [LabelWindow(0, 10, ER, PG), LabelWindow(100, 110, ER, AUTH)]
    labels.append(LabelWindow(200, 210, ER, LEDGER))
    alerts = [EvalAlert(1, ER, PG), EvalAlert(105, ER, AUTH), EvalAlert(230, ER, LEDGER)]
    result = aggregate("x", [match_alerts("d", alerts, labels, duration_s=600)])
    assert result.mean_delay_s == pytest.approx(12)  # (1 + 5 + 30) / 3
    assert result.median_delay_s == pytest.approx(5)


def test_restrict_to_one_signal_type() -> None:
    (only_er,) = restrict([("mixed", ALERTS, LABELS)], ER)
    name, alerts, labels = only_er
    assert name == "mixed"
    assert {a.signal_type for a in alerts} == {ER}
    assert labels == [LABELS[0]]
