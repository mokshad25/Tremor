"""
TREMOR — Template miner tests.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.clock import FakeClock
from app.core.templates import TemplateMiner

if TYPE_CHECKING:
    from pathlib import Path

T0 = 1_000_000.0

# Message shapes whose variable parts are all masked, so each shape must map to
# exactly one template no matter which values are filled in.
SHAPES: tuple[str, ...] = (
    "Payment authorized txn_{h} amount={n}.{n} USD for <EMAIL> in {n}ms",
    "User {u} logged in from {ip}",
    "Ledger post failed for acct_{h} code={n}",
    "Card declined reason=insufficient_funds card <CARD> attempt {n}",
    "Token refresh ok Bearer <TOKEN> expires_in={n}",
)


def fill(shape: str, n: int) -> str:
    """Fill a shape with values derived from ``n``."""
    uuid = f"{n % 0xFFFFFFFF:08x}-1234-4abc-8def-{n % 0xFFFFFFFFFFFF:012x}"
    ip = f"10.{n % 256}.{(n // 256) % 256}.{(n // 65536) % 256}"
    return shape.format(h=f"{n:x}", n=n, u=uuid, ip=ip)


def make_miner(clock: FakeClock | None = None, **kwargs: Any) -> TemplateMiner:
    return TemplateMiner(clock or FakeClock(T0), **kwargs)


# ── Masking ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (
            "Order txn_9f8a7b paid 12.50 in 123ms",
            "Order txn_00aa11 paid 999.99 in 7ms",
            "Order <ID> paid <NUM> in <NUM>",
        ),
        (
            "User 550e8400-e29b-41d4-a716-446655440000 from 10.0.0.12",
            "User 123e4567-e89b-12d3-a456-426614174000 from 192.168.1.1:8080",
            "User <UUID> from <IP>",
        ),
        ("Request 0xdeadbeef failed", "Request 0x12 failed", "Request <HEX> failed"),
        ("Batch 4f9c2a1b7e3d9a00 done", "Batch 00ff00ff00ff00ff done", "Batch <HEX> done"),
    ],
)
def test_masking_collapses_variable_parts(a: str, b: str, expected: str) -> None:
    miner = make_miner()
    id_a = miner.add_message(a)
    id_b = miner.add_message(b)
    assert id_a == id_b
    assert miner.get_template(id_a).template == expected


def test_redaction_placeholders_survive() -> None:
    miner = make_miner()
    tid = miner.add_message("Auth Bearer <TOKEN> for <EMAIL> key <API_KEY> card <CARD>")
    assert miner.get_template(tid).template == (
        "Auth Bearer <TOKEN> for <EMAIL> key <API_KEY> card <CARD>"
    )


# ── Stability ─────────────────────────────────────────────────────────


def test_same_message_same_id() -> None:
    miner = make_miner()
    msg = "Ledger reconcile completed for batch 42"
    assert miner.add_message(msg) == miner.add_message(msg) == miner.add_message(msg)


def test_ids_are_strings_stable_per_pattern() -> None:
    miner = make_miner()
    ids = [miner.add_message(f"Ledger reconcile completed for batch {i}") for i in range(5)]
    assert ids == ["T1"] * 5
    assert miner.add_message("Completely unrelated auth event") == "T2"


def test_unknown_or_malformed_id_is_harmless() -> None:
    miner = make_miner()
    miner.add_message("hello world")
    assert not miner.is_new("nope")
    assert miner.count_in_window("nope", 10) == 0
    with pytest.raises(KeyError):
        miner.get_template("nope")


def test_distinct_messages_distinct_ids() -> None:
    miner = make_miner()
    ids = {miner.add_message(fill(shape, 7)) for shape in SHAPES}
    assert len(ids) == len(SHAPES)


def test_template_info_fields() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock)
    tid = miner.add_message("DB timeout on shard 1", ts=T0 + 1)
    miner.add_message("DB timeout on shard 2", ts=T0 + 5)
    miner.add_message("something else entirely here", ts=T0 + 6)
    info = miner.get_template(tid)
    assert info.id == tid
    assert info.count == 2
    assert info.first_seen == T0 + 1
    assert info.last_seen == T0 + 5
    assert info.sample == "DB timeout on shard 2"
    assert info.rarity == pytest.approx(2 / 3)
    assert miner.total_messages == 3


def test_unknown_template_raises() -> None:
    with pytest.raises(KeyError):
        make_miner().get_template("T999")


def test_ts_defaults_to_clock() -> None:
    clock = FakeClock(T0 + 123)
    miner = make_miner(clock)
    tid = miner.add_message("hello world")
    assert miner.get_template(tid).first_seen == T0 + 123


# ── Novelty ───────────────────────────────────────────────────────────


def test_known_during_warmup_new_after() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock, warmup_seconds=60, novelty_ttl_s=300)
    known = miner.add_message("Payment ok 1", ts=T0)
    miner.add_message("Login ok user 5", ts=T0 + 59)  # still in warm-up
    clock.set(T0 + 100)
    fresh = miner.add_message("HSM key rotation failed", ts=T0 + 100)
    assert not miner.is_new(known)
    assert miner.is_new(fresh)


def test_novelty_expires_after_ttl() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock, warmup_seconds=10, novelty_ttl_s=60)
    miner.add_message("warm up line", ts=T0)
    clock.set(T0 + 20)
    fresh = miner.add_message("brand new failure mode", ts=T0 + 20)
    assert miner.is_new(fresh, now=T0 + 80)
    assert not miner.is_new(fresh, now=T0 + 81)
    clock.set(T0 + 100)
    assert not miner.is_new(fresh)


def _rare_setup(**kwargs: Any) -> tuple[FakeClock, TemplateMiner, str, str]:
    """A miner past warm-up with one rare template (1 of 201) and one common one."""
    clock = FakeClock(T0)
    miner = make_miner(clock, warmup_seconds=100, rarity_threshold=0.01, **kwargs)
    rare = miner.add_message("Rare HSM warning", ts=T0)
    common = ""
    for i in range(200):
        common = miner.add_message(f"Payment ok {i}", ts=T0 + i * 0.1)
    clock.set(T0 + 200)
    return clock, miner, rare, common


def test_rare_template_single_reappearance_is_not_new() -> None:
    _, miner, rare, _ = _rare_setup()
    miner.add_message("Rare HSM warning", ts=T0 + 200)  # rare, but just once
    assert not miner.is_new(rare)


def test_rare_template_surge_is_new() -> None:
    _, miner, rare, _ = _rare_setup(rare_surge_count=3, rare_surge_window_s=60)
    miner.add_message("Rare HSM warning", ts=T0 + 200)
    miner.add_message("Rare HSM warning", ts=T0 + 230)
    assert not miner.is_new(rare, now=T0 + 230)
    miner.add_message("Rare HSM warning", ts=T0 + 259)  # 3 within 60 s
    assert miner.is_new(rare, now=T0 + 259)
    assert miner.get_template(rare).count == 4


def test_rare_template_slow_trickle_is_not_new() -> None:
    _, miner, rare, _ = _rare_setup(rare_surge_count=3, rare_surge_window_s=60)
    for ts in (T0 + 200, T0 + 240, T0 + 280, T0 + 320):  # never 3 inside 60 s
        miner.add_message("Rare HSM warning", ts=ts)
    assert not miner.is_new(rare, now=T0 + 320)


def test_common_template_surge_is_not_new() -> None:
    _, miner, _, common = _rare_setup()
    for _ in range(10):
        miner.add_message("Payment ok 999", ts=T0 + 200)
    assert not miner.is_new(common)


def test_first_seen_after_warmup_is_new_immediately() -> None:
    _, miner, _, _ = _rare_setup(rare_surge_count=3)
    fresh = miner.add_message("Ledger shard failover started", ts=T0 + 200)
    assert miner.is_new(fresh, now=T0 + 200)


def test_is_new_unknown_id_is_false() -> None:
    assert not make_miner().is_new("T12345")


# ── Windowed counts ───────────────────────────────────────────────────


def test_count_in_window_and_eviction() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock, max_window_s=60)
    tid = 0
    for i in range(10):
        tid = miner.add_message("DB timeout on shard 3", service="ledger", ts=T0 + i)
    clock.set(T0 + 9)
    assert miner.count_in_window(tid, 10) == 10
    assert miner.count_in_window(tid, 5) == 5  # seconds T0+5..T0+9
    clock.set(T0 + 100)
    miner.tick()
    assert miner.count_in_window(tid, 60) == 0


def test_count_is_per_service() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock)
    tid = miner.add_message("Timeout calling upstream", service="a", ts=T0)
    miner.add_message("Timeout calling upstream", service="a", ts=T0)
    miner.add_message("Timeout calling upstream", service="b", ts=T0)
    assert miner.count_in_window(tid, 10, service="a") == 2
    assert miner.count_in_window(tid, 10, service="b") == 1
    assert miner.count_in_window(tid, 10) == 3
    assert miner.count_in_window(tid, 10, service="zzz") == 0


def test_late_event_lands_in_its_bucket() -> None:
    clock = FakeClock(T0 + 10)
    miner = make_miner(clock)
    tid = miner.add_message("late thing", ts=T0 + 10)
    miner.add_message("late thing", ts=T0 + 7)  # out of order, still in window
    assert miner.count_in_window(tid, 5) == 2
    assert miner.count_in_window(tid, 2) == 1


def test_window_larger_than_max_rejected() -> None:
    with pytest.raises(ValueError):
        make_miner(max_window_s=60).count_in_window("T1", 61)


def test_new_templates_in_window() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock, warmup_seconds=10)
    known = miner.add_message("Payment ok 1", service="pg", ts=T0)
    clock.set(T0 + 30)
    fresh = 0
    for _ in range(4):
        fresh = miner.add_message("HSM key rotation failed", service="auth", ts=T0 + 30)
    miner.add_message("Payment ok 2", service="pg", ts=T0 + 30)
    assert miner.new_templates_in_window(10) == {fresh: 4}
    assert miner.new_templates_in_window(10, service="auth") == {fresh: 4}
    assert miner.new_templates_in_window(10, service="pg") == {}
    assert known not in miner.new_templates_in_window(60)


# ── Top templates ─────────────────────────────────────────────────────


def test_top_templates_order_and_ties() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock)
    a = miner.add_message("alpha event happened", ts=T0)
    b = miner.add_message("beta thing occurred now", ts=T0)
    c = miner.add_message("gamma issue raised here today", ts=T0)
    miner.add_message("gamma issue raised here today", ts=T0)
    top = miner.get_top_templates(3)
    assert [t.id for t in top] == [c, a, b]  # c=2, then a/b tie broken by lower id
    assert [t.count for t in top] == [2, 1, 1]
    assert len(miner.get_top_templates(1)) == 1


def test_top_template_ties_use_numeric_id_order() -> None:
    miner = make_miner()
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
    ids = [miner.add_message(f"{w} {w} {w} {w}") for w in words]  # T1..T6
    ids += [miner.add_message(f"{w} {w} {w}") for w in words]  # T7..T12, all count 1
    top = [t.id for t in miner.get_top_templates(12)]
    assert top == sorted(ids, key=lambda t: int(t[1:]))
    assert top.index("T2") < top.index("T10")


def test_top_templates_filtered_by_service_and_window() -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock)
    old = miner.add_message("old noisy message here", service="pg", ts=T0)
    for _ in range(5):
        miner.add_message("old noisy message here", service="pg", ts=T0)
    clock.set(T0 + 100)
    recent = miner.add_message("recent auth failure", service="auth", ts=T0 + 100)
    by_window = miner.get_top_templates(5, window_s=10)
    assert [(t.id, t.count) for t in by_window] == [(recent, 1)]
    by_service = miner.get_top_templates(5, service="pg")
    assert [(t.id, t.count) for t in by_service] == [(old, 6)]
    assert miner.get_top_templates(5, service="auth", window_s=10)[0].id == recent


# ── Memory cap ────────────────────────────────────────────────────────


def test_max_clusters_caps_stats() -> None:
    miner = make_miner(max_clusters=5)
    words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"]
    ids = {
        miner.add_message(f"{words[i % 8]} {words[(i * 3) % 8]} unique{chr(97 + i)} event")
        for i in range(20)
    }
    assert len(ids) == 20  # every message created its own cluster...
    assert len(miner.get_top_templates(100)) <= 5  # ...but only `max_clusters` are retained


# ── Persistence ───────────────────────────────────────────────────────


async def test_persist_restore_roundtrip(tmp_path: Path) -> None:
    clock = FakeClock(T0)
    miner = make_miner(clock, warmup_seconds=10)
    ids = [miner.add_message(fill(shape, i), service="pg", ts=T0) for i, shape in enumerate(SHAPES)]
    clock.set(T0 + 50)
    fresh = miner.add_message("brand new failure mode", ts=T0 + 50)
    path = tmp_path / "state" / "templates.json"
    await miner.persist(str(path))
    assert path.exists()
    assert not (tmp_path / "state" / "templates.json.tmp").exists()

    restored = make_miner(FakeClock(T0 + 50), warmup_seconds=10)
    await restored.restore(str(path))
    assert restored.total_messages == miner.total_messages
    assert restored.is_new(fresh)
    for tid in [*ids, fresh]:
        assert restored.get_template(tid) == miner.get_template(tid)
    again = [restored.add_message(fill(shape, 99), ts=T0 + 51) for shape in SHAPES]
    assert again == ids


async def test_restore_rejects_unknown_version(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"version": 999}))
    with pytest.raises(ValueError, match="version"):
        await make_miner().restore(str(path))


# ── Properties ────────────────────────────────────────────────────────

sequences = st.lists(
    st.tuples(st.integers(0, len(SHAPES) - 1), st.integers(0, 10**9)), min_size=1, max_size=60
)


@settings(max_examples=50, deadline=None)
@given(seq=sequences)
def test_property_ids_deterministic(seq: list[tuple[int, int]]) -> None:
    """Two fresh miners fed the same sequence produce identical ids."""
    messages = [fill(SHAPES[s], n) for s, n in seq]
    a, b = make_miner(), make_miner()
    assert [a.add_message(m) for m in messages] == [b.add_message(m) for m in messages]


@settings(max_examples=50, deadline=None)
@given(seq=sequences)
def test_property_shape_maps_to_one_stable_id(seq: list[tuple[int, int]]) -> None:
    """Every message of a shape gets the same id, and restore keeps it."""
    miner = make_miner()
    seen: dict[int, str] = {}
    for s, n in seq:
        tid = miner.add_message(fill(SHAPES[s], n))
        assert seen.setdefault(s, tid) == tid
    assert len(set(seen.values())) == len(seen)

    restored = make_miner()
    restored._load(miner._snapshot())  # sync path behind persist/restore
    for s, tid in seen.items():
        assert restored.add_message(fill(SHAPES[s], 12345)) == tid
