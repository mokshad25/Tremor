# Mokshad — Template Miner, Simulator, Eval: implementation plan

> On approval, the first action is to copy this file verbatim to `docs/plans/mokshad-plan.md`. It is committed together with step 1.
> Repo root: `/Users/mokshad/Desktop/tremor/tremor` (the outer `tremor/` folder is not the repo).

## Context

Phase 1 (ingestion) is confirmed implemented and tested:
- `tailer.py`, `parser.py`, `redact.py` and `window.py` have real code.
- Tests for them are in `tests/test_{tailer,parser,redact,window}.py`.

The next phases are:
- **Phase 2:** I own the Template Miner.
- **Phase 6:** I own the Simulator and the Eval Harness.

Kostubh's modules are still TODO stubs: `baseline.py`, `severity.py`, all detectors and `AlertManager`. No `Signal` type or detector signature exists. Decisions agreed with Mokshad:
- **Template IDs are `str`** (e.g. `"T12"`). This was changed from `int` at Kostubh's request, and `alerts.TemplateHint.template_id` is moving to `str` to match.
- **Phase 1 lint/type fixes go inside the step 1 commit**, not a separate commit.
- **Steps 4–5 are blocked.** Eval waits until (a) Kostubh defines the Signal, detector, BaselineStore and AlertManager interfaces, and (b) the templates and simulator PRs are merged to main. No stacked branches and no guessed interfaces.

## Execution order and branches

| # | Branch (from latest `origin/main`) | Commit | Status |
|---|---|---|---|
| 1 | `feat/mokshad-templates` | `feat(templates): drain3 TemplateMiner with novelty + windowed counts` | go |
| 2 | `feat/mokshad-simulator` | `feat(simulator): seeded Poisson LogGenerator with offline + async file modes` | go |
| 3 | `feat/mokshad-simulator` (same branch) | `feat(scenarios): rate curves, injected templates, outage, corrected labels` | go |
| 4 | `feat/mokshad-eval` | `feat(eval): EvalHarness with TREMOR/static/rolling-mean adapters` | **BLOCKED** |
| 5 | `feat/mokshad-eval` | `docs: template miner, simulator, eval architecture + tradeoffs` | **BLOCKED** (follows 4) |

Git procedure for every branch and commit:
1. Check `git status` on `main` and confirm it is clean.
2. Run `git pull --rebase origin main`, then `git checkout -b <branch>`.
3. Re-check whether any of Kostubh's interfaces have landed.
4. Stage only my files by explicit path.
5. Run `git status` and `git diff --stat`, then commit.
6. Run `git pull --rebase origin main`, then `git push -u origin <branch>`.

Rules that always apply: no force-push to main, no local merges. I'll ask before opening a PR. After each step, I run the full gate (see Verification) and report the result in 2–3 lines.

---

## Step 1 — `app/core/templates.py` (TemplateMiner)

**Files touched:**
- `app/core/templates.py` (rewrite of my own stub)
- `tests/test_templates.py` (new)
- Phase 1 lint fixes (types and formatting only, no behaviour change):
  - `app/core/window.py`:
    - add `-> None` to `__init__`
    - change the `window_sizes: list[int] = (10,60,300)` default to a `Sequence[int]` or `None` default
    - annotate `views`
    - apply black whitespace fixes
  - `app/ingest/parser.py`: move the mid-file imports to the top (E402).
  - `app/ingest/tailer.py`:
    - replace `Optional` with `X | None`
    - type `_file` as `TextIO | None`
    - apply black
    - handle the `_file` None-narrowing
  - `tests/test_tailer.py`: annotate the fixture return type.
- `docs/plans/mokshad-plan.md` (this plan) and `docs/plans/requests-for-team.md` (new).

**Before coding:** read the installed drain3 source (`TemplateMiner`, `TemplateMinerConfig`, `MaskingInstruction`, `save_state`/`load_state`, and the LRU `LogClusterCache`) to confirm the 0.9.x API.

**Public interface:**
```python
@dataclass(frozen=True, slots=True)
class TemplateInfo:
    id: str; template: str; count: int; first_seen: float; last_seen: float
    sample: str            # most recent (already-redacted) message
    rarity: float          # count / total messages seen by the miner (0..1)

class TemplateMiner:
    def __init__(self, clock: Clock, *, warmup_seconds: int = 300, rarity_threshold: float = 0.001,
                 novelty_ttl_s: int = 300, max_clusters: int = 1000, max_window_s: int = 300,
                 sim_th: float = 0.4, depth: int = 4) -> None
    def add_message(self, message: str, *, service: str = "_global", ts: float | None = None) -> str
    def get_template(self, template_id: str) -> TemplateInfo           # KeyError if unknown/evicted
    def get_top_templates(self, n: int, *, service: str | None = None,
                          window_s: int | None = None) -> list[TemplateInfo]
    def is_new(self, template_id: str, now: float | None = None) -> bool
    def count_in_window(self, template_id: str, window_s: int, *, service: str | None = None) -> int
    def new_templates_in_window(self, window_s: int, *, service: str | None = None) -> dict[str, int]
    def tick(self) -> None                                              # evict old buckets on clock
    @property
    def total_messages(self) -> int
    async def persist(self, path: str) -> None
    async def restore(self, path: str) -> None
```

**Design:**
- **Time:** `ts` defaults to `clock.now()`. There is no `time.time()` anywhere, and event time is used when given.
- **Masking:** drain3 `MaskingInstruction`s run in this order:
  1. UUID
  2. `0x` hex and long hex IDs
  3. IPv4
  4. prefixed IDs (`txn_…`, `req_…`, `acct_…`)
  5. numbers (including decimals)

  Masks use drain3's `<` `>` affixes, producing `<UUID>` and `<NUM>`. These sit alongside redact's `<EMAIL>`/`<CARD>`/`<TOKEN>`/`<API_KEY>`, which pass through unchanged. Config is built in code, never from `drain3.ini`.
- **Determinism:** there is no drain3 persistence handler during normal operation, so drain3 never calls `time.time()` on the hot path. drain3 is deterministic for the same input order. Tie-breaks in `get_top_templates` are (count desc, id asc).
- **Novelty:** warm-up ends at the first message's ts + `warmup_seconds`. A template becomes novel at time `t` when either:
  - it is first seen after warm-up, or
  - it is historically rare (`count / total` before the surge is below `rarity_threshold`) and it surges after warm-up: at least `rare_surge_count` (3) occurrences within `rare_surge_window_s` (60 s), and it isn't already novel. (A single reappearance used to be enough; changed 2026-09-28 because Kostubh's detector opens an incident per new template with no minimum count.)

  `is_new` returns true while `now - novel_at <= novelty_ttl_s`, so the flag is stable for a whole incident and does not flap as the count grows.
- **Per-window counter:** each service keeps a `deque[(second, Counter[int])]` of 1 s buckets, bounded to `max_window_s`, using the same pattern as `WindowEngine`. Buckets are evicted on `tick()` and on insert. A late event goes into the matching bucket if it is still retained.
  - `new_templates_in_window(w, service=s)` returns `{template_id: count}` for templates where `is_new` is true. This is the call Kostubh's new_pattern detector needs.
- **Memory cap:** `drain_max_clusters=max_clusters` (drain3 LRU).
  - When a new cluster pushes the stats dict over the cap, stats for IDs no longer in `drain.id_to_cluster` are pruned.
  - Window buckets are bounded by `max_window_s × distinct templates per second`.
  - If an evicted template comes back it gets a new ID and counts as new. This is documented as a tradeoff.
- **Persist/restore:**
  - Serialization reuses drain3's own code through a duck-typed in-memory persistence handler (no subclassing, so strict mypy never sees an `Any` base). The handler is set only for the duration of `save_state`/`load_state`.
  - The file is a JSON envelope: `{version, drain_state(b64), stats, total, warmup_end, novelty}`.
  - Writes are atomic (tmp file + `os.replace`) and run via `asyncio.to_thread`.
  - Restore rejects any version other than 1. The file is trusted local state because drain3 uses jsonpickle; this is noted as a risk.
- **mypy:** results from drain3 are `Any`, so every value is converted with `int(...)`/`str(...)` to satisfy `warn_return_any`.

**Tests (`tests/test_templates.py`):**
- masking: order IDs, amounts, UUIDs, IPs, hex IDs and `txn_` IDs all collapse to one template
- redact placeholders survive intact
- stability: the same message returns the same ID
- similar messages merge; different messages stay distinct
- new vs known: a template seen during warm-up is not new; a first sighting after warm-up is new; novelty expires after the TTL
- rarity: a rare warm-up template that reappears after warm-up is new; a common one is not; the rarity value itself is correct
- `count_in_window` / `new_templates_in_window`: correct counts, per-service isolation, eviction after the window, late events inside lateness
- `get_top_templates`: ordering, ties, service and window filters
- memory cap: `max_clusters=5` with 20 distinct templates leaves ≤5 live stats entries
- persist/restore roundtrip (`tmp_path`): IDs, counts and novelty are preserved, and a known message returns the same ID after restore
- restore of a bad version raises `ValueError`
- **hypothesis:**
  - for random message lists, two fresh miners fed the same sequence produce identical ID sequences
  - re-adding any earlier message returns an ID already seen, and after persist/restore the IDs are unchanged
- no wall time: a FakeClock drives everything (asserted via ts values)

---

## Step 2 — `simulator/gen_logs.py` (LogGenerator)

**Files touched:** `simulator/gen_logs.py`, `tests/test_simulator.py` (new). The minimal additions to `simulator/scenarios.py` that step 2 needs are deferred to step 3. Step 2 runs the existing `steady` shape through a default profile.

**Public interface:**
```python
class GeneratedLine(NamedTuple):
    ts: float
    line: str          # a tuple (ts, raw_line), as requested

@dataclass(frozen=True, slots=True)
class ServiceProfile:
    name: str; base_rate_per_s: float; error_rate: float; latency_p50_ms: float
    fmt: Literal["json", "text"]

DEFAULT_SERVICES: tuple[ServiceProfile, ...]   # payment-gateway(json, ~2%), auth-service(text, ~1.5%), ledger(text, ~1%)

class LogGenerator:
    def __init__(self, scenario: Scenario, *, seed: int | str | None = None,
                 start_ts: float = DEFAULT_START_TS) -> None
    def iter_lines(self) -> Iterator[GeneratedLine]                     # offline, virtual time
    def generate_line(self, service: str, level: str, ts: float, t_rel: float) -> str
    async def write_file(self, path: str | Path, *, speed: float = 1.0,
                         sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
                         rotate_at_s: Sequence[float] | None = None) -> int   # lines written

def main(argv: list[str] | None = None) -> int
# python -m simulator.gen_logs --scenario steady --out sample/app.log [--speed 10] [--offline]
```

**Design:**
- **Shared code path:** `write_file` iterates `iter_lines()`, sleeps `(ts - prev_ts) / speed` between ticks via the injected `sleep`, and appends batches. Byte-identity with offline mode is therefore structural.
- **Rotation:** at each `rotate_at_s`, rename `path` to `path.1` (then `.2` …) and open a fresh `path`, matching logrotate's "create" mode.
- **Determinism:** each service gets its own `random.Random(f"{seed}:{service}")`. String seeding is stable across processes and independent of PYTHONHASHSEED.
  - Streams merge with `heapq.merge` on `(ts, service_idx, seq)`.
  - Timestamps are formatted by hand from `datetime.fromtimestamp(ts, UTC)` with `.3f` ms and a `Z` suffix.
  - JSON uses fixed key order and `separators=(",", ":")`.
  - `DEFAULT_START_TS` is a fixed epoch (2026-01-05T14:00:00Z), and nothing reads the wall clock.
- **Poisson arrivals:** exponential inter-arrivals (`rng.expovariate(λ)`), with λ re-evaluated every virtual second. λ is `base_rate × hour_of_day_factor(ts) × scenario volume curve`.
  - `hour_of_day_factor = 1 + 0.4·sin(2π(h−9)/24)`: busy by day, quiet at night.
- **Levels:** ERROR with probability `error_rate(t)`, otherwise WARNING about 3% of the time, otherwise INFO. The baseline error rate is 1–3% per service.
- **Latency:** `duration_ms` is lognormal around the p50. It is only emitted on JSON lines, because the parser reads `duration_ms` from JSON only.
- **Messages:** realistic fintech templates per service:
  - payment authorize/capture/refund
  - card declined
  - 3DS challenge
  - login ok/failed
  - MFA
  - token refresh
  - ledger post/reconcile
  - balance check
  - DB timeout

  Variable parts include `txn_` hex IDs, UUIDs, amounts and IPs. Fake PII covers every redact path:
  - `user123@example.com`
  - published Luhn-valid test cards (4111…, 5555…4444, 3782…0005)
  - `Bearer <random>`
  - `sk_test_<24 alnum>` keys
- **Malformed lines:** used by `malformed_flood` in step 3. Types are truncated JSON, a missing timestamp, binary junk, and an empty line.

**Tests (`tests/test_simulator.py`):**
- the same seed gives byte-identical output (joined string equality); a different seed gives different output
- timestamps are non-decreasing and inside `[start, start+duration]`
- the steady error rate per service falls in [1%, 3%] (seeded, large sample); the mean volume is within ±10% of the expected λ
- every line parses via `parse_line`: text and JSON both work, and JSON lines carry `duration_ms`
- PII appears in the raw lines (at least one email/card/token/key) and never after `parse_line`, which checks the redact integration
- `write_file` with a no-op `sleep` produces a file identical to `"".join(iter_lines)`
- `write_file` with `rotate_at_s`: the `.1` file exists and the concatenated contents equal the offline output
- tailer integration (`@pytest.mark.integration`): a real `Tailer` reads through one rotation, and the line count equals the generated count
- the CLI `--offline` writes a file

---

## Step 3 — `simulator/scenarios.py`

**Files touched:** `simulator/scenarios.py`, `simulator/gen_logs.py` (consumes the new fields), `tests/test_scenarios.py` (new).

**Model:**
```python
@dataclass(frozen=True, slots=True)
class RateCurve:           # piecewise-linear keyframes ((t_s, value), ...); value_at(t)
@dataclass(frozen=True, slots=True)
class ServicePlan:         # service, volume_mult: RateCurve, error_rate: RateCurve, latency_mult: RateCurve
@dataclass(frozen=True, slots=True)
class InjectedTemplate:    # service, level, template (format str), rate_per_s, start_s, end_s
@dataclass(frozen=True, slots=True)
class Label:               # start_s, end_s, signal_type (SignalType value), service
@dataclass(frozen=True, slots=True)
class Scenario:            # name, description, duration_s, seed, warmup_s, plans, injected, labels,
                           # malformed_ratio=0.0, rotate_at_s=()
    @property
    def expected_anomalies(self) -> list[tuple[float, float, str]]  # backward-compatible view
```
Signal types are plain strings equal to `app.core.alerts.SignalType` values. A test asserts they are valid enum values. `alerts.py` is read-only for me.

**Label fix:** every anomaly now comes after a 360 s clean prefix. The warm-up is `WARMUP_SECONDS=300` plus margin. The old labels at 120 s fell inside warm-up and could never be detected. Each label's start and end are taken from the same constants the plan's curves use, so they match the generator by construction.

| Scenario | Duration | Behaviour (service) | Labels |
|---|---|---|---|
| steady | 900 | all normal | — |
| drift | 1200 | pg error 2%→15% linear over 360–660, held to end | ERROR_RATE pg [360, 1200] |
| burst | 900 | pg error 80% for 480–510 | ERROR_RATE pg [480, 510] |
| **outage** (new) | 900 | ledger 95% errors + new "connection refused to ledger-db" template, volume ×0.3, 480–570 | ERROR_RATE ledger [480, 570], NEW_PATTERN ledger [480, 570] |
| silence | 900 | pg volume 0 for 480–540 | SILENCE pg [480, 540] |
| new_pattern | 900 | auth injects "HSM key rotation failed kid=<uuid>" 2/s, 480–720 | NEW_PATTERN auth [480, 720] |
| latency_spike | 900 | pg latency ×15 (200→3000 ms p50-ish), 480–600 | LATENCY pg [480, 600] |
| noisy_normal | 900 | auth at a steady 3% on low volume (noisy windows) | — |
| rotation | 900 | normal; rotate at 300 and 600 | — |
| malformed_flood | 900 | normal + 50% malformed lines | — |

**Tests (`tests/test_scenarios.py`):**
- there are exactly 10 scenarios, `outage` is present, and the docstring list matches the keys
- labels lie in `[warmup_s, duration_s]` and use a valid SignalType and a known service
- `RateCurve` interpolation and edges
- generator ↔ label agreement for each labelled scenario (using a small `speed`-free offline run):
  - the error rate inside the label is well above the rate outside it
  - silence has zero lines for that service inside the label
  - the injected template is absent before the start and present inside
  - latency p95 inside the label is well above p95 outside it
- about 50% of `malformed_flood` lines return `None` from `parse_line`

---

## Step 4 — `eval/run.py` (EvalHarness): **BLOCKED**

Start conditions:
1. PRs 1 and 2/3 are merged to main.
2. Kostubh has defined the Signal/alert type, the detector call signature, `BaselineStore` and `AlertManager` (implemented or at least final signatures).

Until then I stop, and I record exactly what's needed in `docs/plans/requests-for-team.md`, without proposing a design for Kostubh.

Planned shape, to be finalized against Kostubh's real interfaces once they exist:
- **Pipeline replay:** FakeClock, events driven by virtual second (ticks continue through empty seconds so silence can be observed). The flow is:
  1. `LogGenerator.iter_lines()`
  2. `parse_line` (malformed lines counted)
  3. `TemplateMiner.add_message` gives `tid`, then `miner.is_new(tid, now=t)`
  4. TREMOR adapter: `engine.observe(event, arrival=t, template_id, is_new)`, and `engine.tick(now=t)` every virtual second. Detection reads no clock (agreed with Kostubh on 2026-09-28; exact API in `docs/DETECTION_API.md`).
  5. Baseline adapters: `WindowEngine.add_event` / `tick()`, then `detector_fn`, then the eval dedup stage
- **One `detector_fn` interface** with three adapters:
  - TREMOR: Kostubh's modules. It raises `NotImplementedError` if they're not merged, and TREMOR is then reported as n/a while the baselines still run.
  - static 5%: 60 s error rate > 5% with min events.
  - rolling-mean-only: no seasonality, no MAD, no freeze.
- **Metrics:** precision, recall, F1, mean and median delay, FP/hour, per-scenario correct. Reported overall and ERROR_RATE-only, because the baselines only cover error rate.
- **Matching rule:**
  - A TP needs the same signal_type (and service) with `label.start ≤ alert.ts ≤ label.end + grace`.
  - An alert outside every label is a FP.
  - A label with no alert is a FN.
  - Extra alerts inside an already-matched label are counted as duplicates rather than FPs.
  - The rule goes in TRADEOFFS.md.
- **CLI:** `python -m eval.run --seed 42` prints the table and deterministically rewrites `docs/EVAL.md`, with no timestamps so reruns are byte-identical.
- **Tests:** `tests/test_eval_metrics.py` with hand-computed cases:
  - TP in window, TP in grace, just outside grace is a FP
  - wrong type or service is a FP
  - missed label is a FN
  - duplicate alerts
  - overlapping labels
  - zero alerts / zero labels, where precision is undefined and shown as "—"
  - delay mean and median
  - FP/hour

## Step 5 — Docs: **BLOCKED** (follows step 4, per the agreed order)

- **`docs/ARCHITECTURE.md`:** append `### Template Miner`, `### Simulator` and `### Evaluation Harness` under "Component Details". The existing placeholder line stays; nothing else is edited.
- **`docs/TRADEOFFS.md`:** append `## Phase 2 / Phase 6 (Mokshad)`, covering:
  - one shared drain3 tree across services vs one per service
  - LRU eviction means an evicted template that returns looks new
  - the novelty-TTL definition
  - jsonpickle trust
  - the event-time `ts` param
  - the mixed JSON/text output
  - label windows after warm-up
  - the eval matching rule and duplicate handling
  - baselines being error-rate only

## `docs/plans/requests-for-team.md` (created in step 1, appended as needed)

- **Kostubh:**
  - Eval is blocked on these:
    - the Signal type and detector call signature
    - the BaselineStore and AlertManager signatures
  - FYI: the TemplateMiner API for new_pattern is `new_templates_in_window(window_s, service=)` and `is_new(id)`, and template IDs are `int` to match `TemplateHint`.
  - `alerts.py` has mid-file imports (ruff E402), which will fail CI `ruff check app/`.
- **Config owner:** add `TEMPLATE_MAX_CLUSTERS`, `TEMPLATE_RARITY_THRESHOLD`, `TEMPLATE_NOVELTY_TTL_S` and `TEMPLATE_STATE_PATH` to `Settings` and `.env.example`. Separately, `app/config.py` line 13 has trailing whitespace, which fails black.
- **Lifespan owner (`app/main.py`):** call `TemplateMiner.restore()` on startup and `persist()` on shutdown, next to the baseline.

## Risks

- **I haven't checked the current CI state yet** (Bash was down while planning). Other people's files could already fail ruff/black. I'll run the gate on clean `main` first so I only answer for my own diffs, and report anything else.
- **drain3 API drift within 0.9.x:** I'll read the installed source first. The state format is drain3's jsonpickle, which is only safe to load from our own trusted path.
- **Template text changes over time:** drain3 clusters generalize as more lines arrive, so the template text for an ID can change. IDs stay stable, which is what the hypothesis test checks, but text is not a stable key.
- **Eval runtime:** 10 scenarios × about 900 s × 3 services × about 15 lines/s is roughly 400k lines through drain3. A full eval should take tens of seconds. Tests will use shortened scenarios, and the full run gets `@pytest.mark.slow`.
- **EVAL.md headline:** the current headline ("quiet service jumping to 1%") has no scenario backing it. The regenerated EVAL.md will state only what the numbers show. A `quiet_jump` scenario can be added later if wanted.
- **Tailer integration test timing:** it could be flaky, so it uses generous waits and is marked `integration`.

## Verification (run after every step, then summarized in 2–3 lines)

```
ruff check app/ tests/ simulator/ eval/
black --check app/ tests/ simulator/ eval/
mypy app/core/ --strict
pytest
```
Additional checks per step:
- **Step 2:** `python -m simulator.gen_logs --scenario steady --offline --out /tmp/a.log` run twice gives identical output (`cmp`).
- **Step 3:** eyeball per-scenario stats (lines, error %, labels) from a small script run in the scratchpad.
- **Non-blocking:** `mypy simulator/ --strict`.
