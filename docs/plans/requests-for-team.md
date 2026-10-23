# Requests for the team

Changes Mokshad needs in files owned by others. Mokshad does not edit these files directly.

---

## Kostubh (baseline / detectors / severity / alerts)

### Blocking: eval harness (Phase 6, step 4)

`eval/run.py` replays scenarios through parser → window → baseline → detectors → alert manager.

**Signatures received** (`docs/DETECTION_API.md`, 2026-09-28): `DetectionEngine.observe(event, arrival, template_id, is_new_template)` / `tick(now) -> TickResult`, `Signal`, `AlertManager.process`, and the `Detector` protocol. Eval starts once Kostubh's first PR (engine, baseline, error rate, silence, alerts) and my templates and simulator PRs are merged to main.

### DETECTION_API.md questions: answered from main @ ba29522 (2026-09-28)

1. **`is_new` meaning: still OPEN.** `detectors/base.py` still documents `is_new` as "the miner created this template on this line", and `NewPatternDetector` is still a stub. **Kostubh:** when you write it, use the shared miner's `is_new` as-is: first seen after warm-up, or a rare template surging (3+ in 60 s), held for 300 s. Please update both docstrings to match.
2. **Per-service: ANSWERED.** `DetectionEngine.observe()` does not filter by `event.service`; `service` only labels alerts and baselines. The pipeline must route each event to its own service's engine. Eval does this. A single `"*"` engine misses a single service going silent, and a test proves it (`test_tremor_whole_stream_misses_single_service_silence`). **`app/main.py` owner:** create one engine per service.
3. **Warm-up: ANSWERED.** `warmup_ticks = 30` ticks with n ≥ 20, so about 30–35 s, well inside my 360 s clean prefix. `warmup_seconds` is unused by detection.
4. **`TemplateHint.template_id` is `str`: ANSWERED** (`alerts.py:56`).

### Finding from eval: ERROR_RATE baseline under-learns on low-volume services (Kostubh)

In `docs/EVAL.md` (seed 42), all 12 TREMOR false positives are **INFO**-level ERROR_RATE alerts (z ≈ 3.0–3.7) on low-volume services: 6 on noisy_normal's auth-service (~2 lines/s), the rest on ledger (~5 lines/s).

The learned baseline is too low. auth-service really runs at 3% errors in noisy_normal, but `mu` is 0.8–2.2%. Thirty warm-up ticks of *overlapping* 30 s windows are roughly one minute of data, and gated updates can't pull `mu` back up afterwards.

At WARNING+ TREMOR has **0 false positives** (7/10 scenarios fully correct), so nothing pages, but INFO is noisy. Options:
- a longer `warmup_ticks` (e.g. 300)
- sampling non-overlapping windows during warm-up
- a gentler update gate

`python -m eval.run --seed 42` will show the effect.

### Agreed with Kostubh (recorded 2026-09-28)

1. **No clock in detection.** Time is always an argument: `engine.observe(event, arrival, ...)` and `engine.tick(now)`. For eval, pass the FakeClock time as both `arrival` and `now`, which makes replays fully deterministic.
2. **One shared `TemplateMiner` per process.** The pipeline calls `add_message` once per event and passes `template_id` plus the `is_new` result into `engine.observe()`. Detection never calls the miner.
3. **The miner is the only definition of "new".** The new-pattern detector keeps no seen-set of its own. It only adds alert policy on top:
   - novelty is ignored during a 30-tick warm-up
   - WARNING if the event level is ERROR, INFO otherwise
   - one incident per template id, resolved after 60 s without that template

   `new_templates_in_window()` stays Mokshad's, for eval and the UI.
4. **Signal names are final:** `ERROR_RATE`, `SILENCE`, `NEW_PATTERN`, `LATENCY` (the `SignalType` enum in `alerts.py`).
5. **Pipeline call pattern (Mokshad's side):**
   ```python
   tid = miner.add_message(event.message, service=event.service, ts=event.ts)
   engine.observe(event, arrival, template_id=tid, is_new=miner.is_new(tid, now=arrival))
   ```
   Passing `now=` explicitly keeps `is_new` deterministic. The exact `observe()` argument names will follow `docs/DETECTION_API.md`.

### Delivered: TemplateMiner API (`app/core/templates.py`)

Kostubh asked for `add_message(message) -> str` returning an id that is stable per pattern. That is done on `feat/mokshad-templates`:

- `add_message(message) -> str` returns ids like `"T12"`. The extra keyword-only args are optional: `service="_global"` and `ts=None` (defaults to `clock.now()`).
- Every message of the same pattern gets the same id. Numbers, UUIDs, IPs, hex and `txn_`/`acct_`-style ids, and redacted PII (`<EMAIL>`, `<CARD>`…) are masked first.
- Ids are stable for the whole run, and across `persist`/`restore`. The one exception: if more than `max_clusters` patterns (default 1000) exist, the least-recently-used pattern is evicted and gets a new id if it comes back.
- **Kostubh:** please change `alerts.TemplateHint.template_id` to `str`, as agreed.

Optional extras, if they save you work:

- `is_new(template_id, now=None) -> bool`: true when the template was first seen after warm-up, or when a historically rare template (below the rarity threshold) surges, meaning it appears at least 3 times within 60 s. A single reappearance of an occasional line is not new. The flag stays set for `novelty_ttl_s` (300 s).
- `new_templates_in_window(window_s, *, service=None) -> dict[str, int]`: returns `{template_id: count}` for new templates seen in the last `window_s` seconds.
- `count_in_window(template_id, window_s, *, service=None) -> int`
- `get_top_templates(n, *, service=None, window_s=None) -> list[TemplateInfo]`: for alert root-cause hints.
- `tick()`: call once per tick to evict old window buckets, the same as `WindowEngine.tick()`.

### Lint

- `app/core/alerts.py` has imports in the middle of the file (`from dataclasses import ...` after the enums). Ruff E402 will fail CI's `ruff check app/`.

---

## Config owner (`app/config.py`, `.env.example`)

- Please add settings for the template miner:
  - `TEMPLATE_MAX_CLUSTERS` (default 1000)
  - `TEMPLATE_RARITY_THRESHOLD` (default 0.001)
  - `TEMPLATE_NOVELTY_TTL_S` (default 300)
  - `TEMPLATE_STATE_PATH` (e.g. `./state/templates.json`)
- `app/config.py` line 13 (`class Settings(BaseSettings):   `) has trailing whitespace, so `black --check` fails.

---

## Everyone: CI lint status after `feat/mokshad-templates`

I fixed all ruff and black issues in my own files (`app/ingest/*`, `app/core/window.py`, `app/core/templates.py`, and their tests). These remain, and each one alone keeps CI red:

| File | ruff | black | Likely owner |
|---|---|---|---|
| `app/sinks/base.py` | 14 | reformat | Varad |
| `app/sinks/dryrun.py` | 2 | reformat | Varad |
| `tests/test_sinks.py` | 6 | reformat | Varad |
| `app/api/routes.py` | — | reformat | Sara |
| `app/main.py` | 1 | reformat | ? |

(`app/core/alerts.py` and `app/config.py` were fixed on main in ba29522.)

Most of these clear with `ruff check --fix <file> && black <file>`.

---

## Lifespan owner (`app/main.py`)

- On startup, construct a `TemplateMiner(clock, ...)` and `await miner.restore(settings.template_state_path)` if the file exists.
- On shutdown, `await miner.persist(...)` next to the baseline persist.
