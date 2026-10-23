# TREMOR — Detection API

Public interface of `app/core/` detection (owner: Kostubh). Everything here is pure and
synchronous: no I/O, and **detection never reads a clock**. All time is passed in.

- `engine.observe(event, arrival, ...)`: once per parsed line, with its arrival time
- `engine.tick(now)`: once per second

`arrival` and `now` are plain float seconds from the same clock (`SystemClock` in
production, `FakeClock` in tests and eval). The timestamp inside the log line
(`LogEvent.ts`) is **not** used by detection.

Signal names are the existing `SignalType` values: `ERROR_RATE`, `SILENCE`,
`NEW_PATTERN`, `LATENCY`. Severities are `Severity.INFO < WARNING < HIGH < CRITICAL`.

## Module map

| Module | Public names |
|---|---|
| `app/core/engine.py` | `DetectionEngine`, `Tick`, `TickResult` |
| `app/core/alerts.py` | `AlertManager`, `Alert`, `Signal`, `AlertStatus`, `SignalType`, `TimelineEvent`, `TemplateHint` |
| `app/core/detectors/base.py` | `Detector`, `Observation`, `TickContext`, `TemplateMinerLike` |
| `app/core/baseline.py` | `BaselineStore`, `Baseline`, `BaselineState` |
| `app/core/severity.py` | `Severity`, `score` |
| `app/core/arrivals.py` | `ArrivalWindow` |

## DetectionEngine (`app/core/engine.py`)

```python
class DetectionEngine:
    def __init__(
        self,
        cfg: Settings,
        service: str = "*",                      # "*" = the whole stream
        id_factory: Callable[[], str] | None = None,  # alert/incident ids; uuid4 hex by default
    ) -> None: ...

    def observe(
        self,
        event: LogEvent,
        arrival: float,
        template_id: str | None = None,
        is_new_template: bool = False,
    ) -> None:
        """Record one parsed line. `arrival` is when TREMOR received it, not event.ts.
        template_id / is_new_template come from the shared TemplateMiner, which the
        pipeline calls once per event. Detection never calls the miner."""

    def tick(self, now: float) -> TickResult:
        """Run every detector for the second ending at `now` (window = (now - 30, now]).
        Call exactly once per second, including when no lines arrived."""

    def ack(self, incident_id: str, now: float) -> Alert:
        """Status ACKED. Raises KeyError if the incident is not open."""

    def silence(self, incident_id: str, until: float, now: float) -> Alert:
        """Status SILENCED; nothing is emitted for that key until `until`, except RESOLVED.
        Raises KeyError if the incident is not open."""

    def active(self, now: float) -> list[Alert]:
        """Snapshots of all open incidents."""

    warmed_up: bool            # property: error-rate baseline seeded
    baselines: BaselineStore   # read-only inspection
```

Malformed lines (parser returned `None`) are never passed to `observe`.

## Tick and TickResult (`app/core/engine.py`)

```python
@dataclass(frozen=True, slots=True)
class Tick:
    """Per-second snapshot for the live chart; produced on every tick."""
    ts: str                  # UTC ISO 8601 of `now`
    error_rate: float | None # None when no lines are in the window
    baseline: float | None   # always mu: the value this tick's z was judged against
    z: float | None          # None while learning or insufficient
    lines: int               # lines in the 30 s window
    state: Literal["learning", "insufficient", "active", "incident"]
                             # precedence: incident > insufficient > learning > active
    severity: str | None     # highest severity among open incidents, e.g. "WARNING"
    is_anomaly: bool         # an incident is open

    def to_dict(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class TickResult:
    tick: Tick
    alerts: list[Alert]                  # emitted on this tick, in order (may be empty)
    error_rate: ErrorRateReading | None  # full numbers (n, errors, mu, sigma_eff, z, ...)
```

## Signal (`app/core/alerts.py`)

The only thing detectors hand to the alert lifecycle.

```python
@dataclass(frozen=True, slots=True)
class Signal:
    """One detector's verdict for one key on one tick."""
    signal_type: SignalType
    service: str
    severity: Severity | None     # None = nothing wrong on this tick
    clear: bool | None = None     # True counts toward resolution, False resets the count,
                                  # None is neutral (e.g. insufficient data)
    resolve: bool = False         # detector's own rule says the incident is over
    template_id: str | None = None  # NEW_PATTERN only; part of the dedup key
    value: float | None = None    # error rate, p95 latency (ms) or silent seconds
    baseline: float | None = None # mu the value was judged against
    z_score: float | None = None
    lines: int | None = None
    errors: int | None = None
    reason: str = ""              # e.g. "error rate 9.4% vs baseline 1.9% over the last 30 s"
```

## Detector protocol (`app/core/detectors/base.py`)

```python
class Detector(Protocol):
    """Built as `Detector(cfg: Settings, service: str = "*")`. The engine calls observe()
    for every line and evaluate() once per tick, and hands the Signals to AlertManager."""
    signal_type: SignalType

    def observe(self, obs: Observation) -> None:
        """Record one line. Must be cheap: called for every event."""

    def evaluate(self, ctx: TickContext) -> list[Signal]:
        """This tick's verdicts, one Signal per key (usually one)."""

@dataclass(frozen=True, slots=True)
class Observation:
    arrival: float
    level: str                     # normalized parser level; "ERROR" is the error signal
    duration_ms: float | None = None
    template_id: str | None = None # e.g. "T12"
    is_new_template: bool = False  # the miner created this template on this line
    warmed_up: bool = False        # error-rate baseline was seeded when the line arrived

@dataclass(frozen=True, slots=True)
class TickContext:
    now: float
    window: ArrivalWindow          # lines that arrived in (now - 30, now]
    warmed_up: bool                # error-rate baseline seeded before this tick
    is_open: Callable[[SignalType, str | None], bool]  # (signal, template_id) -> open?
```

Detectors:

| Class | Signal | Rule |
|---|---|---|
| `ErrorRateDetector` | `ERROR_RATE` | z of r = errors/n vs EWMA baseline; CRITICAL if r > 50% with n >= 20 |
| `SilenceDetector` | `SILENCE` | after warm-up, HIGH if no line for 10 s; resolves when lines return |
| `NewPatternDetector` | `NEW_PATTERN` | after warm-up, `is_new_template` opens an incident per template id: WARNING if the line is ERROR, else INFO; resolves after 60 s without that template |
| `LatencyDetector` | `LATENCY` | z of p95 `duration_ms` over 30 s (>= 20 samples) vs EWMA baseline |

New-pattern uses **only** the miner's `is_new` flag to decide what is new; it keeps no
seen-set of its own.

## TemplateMinerLike (`app/core/detectors/base.py`)

What the pipeline (not detection) needs from the shared `TemplateMiner`:

```python
class TemplateMinerLike(Protocol):
    def add_message(self, message: str, *, service: str = "_global", ts: float | None = None) -> str:
        """Template id for this message, e.g. "T12", stable per pattern for the whole run."""

    def is_new(self, template_id: str) -> bool:
        """True iff the most recent add_message() call created `template_id`."""
```

## BaselineStore (`app/core/baseline.py`)

```python
class BaselineStore:
    """Keyed store of Baseline objects, one per (service, signal), e.g. ("*", "ERROR_RATE").
    Detectors own their Baseline and register it here. Warm-up for a service means its
    ERROR_RATE baseline is seeded."""
    def register(self, service: str, signal: str, baseline: Baseline) -> Baseline: ...
    def get(self, service: str, signal: str) -> Baseline | None: ...
    def is_warm(self, service: str) -> bool: ...
    def states(self) -> dict[tuple[str, str], BaselineState]: ...

@dataclass(frozen=True, slots=True)
class BaselineState:
    mu: float | None
    sigma: float | None
    seeded: bool
    warmup_count: int

class Baseline:
    """Warm-up seeded EWMA mean/variance with a gated update and a pluggable noise floor."""
    def __init__(self, alpha: float, warmup_ticks: int, sigma_min: float,
                 noise_floor: Callable[[float, int], float], max_update_z: float) -> None: ...
    seeded: bool; mu: float | None; sigma: float | None      # properties
    def add_warmup(self, value: float) -> None: ...
    def sigma_eff(self, n: int) -> float: ...                # max(sigma, floor(mu, n), sigma_min)
    def z(self, value: float, n: int) -> float: ...
    def update(self, value: float, z: float, incident_open: bool) -> bool: ...
    def state(self) -> BaselineState: ...
```

## AlertManager (`app/core/alerts.py`)

```python
class AlertManager:
    def __init__(self, cfg: Settings, id_factory: Callable[[], str] | None = None) -> None: ...

    def process(self, sig: Signal, now: float) -> list[Alert]:
        """Advance the incident for sig's key (signal_type, service, template_id).
        Emits OPEN when an incident opens, ESCALATED when severity rises above the highest
        severity already emitted, RESOLVED after clear_windows (10) consecutive clear ticks
        or when sig.resolve is set. Drops and rebounds below the peak emit nothing.
        Re-opening within alert_cooldown_s (60 s) of resolving reuses the incident_id."""

    def ack(self, incident_id: str, now: float) -> Alert: ...
        # status ACKED; a later escalation emits ESCALATED and clears the ack
    def silence(self, incident_id: str, until: float, now: float) -> Alert: ...
        # status SILENCED; key keeps tracking, emits nothing until `until` except RESOLVED
    def is_open(self, signal_type: SignalType, service: str = "*",
                template_id: str | None = None) -> bool: ...
    def active(self, now: float) -> list[Alert]: ...
    def highest_open_severity(self) -> Severity | None: ...
```

`Alert` keeps its existing fields and gains optional ones: `incident_id`, `value`,
`baseline`, `z_score`, `lines`, `errors`, `reason`, `template_id`. `Alert.severity` is the
severity name (`"INFO"` ... `"CRITICAL"`); `created_at`/`updated_at` are the `now` values
passed in. Each emitted `Alert` has a fresh `id`; alerts for the same incident share
`incident_id`.

## Example: eval replay on FakeClock

```python
from app.clock import FakeClock
from app.config import Settings
from app.core.alerts import Alert
from app.core.detectors.base import TemplateMinerLike
from app.core.engine import DetectionEngine
from app.ingest.parser import parse_line


def replay(lines: list[tuple[float, str]], miner: TemplateMinerLike) -> list[Alert]:
    """lines: (arrival_s, raw_line) sorted by arrival."""
    clock = FakeClock(start=lines[0][0])
    engine = DetectionEngine(Settings(_env_file=None))
    alerts: list[Alert] = []
    next_tick = clock.now() + 1.0

    for arrival, raw in lines:
        while arrival > next_tick:  # tick every second, including empty ones
            clock.set(next_tick)
            alerts += engine.tick(clock.now()).alerts
            next_tick += 1.0
        clock.set(arrival)
        event = parse_line(raw)
        if event is None:  # malformed lines never reach detection
            continue
        tid = miner.add_message(event.message, service=event.service, ts=event.ts)
        engine.observe(event, clock.now(), template_id=tid, is_new_template=miner.is_new(tid))

    clock.set(next_tick)
    alerts += engine.tick(clock.now()).alerts
    return alerts
```

A line arriving exactly on a tick boundary (`arrival == next_tick`) is observed before
that tick and is inside its window.
