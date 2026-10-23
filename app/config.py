"""
TREMOR — Application configuration via pydantic-settings.

All configuration is driven by environment variables with sane defaults.
See .env.example for the full list.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings, loaded from environment / .env file."""

    # ── Ingestion ─────────────────────────────────────────────────────
    log_paths: str = "./sample/app.log"
    tail_start: str = "end"  # "end" | "beginning"
    poll_interval_ms: int = 150
    lateness_s: int = 5

    # ── Windows & Baseline ───────────────────────────────────────────
    windows_s: str = "10,60,300"
    warmup_seconds: int = 300  # not used by detection; warm-up counts ticks (warmup_ticks)
    min_events: int = 20  # min lines (or latency samples) in the detection window per tick

    # ── Detection baseline (EWMA) ────────────────────────────────────
    detection_window_s: int = 30  # arrival-time window for error rate and latency p95
    warmup_ticks: int = 30  # ticks with n >= min_events used to seed the baseline
    alpha: float = 0.01  # EWMA smoothing factor
    sigma_min: float = 0.01  # absolute floor on sigma_eff for error rate
    baseline_update_max_z: float = 2.0  # baseline only learns from ticks with z below this

    # ── Severity Thresholds ──────────────────────────────────────────
    z_info: float = 3.0  # was 2.0
    z_warn: float = 5.0  # was 3.0
    z_high: float = 8.0  # was 4.0
    z_crit: float = 6.0  # not used by detection: CRITICAL is the rate_ceiling rule
    rate_ceiling: float = 0.5
    clear_z: float = 2.0  # was 1.5
    clear_windows: int = 10  # was 3; now counts consecutive 1 s ticks

    # ── Silence ──────────────────────────────────────────────────────
    silence_seconds: int = 10  # was 30

    # ── Latency ──────────────────────────────────────────────────────
    latency_percentile: float = 0.95
    latency_floor_frac: float = 0.1  # sigma_eff >= this fraction of the baseline p95
    latency_sigma_min_ms: float = 1.0  # keeps z finite when baseline p95 is 0 ms

    # ── New pattern ──────────────────────────────────────────────────
    new_pattern_resolve_s: int = 60  # resolve after this long without the template

    # ── Alerts ───────────────────────────────────────────────────────
    alert_cooldown_s: int = 60  # was 300

    # ── AWS ──────────────────────────────────────────────────────────
    sns_topic_arn: str = ""
    cw_log_group: str = "/tremor/alerts"
    cw_log_stream: str = "default"
    cw_namespace: str = "Tremor"
    aws_endpoint_url: str = ""

    # ── Modes ────────────────────────────────────────────────────────
    dry_run: bool = False
    demo_mode: bool = False

    # ── Database ─────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./tremor.db"

    # ── Server ───────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: str = "*"

    # ── Logging ──────────────────────────────────────────────────────
    log_level: str = "INFO"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False, "extra": "ignore"}

    @property
    def window_sizes(self) -> list[int]:
        """Parse WINDOWS_S into a list of integers."""
        return [int(w.strip()) for w in self.windows_s.split(",")]

    @property
    def log_file_paths(self) -> list[str]:
        """Parse LOG_PATHS into a list of file paths."""
        return [p.strip() for p in self.log_paths.split(",")]

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse CORS_ORIGINS into a list."""
        return [o.strip() for o in self.cors_origins.split(",")]


# Singleton — import this throughout the app
settings = Settings()
