"""
TREMOR — Log line parser.

Responsibilities:
- Auto-detect plain text vs JSON lines per line
- Plain text format: 2026-01-01T12:00:00.123Z ERROR service-name msg...
- Output LogEvent(ts, level, service, message, duration_ms|None, raw_len)
- Normalize levels: WARN→WARNING, FATAL/CRITICAL→ERROR
- Malformed lines counted and sampled, never fatal
- Cap message length (default 2 KB)

Owner: Mokshad (Phase 1)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.ingest.redact import redact


@dataclass(frozen=True, slots=True)
class LogEvent:
    """Parsed log event — the common currency of the pipeline."""

    ts: float  # Unix timestamp
    level: str  # Normalized: DEBUG, INFO, WARNING, ERROR
    service: str
    message: str
    duration_ms: float | None = None
    raw_len: int = 0


# Common log prefix regex: ISO8601 LEVEL SERVICE message...
# Example: 2026-01-01T12:00:00.123Z ERROR payment-gateway Transaction failed...
TEXT_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"([A-Z]+)\s+"
    r"([^\s]+)\s+"
    r"(.*)$"
)

MAX_MESSAGE_LEN = 2048


def normalize_level(level: str) -> str:
    """Normalize log levels to standard Python levels."""
    level = level.upper()
    if level in ("WARN", "WARNING"):
        return "WARNING"
    if level in ("FATAL", "CRITICAL", "ERROR"):
        return "ERROR"
    if level in ("DEBUG", "TRACE"):
        return "DEBUG"
    return "INFO"


def _parse_ts(ts_str: str) -> float:
    """Parse ISO8601 string to Unix timestamp."""
    try:
        # datetime.fromisoformat handles Python 3.11+ Z suffix nicely
        ts_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        return dt.timestamp()
    except ValueError:
        return 0.0


def _cap_message(msg: str) -> str:
    if len(msg) > MAX_MESSAGE_LEN:
        return msg[:MAX_MESSAGE_LEN] + "..."
    return msg


def parse_line(raw: str, default_service: str = "unknown") -> LogEvent | None:
    """
    Parse a log line (JSON or plain text) into a LogEvent.
    Returns None if the line is completely unparseable (malformed).
    Applies PII redaction to the message before returning.
    """
    raw = raw.strip()
    if not raw:
        return None

    raw_len = len(raw)

    # Attempt JSON parsing first if it looks like JSON
    if raw.startswith("{") and raw.endswith("}"):
        try:
            data: dict[str, Any] = json.loads(raw)
            # Basic validation of required fields
            ts_val = data.get("timestamp") or data.get("ts") or data.get("time")
            if ts_val is None:
                raise ValueError("Missing timestamp")

            # Handle numeric vs string timestamps
            if isinstance(ts_val, (int, float)):
                ts = float(ts_val)
                # Heuristic for ms vs s
                if ts > 2e9:  # > year 2033 in seconds, likely ms
                    ts /= 1000.0
            else:
                ts = _parse_ts(str(ts_val))

            if ts == 0.0:
                raise ValueError("Invalid timestamp format")

            level = str(data.get("level", "INFO"))
            service = str(data.get("service", default_service))
            message = str(data.get("message", data.get("msg", "")))
            duration_ms = data.get("duration_ms")

            if duration_ms is not None:
                try:
                    duration_ms = float(duration_ms)
                except (ValueError, TypeError):
                    duration_ms = None

            return LogEvent(
                ts=ts,
                level=normalize_level(level),
                service=service,
                message=redact(_cap_message(message)),
                duration_ms=duration_ms,
                raw_len=raw_len,
            )
        except (json.JSONDecodeError, ValueError):
            # Fall back to text parsing if JSON is malformed
            pass

    # Plain text parsing fallback
    match = TEXT_LOG_RE.match(raw)
    if match:
        ts_str, level_str, service_str, message_str = match.groups()
        ts = _parse_ts(ts_str)
        if ts > 0:
            return LogEvent(
                ts=ts,
                level=normalize_level(level_str),
                service=service_str,
                message=redact(_cap_message(message_str)),
                duration_ms=None,
                raw_len=raw_len,
            )

    # Malformed line
    return None
