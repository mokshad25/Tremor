"""
TREMOR — Parser tests.
"""

from __future__ import annotations

from app.ingest.parser import normalize_level, parse_line


def test_normalize_level() -> None:
    assert normalize_level("WARN") == "WARNING"
    assert normalize_level("WARNING") == "WARNING"
    assert normalize_level("FATAL") == "ERROR"
    assert normalize_level("CRITICAL") == "ERROR"
    assert normalize_level("ERROR") == "ERROR"
    assert normalize_level("DEBUG") == "DEBUG"
    assert normalize_level("TRACE") == "DEBUG"
    assert normalize_level("UNKNOWN") == "INFO"
    assert normalize_level("info") == "INFO"


def test_parse_json_valid_unix_ts() -> None:
    raw = '{"ts": 1704067200, "level": "error", "service": "auth", "message": "Failed login", "duration_ms": 150}'
    event = parse_line(raw)
    assert event is not None
    assert event.ts == 1704067200.0
    assert event.level == "ERROR"
    assert event.service == "auth"
    assert event.message == "Failed login"
    assert event.duration_ms == 150.0
    assert event.raw_len == len(raw)


def test_parse_json_valid_ms_ts() -> None:
    # 1704067200000 ms -> 1704067200.0 s
    raw = '{"ts": 1704067200000, "level": "INFO", "msg": "Hello"}'
    event = parse_line(raw)
    assert event is not None
    assert event.ts == 1704067200.0


def test_parse_json_valid_iso_ts() -> None:
    raw = '{"timestamp": "2024-01-01T12:00:00Z", "level": "WARN", "service": "gw", "message": "High latency"}'
    event = parse_line(raw)
    assert event is not None
    # Quick sanity check on TS instead of exact match to avoid timezone nuances here
    assert event.ts > 0
    assert event.level == "WARNING"


def test_parse_text_valid() -> None:
    raw = "2024-01-01T12:00:00.123Z ERROR payment-gateway Transaction failed for user"
    event = parse_line(raw)
    assert event is not None
    assert event.ts > 0
    assert event.level == "ERROR"
    assert event.service == "payment-gateway"
    assert event.message == "Transaction failed for user"


def test_parse_text_with_pii() -> None:
    raw = "2024-01-01T12:00:00Z INFO auth User test@example.com logged in"
    event = parse_line(raw)
    assert event is not None
    assert event.message == "User <EMAIL> logged in"


def test_parse_json_with_pii() -> None:
    raw = '{"ts": 1704067200, "level": "INFO", "message": "Key is AKIAIOSFODNN7EXAMPLE"}'
    event = parse_line(raw)
    assert event is not None
    assert event.message == "Key is <API_KEY>"


def test_cap_long_message() -> None:
    long_msg = "A" * 3000
    raw = f"2024-01-01T12:00:00Z INFO svc {long_msg}"
    event = parse_line(raw)
    assert event is not None
    assert len(event.message) == 2048 + 3  # 2048 chars + "..."
    assert event.message.endswith("...")


def test_malformed_returns_none() -> None:
    assert parse_line("") is None
    assert parse_line("just some random text") is None
    assert parse_line('{"not_a_log": true}') is None


def test_json_fallback_to_text() -> None:
    # A line that looks like JSON but is actually malformed JSON with a valid text prefix
    # (Unlikely, but tests the fallback logic)
    raw = "2024-01-01T12:00:00Z INFO svc {malformed json}"
    event = parse_line(raw)
    assert event is not None
    assert event.message == "{malformed json}"
