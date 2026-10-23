"""
TREMOR — Latency anomaly detector.

Responsibilities:
- Only active when duration_ms is present in log events
- p95 per window vs baseline p95 with robust z logic
- Same hysteresis and confirmation as error-rate detector

Owner: Kostubh (Phase 2)
"""

from __future__ import annotations

# TODO: Implement in Phase 2
