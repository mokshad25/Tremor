"""
TREMOR — Tailer tests.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
from typing import TYPE_CHECKING

import pytest

from app.clock import SystemClock
from app.ingest.tailer import Tailer

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def temp_log_file() -> Iterator[str]:
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    yield path
    with contextlib.suppress(FileNotFoundError):
        os.remove(path)


@pytest.mark.asyncio
async def test_tailer_reads_from_beginning(temp_log_file: str) -> None:
    # Write some initial lines
    with open(temp_log_file, "w") as f:
        f.write("line1\nline2\n")

    queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
    tailer = Tailer(
        temp_log_file, "test_svc", queue, SystemClock(), start_pos="beginning", poll_ms=10
    )

    await tailer.run()

    # Give it a moment to read
    await asyncio.sleep(0.05)

    # Should read line1 and line2
    svc1, line1 = await queue.get()
    svc2, line2 = await queue.get()

    assert svc1 == "test_svc"
    assert line1 == "line1"
    assert line2 == "line2"

    await tailer.stop()


@pytest.mark.asyncio
async def test_tailer_reads_from_end(temp_log_file: str) -> None:
    # Write some initial lines
    with open(temp_log_file, "w") as f:
        f.write("line1\nline2\n")

    queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
    tailer = Tailer(temp_log_file, "test_svc", queue, SystemClock(), start_pos="end", poll_ms=10)

    await tailer.run()
    await asyncio.sleep(0.05)

    assert queue.empty()

    # Append a new line
    with open(temp_log_file, "a") as f:
        f.write("line3\n")

    await asyncio.sleep(0.05)

    svc, line3 = await queue.get()
    assert line3 == "line3"

    await tailer.stop()


@pytest.mark.skipif(os.name == "nt", reason="Windows locks open files, preventing rename")
@pytest.mark.asyncio
async def test_tailer_rotation(temp_log_file: str) -> None:
    # Initial file
    with open(temp_log_file, "w") as f:
        f.write("line1\n")

    queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
    tailer = Tailer(
        temp_log_file, "test_svc", queue, SystemClock(), start_pos="beginning", poll_ms=10
    )

    await tailer.run()
    await asyncio.sleep(0.05)

    svc, line1 = await queue.get()
    assert line1 == "line1"

    # Rotate (rename old file, create new one)
    os.rename(temp_log_file, temp_log_file + ".1")
    with open(temp_log_file, "w") as f:
        f.write("line2\n")

    await asyncio.sleep(0.05)

    svc, line2 = await queue.get()
    assert line2 == "line2"

    await tailer.stop()
    with contextlib.suppress(OSError):
        os.remove(temp_log_file + ".1")


@pytest.mark.skipif(os.name == "nt", reason="Windows locks open files, preventing truncation")
@pytest.mark.asyncio
async def test_tailer_truncation(temp_log_file: str) -> None:
    with open(temp_log_file, "w") as f:
        f.write("line1\n")

    queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
    tailer = Tailer(
        temp_log_file, "test_svc", queue, SystemClock(), start_pos="beginning", poll_ms=10
    )

    await tailer.run()
    await asyncio.sleep(0.05)
    await queue.get()  # pop line1

    # Truncate
    with open(temp_log_file, "w") as f:
        f.write("line2\n")

    await asyncio.sleep(0.05)

    svc, line2 = await queue.get()
    assert line2 == "line2"

    await tailer.stop()


@pytest.mark.asyncio
async def test_tailer_partial_line_buffering(temp_log_file: str) -> None:
    queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue()
    tailer = Tailer(
        temp_log_file, "test_svc", queue, SystemClock(), start_pos="beginning", poll_ms=10
    )

    with open(temp_log_file, "w") as f:
        f.write("partial")  # no newline

    await tailer.run()
    await asyncio.sleep(0.05)

    assert queue.empty()

    with open(temp_log_file, "a") as f:
        f.write("_line\n")

    await asyncio.sleep(0.05)

    svc, line = await queue.get()
    assert line == "partial_line"

    await tailer.stop()
