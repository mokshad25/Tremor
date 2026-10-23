"""
TREMOR — Async log file tailer.

Responsibilities:
- Async poll loop with configurable interval (default 150ms)
- Detect rotation (inode change) and truncation (size < offset)
- Drain old handle before switching on rotation
- Buffer partial lines until newline arrives
- Tag events with service name (from filename or JSON field)
- Backpressure via bounded asyncio.Queue
- Start position: end (default) or beginning (replay/eval)

Owner: Mokshad (Phase 1)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

import structlog

if TYPE_CHECKING:
    from app.clock import Clock

log = structlog.get_logger()

# Bytes at the start of the file used to detect same-size truncate-and-rewrite.
HEAD_FINGERPRINT_BYTES = 64


class Tailer:
    def __init__(
        self,
        path: str,
        service: str,
        queue: asyncio.Queue[tuple[str, str]],
        clock: Clock,
        start_pos: str = "end",
        poll_ms: int = 150,
    ) -> None:
        self.path = Path(path)
        self.service = service
        self.queue = queue
        self.clock = clock
        self.start_pos = start_pos
        self.poll_s = poll_ms / 1000.0

        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._file: TextIO | None = None
        self._inode: int = -1
        self._offset: int = 0
        self._buffer: str = ""
        self._head: bytes = b""

    async def _open_file(self) -> bool:
        """Attempt to open the file and record its inode and offset. Returns True if successful."""
        try:
            stat = os.stat(self.path)
            self._inode = stat.st_ino

            # Using synchronous open since we only read small amounts periodically
            self._file = open(self.path, encoding="utf-8", errors="replace")  # noqa: SIM115

            if self.start_pos == "end":
                self._file.seek(0, os.SEEK_END)
            else:
                self._file.seek(0, os.SEEK_SET)

            self._offset = self._file.tell()
            self._head = b""
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            await log.aerror("tailer.open_failed", path=str(self.path), error=str(e))
            return False

    async def _check_rotation_or_truncation(self) -> bool:
        """Check if file was rotated or truncated. Returns True if we need to reopen."""
        try:
            stat = os.stat(self.path)
            if stat.st_ino != self._inode:
                return True
            if stat.st_size < self._offset:
                return True
            # A truncate + rewrite to the same (or larger) size keeps inode and size,
            # so also compare the first bytes we have already consumed.
            if self._head and self._read_head(len(self._head)) != self._head:
                return True
            if len(self._head) < HEAD_FINGERPRINT_BYTES and self._offset > len(self._head):
                self._head = self._read_head(min(HEAD_FINGERPRINT_BYTES, self._offset))
            return False
        except FileNotFoundError:
            return True

    def _read_head(self, n: int) -> bytes:
        with open(self.path, "rb") as f:
            return f.read(n)

    async def _read_lines(self) -> list[str]:
        """Read available data and return complete lines. Updates offset and buffer."""
        if not self._file:
            return []

        try:
            # We yield to the event loop just in case
            await asyncio.sleep(0)
            data = self._file.read()
            if not data:
                return []

            self._offset = self._file.tell()

            text = self._buffer + data

            if "\n" in text:
                lines = text.split("\n")
                self._buffer = lines.pop()
                return lines
            else:
                self._buffer = text
                return []

        except Exception as e:
            await log.aerror("tailer.read_error", path=str(self.path), error=str(e))
            return []

    async def _loop(self) -> None:
        """Main tailing loop."""
        while self._running:
            if self._file is None:
                if await self._open_file():
                    await log.ainfo("tailer.opened", path=str(self.path), inode=self._inode)
                else:
                    await asyncio.sleep(self.poll_s)
                    continue

            if await self._check_rotation_or_truncation():
                await log.ainfo("tailer.rotated_or_truncated", path=str(self.path))
                lines = await self._read_lines()
                await self._process_lines(lines)

                if self._file is not None:
                    self._file.close()
                self._file = None
                self._buffer = ""
                self.start_pos = "beginning"
                continue

            lines = await self._read_lines()
            if lines:
                await self._process_lines(lines)

            await asyncio.sleep(self.poll_s)

    async def _process_lines(self, lines: list[str]) -> None:
        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                # Add backpressure timeout
                await asyncio.wait_for(self.queue.put((self.service, line)), timeout=1.0)
            except TimeoutError:
                await log.awarn("tailer.queue_full", path=str(self.path), dropped=1)

    async def run(self) -> None:
        """Start the tailer loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """Stop the tailer loop and clean up."""
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

        if self._file:
            self._file.close()
            self._file = None
