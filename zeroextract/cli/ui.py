"""Interactive terminal UI and progress visualization for ZeroExtract."""

from __future__ import annotations

import io
import math
import os
import shutil
import sys
import time
from typing import TextIO


class TerminalUI:
    """Terminal progress display and status renderer."""

    def __init__(
        self,
        stream: TextIO | None = None,
        quiet: bool = False,
        verbose: bool = False,
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self.quiet = quiet
        self.verbose = verbose
        self._last_render_time = 0.0
        self._is_tty = hasattr(self.stream, "isatty") and self.stream.isatty()

        # Check for unicode block character support
        encoding = getattr(self.stream, "encoding", "utf-8") or "utf-8"
        try:
            "█".encode(encoding)
            self._fill_char = "█"
            self._empty_char = "░"
        except (UnicodeEncodeError, LookupError):
            self._fill_char = "="
            self._empty_char = "-"

    def format_throughput(self, bytes_per_sec: float) -> str:
        """Formats byte transfer rate as a human-readable throughput string."""
        if math.isinf(bytes_per_sec) or math.isnan(bytes_per_sec) or bytes_per_sec <= 0:
            return "0.00 B/s"

        units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"]
        rate = float(bytes_per_sec)
        idx = 0
        while rate >= 1024.0 and idx < len(units) - 1:
            rate /= 1024.0
            idx += 1

        return f"{rate:.2f} {units[idx]}"

    def format_eta(self, seconds_remaining: float) -> str:
        """Formats remaining time as MM:SS or --:-- on unknown."""
        if math.isinf(seconds_remaining) or math.isnan(seconds_remaining) or seconds_remaining < 0:
            return "--:--"

        secs = int(seconds_remaining)
        if secs >= 3600:
            hours = secs // 3600
            mins = (secs % 3600) // 60
            s = secs % 60
            return f"{hours:02d}:{mins:02d}:{s:02d}"

        mins = secs // 60
        s = secs % 60
        return f"{mins:02d}:{s:02d}"

    def render_error(self, msg: str) -> None:
        """Renders an error message to the output stream."""
        err_msg = f"[ERROR] {msg}\n"
        try:
            self.stream.write(err_msg)
            self.stream.flush()
        except Exception:
            pass

    def render_info(self, msg: str) -> None:
        """Renders an informational message."""
        if self.quiet:
            return
        try:
            self.stream.write(f"[INFO] {msg}\n")
            self.stream.flush()
        except Exception:
            pass

    def render_progress(
        self,
        current_bytes: int,
        total_bytes: int,
        current_member: str = "",
        speed: float = 0.0,
        eta: float = 0.0,
        force: bool = False,
    ) -> None:
        """Renders the extraction progress bar and stats."""
        if self.quiet:
            return

        now = time.monotonic()
        if not force and current_bytes < total_bytes and (now - self._last_render_time < 0.1):
            return
        self._last_render_time = now

        ratio = (current_bytes / total_bytes) if total_bytes > 0 else 1.0
        ratio = max(0.0, min(1.0, ratio))
        pct = ratio * 100.0

        speed_str = self.format_throughput(speed)
        eta_str = self.format_eta(eta)

        cols = 80
        try:
            cols = shutil.get_terminal_size((80, 20)).columns
        except Exception:
            pass
        cols = max(30, cols)

        prefix = f"{pct:5.1f}% |"
        suffix = f"| {speed_str} ETA {eta_str}"

        # If terminal is very narrow or redirected non-tty
        if not self._is_tty:
            if force or (now - getattr(self, "_last_batch_time", 0.0) >= 1.0):
                self._last_batch_time = now
                self.stream.write(f"Progress: {pct:5.1f}% ({current_bytes}/{total_bytes} bytes) - {speed_str}\n")
                self.stream.flush()
            return

        bar_len = cols - len(prefix) - len(suffix) - 2
        bar_len = max(5, min(40, bar_len))

        fill_len = int(round(bar_len * ratio))
        empty_len = bar_len - fill_len
        bar_str = (self._fill_char * fill_len) + (self._empty_char * empty_len)

        line = f"\r{prefix}{bar_str}{suffix}"
        if len(line) > cols:
            line = line[:cols]

        self.stream.write(line)
        if current_bytes >= total_bytes:
            self.stream.write("\n")
        self.stream.flush()


__all__ = ["TerminalUI"]
