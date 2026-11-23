"""ZeroExtract Command-Line Interface subsystem."""

from __future__ import annotations

from zeroextract.cli.gui import launch_gui
from zeroextract.cli.main import create_parser, main
from zeroextract.cli.ui import TerminalUI
from zeroextract.cli.windows_setup import create_batch_launcher, normalize_windows_path

__all__ = [
    "main",
    "create_parser",
    "launch_gui",
    "TerminalUI",
    "normalize_windows_path",
    "create_batch_launcher",
]
