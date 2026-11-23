"""Windows shell and path integration utilities for ZeroExtract."""

from __future__ import annotations

import os
from pathlib import Path
import sys


def normalize_windows_path(path_str: str) -> str:
    """Normalizes Windows paths, handling quotes, spaces, slashes, and UNC prefixes.

    Args:
        path_str: Raw path input (e.g., from drag-and-drop or command line).

    Returns:
        Clean, normalized path string.
    """
    if not path_str:
        return ""

    # Strip surrounding single or double quotes
    s = path_str.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()

    # Preserve UNC network path prefix
    is_unc = s.startswith(("\\\\", "//"))

    # Convert forward slashes to backslashes on Windows
    s = s.replace("/", "\\")

    # Strip trailing whitespace and trailing dots (Win32 rules, unless '.' or '..')
    while len(s) > 1 and s.endswith(" ") and not s.endswith("\\ "):
        s = s.rstrip(" ")

    # Strip trailing dots from filename component unless dot directory
    base_name = os.path.basename(s)
    if base_name not in (".", "..") and base_name.endswith("."):
        dir_name = os.path.dirname(s)
        clean_base = base_name.rstrip(".")
        s = os.path.join(dir_name, clean_base) if dir_name else clean_base

    if is_unc and not s.startswith("\\\\"):
        s = "\\\\" + s.lstrip("\\")

    return s


def create_batch_launcher(batch_path: str | os.PathLike) -> None:
    """Generates a zeroextract.bat launcher for Windows CMD / PowerShell / Explorer drag-and-drop.

    Args:
        batch_path: Target .bat file path.
    """
    bp = Path(batch_path)
    bp.parent.mkdir(parents=True, exist_ok=True)

    batch_content = (
        "@echo off\r\n"
        "REM ZeroExtract Windows Batch Launcher\r\n"
        'python -m zeroextract %*\r\n'
    )
    bp.write_text(batch_content, encoding="utf-8")


__all__ = ["normalize_windows_path", "create_batch_launcher"]
