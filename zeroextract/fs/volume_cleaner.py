"""Progressive multi-volume archive cleaner.

Safely detects, unlocks, and unlinks completed split archive volumes
(.z01, .part1.rar, .7z.001, etc.) with exponential backoff and attribute clearing.
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
import time
from ctypes import wintypes
from typing import Any

FILE_ATTRIBUTE_READONLY = 0x00000001
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF


class VolumeCleanError(OSError):
    """Raised when unlinking or cleaning an archive volume fails."""

    def __init__(self, message: str, win_error: int | None = None) -> None:
        self.win_error = win_error
        super().__init__(message)


_kernel32 = None
if sys.platform == "win32":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetFileAttributesW.restype = wintypes.DWORD

    _kernel32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _kernel32.SetFileAttributesW.restype = wintypes.BOOL


class VolumeCleaner:
    """Manages progressive safe unlinking of completed split archive volumes."""

    # Split volume regex patterns in precedence order
    SPLIT_PATTERNS = [
        re.compile(r"^(.*?)\.part(\d+)\.rar$", re.IGNORECASE),
        re.compile(r"^(.*?)\.7z\.(\d+)$", re.IGNORECASE),
        re.compile(r"^(.*?)\.zip\.(\d+)$", re.IGNORECASE),
        re.compile(r"^(.*?)\.z(\d{2,})$", re.IGNORECASE),
        re.compile(r"^(.*?)\.r(\d{2,})$", re.IGNORECASE),
        re.compile(r"^(.*?)\.(\d{3,})$"),
    ]

    def __init__(self, kernel32_dll: Any = None) -> None:
        self._k32 = kernel32_dll or _kernel32

    def is_split_volume(self, path: str | os.PathLike) -> bool:
        """Determines if a given filename matches known multi-part archive volume patterns.

        Recognizes:
            - RAR split: .part1.rar, .part02.rar
            - RAR old split: .r00, .r01
            - 7-Zip split: .7z.001, .7z.002
            - ZIP split: .z01, .z02, .zip.001
            - Generic split: .001, .002

        Args:
            path: File path or name.

        Returns:
            True if filename matches a split volume pattern, False otherwise.
        """
        filename = os.path.basename(os.fspath(path))
        for pattern in self.SPLIT_PATTERNS:
            if pattern.match(filename):
                return True
        return False

    def get_volume_index(self, path: str | os.PathLike) -> tuple[str, int]:
        """Parses the base archive name and numeric sequence index from a split volume path.

        Args:
            path: Split volume file path or name.

        Returns:
            Tuple of (base_name, volume_index).

        Raises:
            ValueError: If path does not match any recognized split volume format.
        """
        filename = os.path.basename(os.fspath(path))
        for pattern in self.SPLIT_PATTERNS:
            m = pattern.match(filename)
            if m:
                base_name = m.group(1)
                vol_index = int(m.group(2))
                return base_name, vol_index

        raise ValueError(f"Not a recognized split archive volume filename: '{filename}'")

    def unlink_volume(
        self,
        volume_path: str | os.PathLike,
        max_retries: int = 5,
        retry_delay: float = 0.5,
    ) -> bool:
        """Safely unlinks a completed volume file, handling read-only flags and lock contention.

        Args:
            volume_path: Path to the volume file to delete.
            max_retries: Number of retry attempts in case of file locks.
            retry_delay: Initial delay in seconds between retries (exponential backoff).

        Returns:
            True on successful deletion.

        Raises:
            FileNotFoundError: If the volume file does not exist.
            VolumeCleanError: If the file cannot be deleted after all retries.
        """
        path_str = os.fspath(volume_path)
        if isinstance(path_str, bytes):
            path_str = path_str.decode("utf-8")

        if not os.path.exists(path_str):
            raise FileNotFoundError(f"Volume file not found: '{path_str}'")

        # Clear Windows read-only attribute if present
        if self._k32 is not None and sys.platform == "win32":
            attrs = self._k32.GetFileAttributesW(path_str)
            if attrs != INVALID_FILE_ATTRIBUTES and (attrs & FILE_ATTRIBUTE_READONLY):
                new_attrs = attrs & ~FILE_ATTRIBUTE_READONLY
                self._k32.SetFileAttributesW(path_str, new_attrs)

        # Progressive unlinking with exponential backoff
        last_error = None
        for attempt in range(max_retries):
            try:
                os.unlink(path_str)
                return True
            except (PermissionError, OSError) as exc:
                last_error = exc
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))

        raise VolumeCleanError(
            f"Failed to unlink volume '{path_str}' after {max_retries} attempts: {last_error}"
        ) from last_error
