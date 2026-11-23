"""Disk free space and safety headroom monitoring.

Provides Win32 GetDiskFreeSpaceExW bindings to continuously enforce
minimum safety cushion thresholds before and during space-reclaiming extraction.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import sys
from ctypes import wintypes
from typing import Any


class LowHeadroomError(RuntimeError):
    """Raised when available disk space falls below safety headroom thresholds."""

    def __init__(
        self,
        message: str,
        path: str = "",
        free_bytes: int = 0,
        required_bytes: int = 0,
        cushion_bytes: int = 0,
        shortage_bytes: int = 0,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.free_bytes = free_bytes
        self.required_bytes = required_bytes
        self.cushion_bytes = cushion_bytes
        self.shortage_bytes = shortage_bytes


_kernel32 = None
if sys.platform == "win32":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _kernel32.GetDiskFreeSpaceExW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
    ]
    _kernel32.GetDiskFreeSpaceExW.restype = wintypes.BOOL


def _normalize_directory(path: str | os.PathLike) -> str:
    """Extracts a valid directory path or volume root for disk space querying."""
    abs_path = os.path.abspath(os.fspath(path))
    if os.path.isdir(abs_path):
        return abs_path
    parent = os.path.dirname(abs_path)
    if parent and os.path.exists(parent):
        return parent
    drive, _ = os.path.splitdrive(abs_path)
    if drive:
        return drive + "\\"
    return abs_path


class HeadroomMonitor:
    """Monitors disk space capacity and enforces safety headroom cushions."""

    DEFAULT_MIN_CUSHION = 512 * 1024 * 1024  # 512 MB default safety headroom

    def __init__(self, kernel32_dll: Any = None) -> None:
        self._k32 = kernel32_dll or _kernel32

    def get_free_space(self, path: str | os.PathLike) -> int:
        """Returns the number of free bytes available to the caller on the volume.

        Args:
            path: File or directory path on the target volume.

        Returns:
            Free space in bytes.

        Raises:
            OSError: If disk space query fails.
        """
        dir_path = _normalize_directory(path)

        if self._k32 is not None and sys.platform == "win32":
            free_user = ctypes.c_uint64(0)
            total = ctypes.c_uint64(0)
            free_total = ctypes.c_uint64(0)

            ret = self._k32.GetDiskFreeSpaceExW(
                dir_path,
                ctypes.byref(free_user),
                ctypes.byref(total),
                ctypes.byref(free_total),
            )
            if not ret:
                err = ctypes.get_last_error()
                raise OSError(f"GetDiskFreeSpaceExW failed for '{dir_path}' with error code {err}")
            return int(free_user.value)

        # Fallback using shutil.disk_usage
        usage = shutil.disk_usage(dir_path)
        return usage.free

    def get_total_space(self, path: str | os.PathLike) -> int:
        """Returns the total capacity in bytes of the volume hosting the path.

        Args:
            path: File or directory path on the target volume.

        Returns:
            Total disk capacity in bytes.

        Raises:
            OSError: If disk space query fails.
        """
        dir_path = _normalize_directory(path)

        if self._k32 is not None and sys.platform == "win32":
            free_user = ctypes.c_uint64(0)
            total = ctypes.c_uint64(0)
            free_total = ctypes.c_uint64(0)

            ret = self._k32.GetDiskFreeSpaceExW(
                dir_path,
                ctypes.byref(free_user),
                ctypes.byref(total),
                ctypes.byref(free_total),
            )
            if not ret:
                err = ctypes.get_last_error()
                raise OSError(f"GetDiskFreeSpaceExW failed for '{dir_path}' with error code {err}")
            return int(total.value)

        usage = shutil.disk_usage(dir_path)
        return usage.total

    def check_headroom(
        self,
        path: str | os.PathLike,
        required_bytes: int = 0,
        min_headroom_cushion: int = DEFAULT_MIN_CUSHION,
    ) -> bool:
        """Checks if there is enough free space to satisfy required_bytes plus safety cushion.

        Args:
            path: Target filesystem path.
            required_bytes: Number of bytes about to be written.
            min_headroom_cushion: Required free space reserve (default 512MB).

        Returns:
            True if (free_space - required_bytes) >= min_headroom_cushion, False otherwise.
        """
        free_space = self.get_free_space(path)
        return (free_space - required_bytes) >= min_headroom_cushion

    def ensure_headroom(
        self,
        path: str | os.PathLike,
        required_bytes: int = 0,
        min_headroom_cushion: int = DEFAULT_MIN_CUSHION,
    ) -> None:
        """Enforces that free space remains above the safety headroom threshold.

        Args:
            path: Target filesystem path.
            required_bytes: Number of bytes about to be written.
            min_headroom_cushion: Required free space reserve (default 512MB).

        Raises:
            LowHeadroomError: If remaining space would breach the safety cushion.
        """
        free_space = self.get_free_space(path)
        net_headroom = free_space - required_bytes
        if net_headroom < min_headroom_cushion:
            shortage = min_headroom_cushion - net_headroom
            path_str = str(path)
            raise LowHeadroomError(
                f"Insufficient disk headroom on volume for '{path_str}': "
                f"Available: {free_space / (1024*1024):.1f} MB, "
                f"Required: {required_bytes / (1024*1024):.1f} MB, "
                f"Safety cushion: {min_headroom_cushion / (1024*1024):.1f} MB, "
                f"Shortage: {shortage / (1024*1024):.1f} MB.",
                path=path_str,
                free_bytes=free_space,
                required_bytes=required_bytes,
                cushion_bytes=min_headroom_cushion,
                shortage_bytes=shortage,
            )
