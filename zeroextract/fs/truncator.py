"""Universal reverse file tail truncation.

Physically shrinks files from tail to beginning via Win32 SetEndOfFile
and Python's f.truncate(), instantly returning freed trailing disk space to the OS.
"""

from __future__ import annotations

import ctypes
import os
import sys
from contextlib import contextmanager
from ctypes import wintypes
from typing import Any, Generator

# Win32 Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
FILE_BEGIN = 0

# FormatMessage Constants
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200


class TruncateError(OSError):
    """Raised when tail truncation fails."""

    def __init__(self, message: str, win_error: int | None = None) -> None:
        self.win_error = win_error
        super().__init__(message)


_kernel32 = None
if sys.platform == "win32":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE

    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int64,
        ctypes.POINTER(ctypes.c_int64),
        wintypes.DWORD,
    ]
    _kernel32.SetFilePointerEx.restype = wintypes.BOOL

    _kernel32.SetEndOfFile.argtypes = [wintypes.HANDLE]
    _kernel32.SetEndOfFile.restype = wintypes.BOOL

    _kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _kernel32.FlushFileBuffers.restype = wintypes.BOOL

    _kernel32.GetFileSizeEx.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_int64),
    ]
    _kernel32.GetFileSizeEx.restype = wintypes.BOOL

    _kernel32.FormatMessageW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    _kernel32.FormatMessageW.restype = wintypes.DWORD


def _get_win_error_message(error_code: int) -> str:
    if _kernel32 is None:
        return f"Windows Error {error_code}"
    buf = ctypes.create_unicode_buffer(1024)
    chars = _kernel32.FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        None,
        error_code,
        0,
        buf,
        len(buf),
        None,
    )
    if chars > 0:
        return buf.value.strip()
    return ctypes.FormatError(error_code).strip()


class ReverseTruncator:
    """Manages physical file tail truncation to reclaim space in lockstep."""

    def __init__(self, kernel32_dll: Any = None) -> None:
        self._k32 = kernel32_dll or _kernel32

    def truncate_tail(self, file_path_or_handle: Any, new_size: int) -> int:
        """Physically truncates file tail to new_size.

        Validates new_size >= 0. Checks current size.
        If new_size >= current_size, returns 0.
        Flushes file buffers before shrinking.
        Truncates file to new_size and verifies resulting size.
        Returns number of bytes freed (current_size - new_size).

        Args:
            file_path_or_handle: File path, open file object, file descriptor, or HANDLE.
            new_size: Desired new file size in bytes.

        Returns:
            Number of bytes freed from disk.

        Raises:
            ValueError: If new_size is negative.
            TruncateError: If truncation fails or size verification fails.
        """
        if new_size < 0:
            raise ValueError(f"new_size must be non-negative, got {new_size}")

        if self._k32 is not None:
            return self._truncate_win32(file_path_or_handle, new_size)
        return self._truncate_fallback(file_path_or_handle, new_size)

    def _truncate_win32(self, file_path_or_handle: Any, new_size: int) -> int:
        if hasattr(file_path_or_handle, "flush"):
            try:
                file_path_or_handle.flush()
            except OSError:
                pass
        if hasattr(file_path_or_handle, "seek"):
            try:
                file_path_or_handle.seek(new_size)
            except OSError:
                pass

        with self._resolve_handle(file_path_or_handle) as h:
            # Query current size
            cur_size = ctypes.c_int64(0)
            if not self._k32.GetFileSizeEx(h, ctypes.byref(cur_size)):
                err = ctypes.get_last_error()
                raise TruncateError(
                    f"GetFileSizeEx failed: [{err}] {_get_win_error_message(err)}",
                    win_error=err,
                )

            initial_size = cur_size.value
            if new_size >= initial_size:
                return 0

            # Flush buffers prior to shrinking
            self._k32.FlushFileBuffers(h)

            # Move file pointer to new_size
            new_fp = ctypes.c_int64(0)
            if not self._k32.SetFilePointerEx(h, ctypes.c_int64(new_size), ctypes.byref(new_fp), FILE_BEGIN):
                err = ctypes.get_last_error()
                raise TruncateError(
                    f"SetFilePointerEx failed: [{err}] {_get_win_error_message(err)}",
                    win_error=err,
                )

            # Set end of file
            if not self._k32.SetEndOfFile(h):
                err = ctypes.get_last_error()
                raise TruncateError(
                    f"SetEndOfFile failed: [{err}] {_get_win_error_message(err)}",
                    win_error=err,
                )

            # Flush buffers post-truncation
            self._k32.FlushFileBuffers(h)

            # Verify resulting size
            verified_size = ctypes.c_int64(0)
            if not self._k32.GetFileSizeEx(h, ctypes.byref(verified_size)):
                err = ctypes.get_last_error()
                raise TruncateError(
                    f"Verification GetFileSizeEx failed: [{err}] {_get_win_error_message(err)}",
                    win_error=err,
                )

            if verified_size.value != new_size:
                raise TruncateError(
                    f"Truncation verification failed: expected size {new_size}, got {verified_size.value}"
                )

        if hasattr(file_path_or_handle, "seek"):
            try:
                file_path_or_handle.seek(new_size)
            except OSError:
                pass

        return initial_size - new_size

    def _truncate_fallback(self, file_path_or_handle: Any, new_size: int) -> int:
        """Universal Python fallback truncation for non-Windows systems."""
        if hasattr(file_path_or_handle, "truncate") and hasattr(file_path_or_handle, "seek"):
            f = file_path_or_handle
            f.seek(0, os.SEEK_END)
            initial_size = f.tell()
            if new_size >= initial_size:
                return 0

            f.flush()
            f.truncate(new_size)
            f.flush()
            if hasattr(f, "fileno"):
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass

            f.seek(0, os.SEEK_END)
            final_size = f.tell()
            if final_size != new_size:
                raise TruncateError(
                    f"Fallback truncate verification failed: expected {new_size}, got {final_size}"
                )
            return initial_size - new_size
        elif isinstance(file_path_or_handle, (str, bytes, os.PathLike)):
            path = os.fspath(file_path_or_handle)
            initial_size = os.path.getsize(path)
            if new_size >= initial_size:
                return 0

            with open(path, "r+b") as f:
                f.flush()
                f.truncate(new_size)
                f.flush()
                os.fsync(f.fileno())

            final_size = os.path.getsize(path)
            if final_size != new_size:
                raise TruncateError(
                    f"Fallback truncate verification failed: expected {new_size}, got {final_size}"
                )
            return initial_size - new_size
        elif isinstance(file_path_or_handle, int):
            initial_size = os.fstat(file_path_or_handle).st_size
            if new_size >= initial_size:
                return 0
            os.ftruncate(file_path_or_handle, new_size)
            try:
                os.fsync(file_path_or_handle)
            except OSError:
                pass
            final_size = os.fstat(file_path_or_handle).st_size
            if final_size != new_size:
                raise TruncateError(
                    f"Fallback ftruncate verification failed: expected {new_size}, got {final_size}"
                )
            return initial_size - new_size
        else:
            raise TruncateError(f"Unsupported file_path_or_handle type: {type(file_path_or_handle)}")

    @contextmanager
    def _resolve_handle(self, file_path_or_handle: Any) -> Generator[wintypes.HANDLE, None, None]:
        if isinstance(file_path_or_handle, (str, bytes, os.PathLike)):
            path_str = os.fspath(file_path_or_handle)
            if isinstance(path_str, bytes):
                path_str = path_str.decode("utf-8")

            h = self._k32.CreateFileW(
                path_str,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if h == INVALID_HANDLE_VALUE or (h is not None and (h & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF) or not h:
                err = ctypes.get_last_error()
                raise TruncateError(
                    f"CreateFileW failed for '{path_str}': [{err}] {_get_win_error_message(err)}",
                    win_error=err,
                )
            try:
                yield h
            finally:
                self._k32.CloseHandle(h)
        elif hasattr(file_path_or_handle, "fileno"):
            import msvcrt
            fd = file_path_or_handle.fileno()
            h = msvcrt.get_osfhandle(fd)
            yield h
        elif isinstance(file_path_or_handle, int):
            import msvcrt
            try:
                h = msvcrt.get_osfhandle(file_path_or_handle)
                yield h
            except (ValueError, OSError):
                yield file_path_or_handle
        else:
            yield file_path_or_handle
