"""Windows NTFS/ReFS sparse file management and hole punching.

Provides ctypes bindings to Win32 kernel32 APIs for FSCTL_SET_SPARSE,
FSCTL_SET_ZERO_DATA, and FSCTL_QUERY_ALLOCATED_RANGES with 64KB cluster alignment.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import sys
from contextlib import contextmanager
from ctypes import wintypes
from typing import Any, Generator, Sequence

# Windows IOCTL Constants
FSCTL_SET_SPARSE = 0x000900C4
FSCTL_SET_ZERO_DATA = 0x000980C8
FSCTL_QUERY_ALLOCATED_RANGES = 0x000940CF
FILE_SUPPORTS_SPARSE_FILES = 0x00000040

# Linux fallocate Constants
FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02

# File Access & Sharing Flags
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
ERROR_MORE_DATA = 234

# FormatMessage Constants
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200


class FILE_ZERO_DATA_INFORMATION(ctypes.Structure):
    """Ctypes structure for FSCTL_SET_ZERO_DATA input."""

    _fields_ = [
        ("FileOffset", ctypes.c_int64),
        ("BeyondFinalZero", ctypes.c_int64),
    ]


class FILE_ALLOCATED_RANGE_BUFFER(ctypes.Structure):
    """Ctypes structure for FSCTL_QUERY_ALLOCATED_RANGES input/output."""

    _fields_ = [
        ("FileOffset", ctypes.c_int64),
        ("Length", ctypes.c_int64),
    ]


class SparseError(OSError):
    """Raised when a sparse file operation fails."""

    def __init__(self, message: str, win_error: int | None = None) -> None:
        self.win_error = win_error
        super().__init__(message)


# Initialize kernel32 library and function signatures
_kernel32 = None
if sys.platform == "win32":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _kernel32.DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _kernel32.DeviceIoControl.restype = wintypes.BOOL

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

    _kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _kernel32.GetVolumeInformationW.restype = wintypes.BOOL

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

    _kernel32.GetFileSizeEx.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_int64),
    ]
    _kernel32.GetFileSizeEx.restype = wintypes.BOOL

_libc = None
if sys.platform.startswith("linux"):
    try:
        _libc_name = ctypes.util.find_library("c") or "libc.so.6"
        _libc = ctypes.CDLL(_libc_name, use_errno=True)
        if hasattr(_libc, "fallocate"):
            _libc.fallocate.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int64,
                ctypes.c_int64,
            ]
            _libc.fallocate.restype = ctypes.c_int
    except OSError:
        _libc = None


def get_win_error_message(error_code: int) -> str:
    """Formats a Windows system error code into a descriptive message."""
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


def get_volume_root(path: str | os.PathLike) -> str:
    """Resolves a file path to its volume root path (e.g., 'C:\\')."""
    abs_path = os.path.abspath(os.fspath(path))
    drive, _ = os.path.splitdrive(abs_path)
    if drive:
        return drive + "\\"
    if abs_path.startswith("\\\\"):
        # UNC path \\server\share\...
        parts = abs_path.split("\\")
        if len(parts) >= 4:
            return f"\\\\{parts[2]}\\{parts[3]}\\"
    return os.path.abspath(os.sep)


class SparsePuncher:
    """Manages Windows NTFS/ReFS and Linux fallocate sparse file operations."""

    def __init__(self, kernel32_dll: Any = None, libc_cdll: Any = None) -> None:
        self._k32 = kernel32_dll or _kernel32
        self._libc = libc_cdll or _libc

    def is_sparse_supported(self, path: str | os.PathLike) -> bool:
        """Queries volume filesystem flags to check if sparse files are supported.

        Args:
            path: Path to any file or directory on the target volume.

        Returns:
            True if volume supports sparse files, False otherwise.
        """
        if self._k32 is None:
            return bool(self._libc is not None and hasattr(self._libc, "fallocate"))

        root = get_volume_root(path)
        vol_name = ctypes.create_unicode_buffer(261)
        fs_name = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        max_len = wintypes.DWORD()
        flags = wintypes.DWORD()

        ret = self._k32.GetVolumeInformationW(
            root,
            vol_name,
            260,
            ctypes.byref(serial),
            ctypes.byref(max_len),
            ctypes.byref(flags),
            fs_name,
            260,
        )
        if not ret:
            err = ctypes.get_last_error()
            raise SparseError(
                f"GetVolumeInformationW failed for '{root}': [{err}] {get_win_error_message(err)}",
                win_error=err,
            )
        return bool(flags.value & FILE_SUPPORTS_SPARSE_FILES)

    def mark_as_sparse(self, file_path_or_handle: Any) -> bool:
        """Sets the sparse attribute on an open file handle or path via FSCTL_SET_SPARSE.

        Args:
            file_path_or_handle: File path, open file object, file descriptor, or HANDLE.

        Returns:
            True on success.

        Raises:
            SparseError: If setting sparse attribute fails.
        """
        if self._k32 is None:
            if self._libc is not None and hasattr(self._libc, "fallocate"):
                return True
            raise SparseError("Sparse files are only supported on Windows or Linux.")

        with self._resolve_handle(file_path_or_handle, access=GENERIC_READ | GENERIC_WRITE) as h:
            bytes_returned = wintypes.DWORD(0)
            ret = self._k32.DeviceIoControl(
                h,
                FSCTL_SET_SPARSE,
                None,
                0,
                None,
                0,
                ctypes.byref(bytes_returned),
                None,
            )
            if not ret:
                err = ctypes.get_last_error()
                raise SparseError(
                    f"FSCTL_SET_SPARSE failed: [{err}] {get_win_error_message(err)}",
                    win_error=err,
                )
            return True

    def punch_hole(
        self,
        file_path_or_handle: Any,
        offset: int,
        length: int,
        cluster_size: int = 65536,
    ) -> int:
        """Punches a sparse hole for byte range [offset, offset + length).

        Aligns the deallocation region to cluster boundaries (default 64KB).
        Ensures the file has the sparse attribute set.

        Args:
            file_path_or_handle: File path, file object, file descriptor, or HANDLE.
            offset: Starting byte offset of range to deallocate.
            length: Number of bytes to deallocate.
            cluster_size: Alignment boundary size in bytes (default 64KB).

        Returns:
            Number of bytes deallocated.
        """
        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")
        if length < 0:
            raise ValueError(f"length must be non-negative, got {length}")
        if length == 0:
            return 0

        if self._k32 is None and not (self._libc is not None and hasattr(self._libc, "fallocate")):
            raise SparseError("Sparse hole punching is only supported on Windows or Linux.")

        # Compute cluster-aligned deallocation range
        # Start offset aligns UP to ensure no preceding bytes are destroyed.
        # End offset aligns DOWN to ensure no trailing bytes are destroyed.
        if cluster_size is not None and cluster_size > 1:
            aligned_start = ((offset + cluster_size - 1) // cluster_size) * cluster_size
            aligned_end = ((offset + length) // cluster_size) * cluster_size
        else:
            aligned_start = offset
            aligned_end = offset + length

        if aligned_end <= aligned_start:
            # Region smaller than a single cluster or spans partial clusters
            return 0

        if self._k32 is None:
            return self._punch_hole_linux(file_path_or_handle, aligned_start, aligned_end - aligned_start)

        with self._resolve_handle(file_path_or_handle, access=GENERIC_READ | GENERIC_WRITE) as h:
            # Ensure marked as sparse
            bytes_returned = wintypes.DWORD(0)
            self._k32.DeviceIoControl(
                h,
                FSCTL_SET_SPARSE,
                None,
                0,
                None,
                0,
                ctypes.byref(bytes_returned),
                None,
            )

            zinfo = FILE_ZERO_DATA_INFORMATION()
            zinfo.FileOffset = aligned_start
            zinfo.BeyondFinalZero = aligned_end

            ret = self._k32.DeviceIoControl(
                h,
                FSCTL_SET_ZERO_DATA,
                ctypes.byref(zinfo),
                ctypes.sizeof(zinfo),
                None,
                0,
                ctypes.byref(bytes_returned),
                None,
            )
            if not ret:
                err = ctypes.get_last_error()
                raise SparseError(
                    f"FSCTL_SET_ZERO_DATA failed for range [{aligned_start}, {aligned_end}): "
                    f"[{err}] {get_win_error_message(err)}",
                    win_error=err,
                )

            return aligned_end - aligned_start

    def get_allocated_ranges(
        self,
        file_path_or_handle: Any,
        query_offset: int = 0,
        query_length: int | None = None,
    ) -> list[tuple[int, int]]:
        """Queries allocated ranges on disk via FSCTL_QUERY_ALLOCATED_RANGES.

        Args:
            file_path_or_handle: File path, file object, file descriptor, or HANDLE.
            query_offset: Starting offset of query (default 0).
            query_length: Length of query range in bytes, or None for entire file.

        Returns:
            List of (offset, length) tuples of allocated physical byte ranges.
        """
        if self._k32 is None:
            if sys.platform.startswith("linux") and hasattr(os, "SEEK_DATA") and hasattr(os, "SEEK_HOLE"):
                return self._get_allocated_ranges_linux(file_path_or_handle, query_offset, query_length)
            raise SparseError("Allocated range query is only supported on Windows or Linux.")

        with self._resolve_handle(file_path_or_handle, access=GENERIC_READ) as h:
            if query_length is None:
                file_size = ctypes.c_int64(0)
                if not self._k32.GetFileSizeEx(h, ctypes.byref(file_size)):
                    err = ctypes.get_last_error()
                    raise SparseError(
                        f"GetFileSizeEx failed: [{err}] {get_win_error_message(err)}",
                        win_error=err,
                    )
                query_length = file_size.value - query_offset
                if query_length <= 0:
                    return []

            ranges: list[tuple[int, int]] = []
            cur_offset = query_offset
            remaining_len = query_length

            batch_capacity = 256
            buffer_type = FILE_ALLOCATED_RANGE_BUFFER * batch_capacity
            out_buf = buffer_type()
            out_buf_size = ctypes.sizeof(out_buf)

            while remaining_len > 0:
                q_in = FILE_ALLOCATED_RANGE_BUFFER(cur_offset, remaining_len)
                bytes_returned = wintypes.DWORD(0)

                ret = self._k32.DeviceIoControl(
                    h,
                    FSCTL_QUERY_ALLOCATED_RANGES,
                    ctypes.byref(q_in),
                    ctypes.sizeof(q_in),
                    ctypes.byref(out_buf),
                    out_buf_size,
                    ctypes.byref(bytes_returned),
                    None,
                )
                err = ctypes.get_last_error()

                if not ret and err != ERROR_MORE_DATA:
                    raise SparseError(
                        f"FSCTL_QUERY_ALLOCATED_RANGES failed: [{err}] {get_win_error_message(err)}",
                        win_error=err,
                    )

                num_records = bytes_returned.value // ctypes.sizeof(FILE_ALLOCATED_RANGE_BUFFER)
                if num_records == 0:
                    break

                for i in range(num_records):
                    rec = out_buf[i]
                    ranges.append((rec.FileOffset, rec.Length))

                last_rec = out_buf[num_records - 1]
                last_end = last_rec.FileOffset + last_rec.Length
                if last_end <= cur_offset:
                    break
                remaining_len -= (last_end - cur_offset)
                cur_offset = last_end

                if ret:
                    # Successfully completed query without needing more buffer pages
                    break

            return ranges

    @contextmanager
    def _resolve_handle(
        self,
        file_path_or_handle: Any,
        access: int = GENERIC_READ | GENERIC_WRITE,
    ) -> Generator[wintypes.HANDLE, None, None]:
        """Context manager resolving path or handle to a usable Win32 HANDLE."""
        if isinstance(file_path_or_handle, (str, bytes, os.PathLike)):
            path_str = os.fspath(file_path_or_handle)
            if isinstance(path_str, bytes):
                path_str = path_str.decode("utf-8")

            h = self._k32.CreateFileW(
                path_str,
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            # Check for INVALID_HANDLE_VALUE (-1 or 0xFFFFFFFFFFFFFFFF)
            if h == INVALID_HANDLE_VALUE or (h is not None and (h & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFFFFF) or not h:
                err = ctypes.get_last_error()
                raise SparseError(
                    f"CreateFileW failed for '{path_str}': [{err}] {get_win_error_message(err)}",
                    win_error=err,
                )
            try:
                yield h
            finally:
                self._k32.CloseHandle(h)
        elif hasattr(file_path_or_handle, "fileno"):
            # Python file object
            import msvcrt
            fd = file_path_or_handle.fileno()
            h = msvcrt.get_osfhandle(fd)
            yield h
        elif isinstance(file_path_or_handle, int):
            # C runtime fd or raw Win32 HANDLE
            import msvcrt
            try:
                h = msvcrt.get_osfhandle(file_path_or_handle)
                yield h
            except (ValueError, OSError):
                yield file_path_or_handle
        else:
            yield file_path_or_handle

    @contextmanager
    def _resolve_fd(self, file_path_or_handle: Any, flags: int = os.O_RDWR) -> Generator[int, None, None]:
        """Context manager resolving path, file object, or int fd to a POSIX file descriptor."""
        if isinstance(file_path_or_handle, (str, bytes, os.PathLike)):
            fd = os.open(os.fspath(file_path_or_handle), flags)
            try:
                yield fd
            finally:
                os.close(fd)
        elif hasattr(file_path_or_handle, "fileno"):
            yield file_path_or_handle.fileno()
        elif isinstance(file_path_or_handle, int):
            yield file_path_or_handle
        else:
            raise SparseError(f"Unsupported file handle type: {type(file_path_or_handle)}")

    def _punch_hole_linux(self, file_path_or_handle: Any, offset: int, length: int) -> int:
        """Punches a sparse hole on Linux via fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)."""
        with self._resolve_fd(file_path_or_handle, os.O_RDWR) as fd:
            ctypes.set_errno(0)
            ret = self._libc.fallocate(
                fd,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                ctypes.c_int64(offset),
                ctypes.c_int64(length),
            )
            if ret != 0:
                err = ctypes.get_errno()
                raise SparseError(
                    f"fallocate(FALLOC_FL_PUNCH_HOLE) failed for range [{offset}, {offset + length}): "
                    f"[{err}] {os.strerror(err)}",
                    win_error=err,
                )
        return length

    def _get_allocated_ranges_linux(
        self,
        file_path_or_handle: Any,
        query_offset: int = 0,
        query_length: int | None = None,
    ) -> list[tuple[int, int]]:
        """Queries allocated data ranges on Linux using lseek(SEEK_DATA / SEEK_HOLE)."""
        with self._resolve_fd(file_path_or_handle, os.O_RDONLY) as fd:
            file_size = os.fstat(fd).st_size
            end_limit = file_size if query_length is None else min(file_size, query_offset + query_length)
            if query_offset >= end_limit:
                return []

            ranges: list[tuple[int, int]] = []
            pos = query_offset
            while pos < end_limit:
                try:
                    data_start = os.lseek(fd, pos, os.SEEK_DATA)
                except OSError as exc:
                    if exc.errno == errno.ENXIO:
                        break
                    raise SparseError(f"lseek(SEEK_DATA) failed: {exc}") from exc

                if data_start >= end_limit:
                    break

                try:
                    hole_start = os.lseek(fd, data_start, os.SEEK_HOLE)
                except OSError as exc:
                    if exc.errno == errno.ENXIO:
                        hole_start = end_limit
                    else:
                        raise SparseError(f"lseek(SEEK_HOLE) failed: {exc}") from exc

                region_end = min(hole_start, end_limit)
                if region_end > data_start:
                    ranges.append((data_start, region_end - data_start))
                pos = region_end

            return ranges
