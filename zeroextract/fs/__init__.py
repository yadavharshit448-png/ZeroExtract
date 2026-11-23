"""Filesystem space reclamation subsystem for ZeroExtract.

Provides atomic and progressive primitives to reclaim physical disk space
on Windows NTFS/ReFS and other filesystems during archive decompression.
"""

from __future__ import annotations

import abc
import os
from typing import Any

from zeroextract.fs.headroom import HeadroomMonitor, LowHeadroomError
from zeroextract.fs.sparse import (
    FILE_ALLOCATED_RANGE_BUFFER,
    FILE_ZERO_DATA_INFORMATION,
    FSCTL_QUERY_ALLOCATED_RANGES,
    FSCTL_SET_SPARSE,
    FSCTL_SET_ZERO_DATA,
    SparseError,
    SparsePuncher,
)
from zeroextract.fs.truncator import ReverseTruncator, TruncateError
from zeroextract.fs.volume_cleaner import VolumeCleaner, VolumeCleanError


class ISpaceReclaimer(abc.ABC):
    """Abstract interface contract for filesystem space reclamation."""

    @abc.abstractmethod
    def punch_hole(self, file_path: str | os.PathLike, offset: int, length: int) -> int:
        """Deallocates physical disk clusters for the byte range [offset, offset + length).

        Args:
            file_path: Target archive file path.
            offset: Starting byte offset.
            length: Number of bytes to deallocate.

        Returns:
            Number of bytes successfully deallocated.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def truncate_tail(self, file_path: str | os.PathLike, new_size: int) -> int:
        """Physically truncates the file to new_size, instantly returning trailing space to OS.

        Args:
            file_path: Target archive file path.
            new_size: New file length in bytes.

        Returns:
            Number of bytes freed from disk.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def unlink_volume(self, volume_path: str | os.PathLike) -> bool:
        """Deletes a completed archive volume file after validation.

        Args:
            volume_path: Path to the completed volume.

        Returns:
            True on successful deletion.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_free_headroom(self, path: str | os.PathLike) -> int:
        """Returns free disk space in bytes for the volume hosting path.

        Args:
            path: Target filesystem path.

        Returns:
            Free space in bytes.
        """
        raise NotImplementedError


class SpaceReclaimer(ISpaceReclaimer):
    """Unified implementation of ISpaceReclaimer coordinating all reclamation strategies."""

    def __init__(
        self,
        sparse_puncher: SparsePuncher | None = None,
        reverse_truncator: ReverseTruncator | None = None,
        volume_cleaner: VolumeCleaner | None = None,
        headroom_monitor: HeadroomMonitor | None = None,
    ) -> None:
        self.sparse = sparse_puncher or SparsePuncher()
        self.truncator = reverse_truncator or ReverseTruncator()
        self.cleaner = volume_cleaner or VolumeCleaner()
        self.headroom = headroom_monitor or HeadroomMonitor()

    def punch_hole(self, file_path: str | os.PathLike, offset: int, length: int) -> int:
        return self.sparse.punch_hole(file_path, offset, length)

    def truncate_tail(self, file_path: str | os.PathLike, new_size: int) -> int:
        return self.truncator.truncate_tail(file_path, new_size)

    def unlink_volume(self, volume_path: str | os.PathLike) -> bool:
        return self.cleaner.unlink_volume(volume_path)

    def get_free_headroom(self, path: str | os.PathLike) -> int:
        return self.headroom.get_free_space(path)


__all__ = [
    "ISpaceReclaimer",
    "SpaceReclaimer",
    "SparsePuncher",
    "ReverseTruncator",
    "VolumeCleaner",
    "HeadroomMonitor",
    "SparseError",
    "TruncateError",
    "VolumeCleanError",
    "LowHeadroomError",
    "FSCTL_SET_SPARSE",
    "FSCTL_SET_ZERO_DATA",
    "FSCTL_QUERY_ALLOCATED_RANGES",
    "FILE_ZERO_DATA_INFORMATION",
    "FILE_ALLOCATED_RANGE_BUFFER",
]
