"""Comprehensive unit tests for ZeroExtract filesystem space reclaimer subsystem.

Tests SparsePuncher, ReverseTruncator, VolumeCleaner, HeadroomMonitor,
and the unified SpaceReclaimer interface against real Windows NTFS filesystem
and mock/fallback scenarios.
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from zeroextract.fs import (
    FILE_ALLOCATED_RANGE_BUFFER,
    FILE_ZERO_DATA_INFORMATION,
    FSCTL_QUERY_ALLOCATED_RANGES,
    FSCTL_SET_SPARSE,
    FSCTL_SET_ZERO_DATA,
    HeadroomMonitor,
    ISpaceReclaimer,
    LowHeadroomError,
    ReverseTruncator,
    SpaceReclaimer,
    SparseError,
    SparsePuncher,
    TruncateError,
    VolumeCleaner,
    VolumeCleanError,
)

# ---------------------------------------------------------------------------
# SparsePuncher Tests
# ---------------------------------------------------------------------------


class TestSparsePuncher:
    """Tests for Windows NTFS sparse file hole puncher."""

    def test_cluster_alignment_calculations(self) -> None:
        """Verifies inward cluster-boundary alignment math."""
        puncher = SparsePuncher()

        # Perfectly aligned 64KB block at offset 0
        with patch.object(puncher, "_resolve_handle") as mock_res, \
             patch.object(puncher, "_k32") as mock_k32:
            mock_res.return_value.__enter__.return_value = 123
            mock_k32.DeviceIoControl.return_value = 1

            deallocated = puncher.punch_hole("dummy", 0, 65536, cluster_size=65536)
            assert deallocated == 65536

            # Range smaller than 1 cluster spanning partial cluster
            deallocated_small = puncher.punch_hole("dummy", 1000, 2000, cluster_size=65536)
            assert deallocated_small == 0

            # Sub-cluster boundary: offset 1000, len 140000 (span: 1000 to 141000)
            # Aligned start: 65536, Aligned end: 131072 -> 65536 bytes
            deallocated_span = puncher.punch_hole("dummy", 1000, 140000, cluster_size=65536)
            assert deallocated_span == 65536

            # Length 0 returns 0 immediately
            assert puncher.punch_hole("dummy", 0, 0) == 0

    def test_punch_hole_negative_inputs_raise(self) -> None:
        """Verifies negative offsets or lengths raise ValueError."""
        puncher = SparsePuncher()
        with pytest.raises(ValueError, match="offset must be non-negative"):
            puncher.punch_hole("dummy", -1, 100)

        with pytest.raises(ValueError, match="length must be non-negative"):
            puncher.punch_hole("dummy", 0, -50)

    @pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows NTFS")
    def test_real_ntfs_sparse_hole_punch(self, tmp_path) -> None:
        """Performs a real sparse hole punch on Windows NTFS and verifies data integrity."""
        puncher = SparsePuncher()

        # Check if current drive supports sparse files
        if not puncher.is_sparse_supported(tmp_path):
            pytest.skip(f"Volume for '{tmp_path}' does not support sparse files.")

        # Create a 2 MB test file with pattern
        test_file = tmp_path / "test_sparse_real.bin"
        chunk_size = 64 * 1024
        total_size = 32 * chunk_size  # 2097152 bytes (2MB)

        pattern_a = b"A" * chunk_size
        pattern_b = b"B" * chunk_size
        pattern_c = b"C" * chunk_size

        with open(test_file, "wb") as f:
            for i in range(32):
                if i < 4:
                    f.write(pattern_a)
                elif i < 12:
                    f.write(pattern_b)
                else:
                    f.write(pattern_c)

        # Mark as sparse
        marked = puncher.mark_as_sparse(test_file)
        assert marked is True

        # Initial allocated ranges should cover the file
        initial_ranges = puncher.get_allocated_ranges(test_file)
        assert len(initial_ranges) >= 1
        initial_total_alloc = sum(length for _, length in initial_ranges)
        assert initial_total_alloc == total_size

        # Punch hole for blocks 4..12 (offset: 4 * 64KB = 262144, length: 8 * 64KB = 524288)
        hole_offset = 4 * chunk_size
        hole_len = 8 * chunk_size
        freed = puncher.punch_hole(test_file, hole_offset, hole_len, cluster_size=chunk_size)
        assert freed == hole_len

        # Query allocated ranges post-hole punch
        ranges_after = puncher.get_allocated_ranges(test_file)
        # Should now have at least two allocated ranges with a gap in between
        total_alloc_after = sum(length for _, length in ranges_after)
        assert total_alloc_after <= total_size - hole_len

        # Verify that data outside the hole is intact, and data in the hole reads as zero bytes
        with open(test_file, "rb") as f:
            content = f.read()

        assert len(content) == total_size
        assert content[:hole_offset] == pattern_a * 4
        assert content[hole_offset : hole_offset + hole_len] == b"\x00" * hole_len
        assert content[hole_offset + hole_len :] == pattern_c * 20

    @pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows")
    def test_sparse_puncher_with_open_file_object(self, tmp_path) -> None:
        """Verifies SparsePuncher works when passed an open Python file object."""
        puncher = SparsePuncher()
        if not puncher.is_sparse_supported(tmp_path):
            pytest.skip("Sparse files not supported on this volume")

        test_file = tmp_path / "test_open_file.bin"
        test_file.write_bytes(b"Z" * (256 * 1024))

        with open(test_file, "r+b") as f:
            marked = puncher.mark_as_sparse(f)
            assert marked is True

            freed = puncher.punch_hole(f, 65536, 65536, cluster_size=65536)
            assert freed == 65536

            ranges = puncher.get_allocated_ranges(f)
            assert len(ranges) >= 2

    @pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows")
    def test_is_sparse_supported_on_current_drive(self) -> None:
        """Verifies is_sparse_supported returns boolean without error on current drive."""
        puncher = SparsePuncher()
        supported = puncher.is_sparse_supported(".")
        assert isinstance(supported, bool)

    def test_mock_sparse_error_handling(self) -> None:
        """Tests error propagation when DeviceIoControl fails."""
        mock_k32 = MagicMock()
        mock_k32.DeviceIoControl.return_value = 0  # Fail
        puncher = SparsePuncher(kernel32_dll=mock_k32)

        with patch.object(puncher, "_resolve_handle") as mock_res:
            mock_res.return_value.__enter__.return_value = 456
            with pytest.raises(SparseError, match="FSCTL_SET_SPARSE failed"):
                puncher.mark_as_sparse("dummy")

            with pytest.raises(SparseError, match="FSCTL_SET_ZERO_DATA failed"):
                puncher.punch_hole("dummy", 0, 65536, cluster_size=65536)


# ---------------------------------------------------------------------------
# ReverseTruncator Tests
# ---------------------------------------------------------------------------


class TestReverseTruncator:
    """Tests for universal reverse tail truncation."""

    def test_truncate_negative_size_raises(self) -> None:
        """Verifies negative new_size raises ValueError."""
        truncator = ReverseTruncator()
        with pytest.raises(ValueError, match="new_size must be non-negative"):
            truncator.truncate_tail("dummy", -1)

    def test_truncate_same_or_larger_size_returns_zero(self, tmp_path) -> None:
        """Verifies that requesting new_size >= current_size is a no-op returning 0."""
        truncator = ReverseTruncator()
        test_file = tmp_path / "no_op_trunc.bin"
        test_file.write_bytes(b"1234567890")

        # Same size
        freed = truncator.truncate_tail(test_file, 10)
        assert freed == 0
        assert test_file.stat().st_size == 10

        # Larger size
        freed = truncator.truncate_tail(test_file, 20)
        assert freed == 0
        assert test_file.stat().st_size == 10

    def test_real_file_tail_truncation(self, tmp_path) -> None:
        """Tests physical tail truncation on a real disk file."""
        truncator = ReverseTruncator()
        test_file = tmp_path / "real_trunc.bin"

        # Create 100,000 bytes test file
        original_data = b"X" * 40000 + b"Y" * 60000
        test_file.write_bytes(original_data)
        assert test_file.stat().st_size == 100000

        # Truncate to 40,000 bytes
        freed = truncator.truncate_tail(test_file, 40000)
        assert freed == 60000
        assert test_file.stat().st_size == 40000

        # Verify content of preserved prefix
        assert test_file.read_bytes() == b"X" * 40000

        # Truncate to 0 bytes
        freed_to_zero = truncator.truncate_tail(test_file, 0)
        assert freed_to_zero == 40000
        assert test_file.stat().st_size == 0
        assert test_file.read_bytes() == b""

    def test_truncate_with_open_file_object(self, tmp_path) -> None:
        """Verifies truncation works with an open file handle/object."""
        truncator = ReverseTruncator()
        test_file = tmp_path / "open_trunc.bin"
        test_file.write_bytes(b"Hello World Tail Truncate")
        initial_size = test_file.stat().st_size

        with open(test_file, "r+b") as f:
            freed = truncator.truncate_tail(f, 11)
            assert freed == initial_size - 11

        assert test_file.stat().st_size == 11
        assert test_file.read_bytes() == b"Hello World"

    def test_truncate_with_raw_file_descriptor(self, tmp_path) -> None:
        """Verifies truncation works with an integer OS file descriptor."""
        truncator = ReverseTruncator()
        test_file = tmp_path / "fd_trunc.bin"
        test_file.write_bytes(b"B" * 2000)

        fd = os.open(str(test_file), os.O_RDWR | os.O_BINARY if hasattr(os, "O_BINARY") else os.O_RDWR)
        try:
            freed = truncator.truncate_tail(fd, 800)
            assert freed == 1200
        finally:
            os.close(fd)

        assert test_file.stat().st_size == 800
        assert test_file.read_bytes() == b"B" * 800

    def test_fallback_truncator(self, tmp_path) -> None:
        """Tests the Python fallback truncation logic directly."""
        truncator = ReverseTruncator()
        test_file = tmp_path / "fallback_trunc.bin"
        test_file.write_bytes(b"A" * 500)

        freed = truncator._truncate_fallback(test_file, 200)
        assert freed == 300
        assert test_file.stat().st_size == 200
        assert test_file.read_bytes() == b"A" * 200


# ---------------------------------------------------------------------------
# VolumeCleaner Tests
# ---------------------------------------------------------------------------


class TestVolumeCleaner:
    """Tests for progressive multi-volume split archive cleaner."""

    def test_is_split_volume_patterns(self) -> None:
        """Verifies accurate identification of various multi-volume archive formats."""
        cleaner = VolumeCleaner()

        # RAR modern
        assert cleaner.is_split_volume("game.part1.rar") is True
        assert cleaner.is_split_volume("game.part01.rar") is True
        assert cleaner.is_split_volume("archive.PART99.RAR") is True

        # RAR old
        assert cleaner.is_split_volume("game.r00") is True
        assert cleaner.is_split_volume("game.r01") is True

        # 7-Zip
        assert cleaner.is_split_volume("game.7z.001") is True
        assert cleaner.is_split_volume("data.7Z.015") is True

        # ZIP splits
        assert cleaner.is_split_volume("backup.z01") is True
        assert cleaner.is_split_volume("backup.Z12") is True
        assert cleaner.is_split_volume("data.zip.001") is True

        # Generic numeric
        assert cleaner.is_split_volume("largefile.001") is True
        assert cleaner.is_split_volume("largefile.999") is True

        # Non-split files
        assert cleaner.is_split_volume("game.zip") is False
        assert cleaner.is_split_volume("game.rar") is False
        assert cleaner.is_split_volume("game.7z") is False
        assert cleaner.is_split_volume("document.pdf") is False
        assert cleaner.is_split_volume("file.0") is False

    def test_get_volume_index_parsing(self) -> None:
        """Verifies parsing of archive base name and sequence index."""
        cleaner = VolumeCleaner()

        base, idx = cleaner.get_volume_index("game.part1.rar")
        assert base == "game" and idx == 1

        base, idx = cleaner.get_volume_index("Cyberpunk.part07.rar")
        assert base == "Cyberpunk" and idx == 7

        base, idx = cleaner.get_volume_index("archive.7z.003")
        assert base == "archive" and idx == 3

        base, idx = cleaner.get_volume_index("setup.z02")
        assert base == "setup" and idx == 2

        base, idx = cleaner.get_volume_index("data.004")
        assert base == "data" and idx == 4

        with pytest.raises(ValueError, match="Not a recognized split archive"):
            cleaner.get_volume_index("single_archive.zip")

    def test_unlink_volume_success(self, tmp_path) -> None:
        """Tests successful unlinking of an existing volume file."""
        cleaner = VolumeCleaner()
        vol = tmp_path / "game.part1.rar"
        vol.write_bytes(b"volume data")
        assert vol.exists()

        result = cleaner.unlink_volume(vol)
        assert result is True
        assert not vol.exists()

    def test_unlink_non_existent_volume_raises(self, tmp_path) -> None:
        """Tests that unlinking a non-existent file raises FileNotFoundError."""
        cleaner = VolumeCleaner()
        missing = tmp_path / "does_not_exist.part1.rar"
        with pytest.raises(FileNotFoundError):
            cleaner.unlink_volume(missing)

    @pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows file attributes")
    def test_unlink_read_only_volume(self, tmp_path) -> None:
        """Verifies that read-only attribute is automatically stripped before unlinking."""
        cleaner = VolumeCleaner()
        vol = tmp_path / "readonly.z01"
        vol.write_bytes(b"locked volume")

        # Mark read-only via kernel32
        k32 = ctypes.WinDLL("kernel32")
        k32.SetFileAttributesW(str(vol), 0x00000001)  # FILE_ATTRIBUTE_READONLY
        assert bool(k32.GetFileAttributesW(str(vol)) & 0x00000001)

        result = cleaner.unlink_volume(vol)
        assert result is True
        assert not vol.exists()

    def test_unlink_retry_and_exhaustion(self, tmp_path) -> None:
        """Verifies retry backoff and final VolumeCleanError when unlinking permanently fails."""
        cleaner = VolumeCleaner()
        vol = tmp_path / "locked.part1.rar"
        vol.write_bytes(b"content")

        with patch("os.unlink", side_effect=PermissionError("Access is denied")):
            with pytest.raises(VolumeCleanError, match="Failed to unlink volume"):
                cleaner.unlink_volume(vol, max_retries=2, retry_delay=0.01)


# ---------------------------------------------------------------------------
# HeadroomMonitor Tests
# ---------------------------------------------------------------------------


class TestHeadroomMonitor:
    """Tests for disk free space and safety headroom monitoring."""

    def test_real_disk_space_query(self) -> None:
        """Queries actual disk free and total space on the current workspace volume."""
        monitor = HeadroomMonitor()
        workspace = os.path.abspath(".")

        free_space = monitor.get_free_space(workspace)
        total_space = monitor.get_total_space(workspace)

        assert isinstance(free_space, int)
        assert isinstance(total_space, int)
        assert free_space > 0
        assert total_space > free_space

    def test_check_headroom_logic(self) -> None:
        """Verifies threshold calculation logic."""
        monitor = HeadroomMonitor()

        with patch.object(monitor, "get_free_space", return_value=10 * 1024 * 1024 * 1024):  # 10 GB
            # 1GB required with 512MB cushion -> 10GB - 1GB = 9GB >= 512MB -> True
            assert monitor.check_headroom("dummy", required_bytes=1024**3, min_headroom_cushion=512 * 1024**2) is True

            # 9.8GB required with 512MB cushion -> 10GB - 9.8GB = 200MB < 512MB -> False
            assert monitor.check_headroom("dummy", required_bytes=int(9.8 * 1024**3), min_headroom_cushion=512 * 1024**2) is False

    def test_ensure_headroom_raises_on_shortage(self) -> None:
        """Verifies LowHeadroomError is raised with diagnostic attributes when threshold breached."""
        monitor = HeadroomMonitor()

        with patch.object(monitor, "get_free_space", return_value=2 * 1024 * 1024 * 1024):  # 2 GB
            # Squeezing 1.8 GB into 2 GB with 512 MB cushion leaves only 200 MB (< 512 MB)
            cushion = 512 * 1024 * 1024
            req = int(1.8 * 1024 * 1024 * 1024)

            with pytest.raises(LowHeadroomError) as exc_info:
                monitor.ensure_headroom("d:\\target", required_bytes=req, min_headroom_cushion=cushion)

            err = exc_info.value
            assert err.free_bytes == 2 * 1024 * 1024 * 1024
            assert err.required_bytes == req
            assert err.cushion_bytes == cushion
            assert err.shortage_bytes > 0
            assert "Insufficient disk headroom" in str(err)


# ---------------------------------------------------------------------------
# SpaceReclaimer Unified Interface Integration Tests
# ---------------------------------------------------------------------------


class TestSpaceReclaimerIntegration:
    """Integration tests verifying the ISpaceReclaimer contract implementation."""

    def test_contract_compliance(self) -> None:
        """Verifies SpaceReclaimer conforms to ISpaceReclaimer abstract contract."""
        reclaimer = SpaceReclaimer()
        assert isinstance(reclaimer, ISpaceReclaimer)

    def test_unified_reclaimer_operations(self, tmp_path) -> None:
        """Exercises all four reclaimer operations through unified interface."""
        reclaimer = SpaceReclaimer()

        # 1. Headroom query
        free_bytes = reclaimer.get_free_headroom(tmp_path)
        assert free_bytes > 0

        # 2. Tail truncation
        t_file = tmp_path / "reclaimer_trunc.bin"
        t_file.write_bytes(b"M" * 8000)
        freed = reclaimer.truncate_tail(t_file, 3000)
        assert freed == 5000
        assert t_file.stat().st_size == 3000

        # 3. Volume unlinking
        v_file = tmp_path / "part01.rar"
        v_file.write_bytes(b"volume data")
        assert v_file.exists()
        reclaimer.unlink_volume(v_file)
        assert not v_file.exists()

        # 4. Sparse punch hole
        if reclaimer.sparse.is_sparse_supported(tmp_path):
            s_file = tmp_path / "reclaimer_sparse.bin"
            s_file.write_bytes(b"S" * (128 * 1024))
            hole_freed = reclaimer.punch_hole(s_file, 0, 65536)
            assert hole_freed == 65536
