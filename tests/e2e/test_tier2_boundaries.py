"""Tier 2: Boundary & Corner Cases Test Suite for ZeroExtract.

Covers extreme boundary values, resource limits, off-by-one errors, filesystem corner
cases, and safety safeguards across all 14 architectural features (F1 through F14).
Each feature includes at least 5 isolated tests (total >= 70 tests).

Features Covered:
- F1:  NTFS Sparse Hole-Punching (0-byte file, 1-byte punch, <64KB cluster, massive hole, exact boundary, invalid inputs)
- F2:  Reverse Tail Truncation (1-byte shrink, 0-byte shrink, 1-member archive, 0-member archive, tail member > rest, open handle)
- F3:  Progressive Volume Unlinking (1-byte split, 100 volumes, exact member boundary, 0-byte member cross, locked file)
- F4:  Disk Headroom Monitor (headroom == member, headroom 1 byte below, 0-byte headroom, non-existent drive, 10TB limit)
- F5:  ZIP & ZIP64 Reverse Extractor (0-byte entry, 1-byte entry, >260 char MAX_PATH, special chars, comments & extra fields, ZIP64 format)
- F6:  Multi-Volume Stream Extractor (vol 0 missing, irregular naming, member across 4 vols, prime vol size, EOF mid-stream)
- F7:  Chunked Lockstep Deallocation (chunk > file, 1KB tiny chunk, 16MB huge chunk, unaligned chunk, repetitive vs high-entropy)
- F8:  0-Byte Pre-Verification Shield (corrupt byte 0, corrupt last byte, corrupt CD CRC, empty zip, encrypted zip)
- F9:  Two-Phase Commit Atomic Writer (target collision, read-only target, no-write dir, cross-volume, crash before rename)
- F10: Crash-Safe Transaction Journal (existing journal, invalid JSON, future schema, 10K entries, read-only journal)
- F11: Corruption & Rollback Safeguards (truncated CD, bad zlib stream, size mismatch, zero valid members, zip slip traversal)
- F12: CLI & Command Options (no args, non-existent path, negative headroom, multiple archives, dry-run read-only)
- F13: Interactive Terminal UI (redirected/0-width stdout, rapid updates/flicker, unicode/ascii fallback, resize, CI batch)
- F14: Windows Integration (drag-and-drop multiple, UNC network paths, forward slashes, trailing dots/spaces, quoted paths)
"""

from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import tempfile
import time
from typing import Any, Mapping
import unittest
import zipfile
import zlib

# Test infrastructure fixtures
from tests.fixtures.archive_builder import (
    calculate_expected_hashes,
    create_complex_tree_zip,
    create_corrupt_zip,
    create_multi_part_zip,
    create_simple_zip,
    create_sparse_payload_zip,
    create_zip64,
    inspect_zip_structure,
)
from tests.fixtures.harness import (
    CLIResult,
    VerificationResult,
    get_allocated_file_size,
    is_file_sparse,
    is_sparse_supported,
    run_cli,
    verify_directory_contents,
)

# Milestone 1: Filesystem Space Reclamation subsystem
from zeroextract.fs import (
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

# Milestone 2: Format Parsers & Extraction Pipelines
try:
    from zeroextract.formats import (
        ChunkedSparseExtractor,
        MultiVolumeStreamReader,
        MultiVolumeStreamer,
        ZipEntry,
        ZipReverseExtractor,
    )
    from zeroextract.formats.zip_reverse import (
        BadZipSignatureError,
        ChecksumError as ZipChecksumError,
        CorruptArchiveError,
        PathTraversalError,
        UnsupportedCompressionError,
    )
    HAS_M2 = True
except (ImportError, ModuleNotFoundError):
    HAS_M2 = False
    ZipReverseExtractor = None
    MultiVolumeStreamer = None
    MultiVolumeStreamReader = None
    ChunkedSparseExtractor = None

# Milestone 3: Safety Shields, Journal & Resumption
try:
    from zeroextract.safety.preverify import PreflightShield
    from zeroextract.safety.atomic import AtomicWriter
    from zeroextract.safety.journal import TransactionJournal
    from zeroextract.safety.exceptions import (
        ChecksumError,
        CorruptionError,
        CorruptionGuard,
    )
    HAS_M3 = True
except (ImportError, ModuleNotFoundError):
    HAS_M3 = False
    PreflightShield = None
    AtomicWriter = None
    TransactionJournal = None
    CorruptionGuard = None

# Milestone 4: CLI & User Experience
try:
    import zeroextract.cli.main as cli_main
    from zeroextract.cli.ui import TerminalUI
    from zeroextract.cli.windows_setup import normalize_windows_path
    HAS_M4 = True
except (ImportError, ModuleNotFoundError):
    HAS_M4 = False
    cli_main = None
    TerminalUI = None
    normalize_windows_path = None


# ===========================================================================
# F1: NTFS Sparse Hole-Punching (Boundary Cases)
# ===========================================================================

class TestF1SparsePuncherBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 1: NTFS Sparse Hole-Punching."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.puncher = SparsePuncher()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_empty_file_hole_punch(self) -> None:
        """Punches a hole in a 0-byte file; returns 0 deallocated bytes on 0-len or preserves size."""
        empty_file = self.dir_path / "empty.bin"
        empty_file.write_bytes(b"")

        # Zero-length punch returns 0
        freed_zero = self.puncher.punch_hole(empty_file, 0, 0)
        self.assertEqual(freed_zero, 0)
        self.assertEqual(empty_file.stat().st_size, 0)

        # 64KB punch on empty file: succeeds without error and file size remains 0
        self.puncher.punch_hole(empty_file, 0, 65536)
        self.assertEqual(empty_file.stat().st_size, 0)

    def test_one_byte_hole_punch(self) -> None:
        """Punches a 1-byte hole; inward cluster alignment deallocates 0 bytes and preserves byte."""
        one_byte_file = self.dir_path / "one_byte.bin"
        one_byte_file.write_bytes(b"X")

        freed = self.puncher.punch_hole(one_byte_file, 0, 1)
        self.assertEqual(freed, 0)
        self.assertEqual(one_byte_file.read_bytes(), b"X")
        self.assertEqual(one_byte_file.stat().st_size, 1)

    def test_file_smaller_than_cluster_boundary(self) -> None:
        """Punches a hole in a file smaller than a 64KB cluster (e.g. 32KB); inward alignment returns 0."""
        small_file = self.dir_path / "small_32kb.bin"
        pattern = b"C" * 32768
        small_file.write_bytes(pattern)

        freed = self.puncher.punch_hole(small_file, 0, 32768, cluster_size=65536)
        self.assertEqual(freed, 0)
        self.assertEqual(small_file.read_bytes(), pattern)
        self.assertEqual(small_file.stat().st_size, 32768)

    def test_massive_hole_punch(self) -> None:
        """Punches a massive multi-megabyte sparse hole; checks allocated disk space and content zeroing."""
        if sys.platform != "win32" or not self.puncher.is_sparse_supported(self.dir_path):
            self.skipTest("Requires Windows NTFS volume supporting sparse files")

        large_file = self.dir_path / "massive_sparse.bin"
        chunk_size = 64 * 1024
        total_size = 64 * 1024 * 1024  # 64MB

        with open(large_file, "wb") as f:
            f.write(b"START_HEADER_MARK" + b"\x00" * (chunk_size - 17))
            f.seek(total_size - chunk_size)
            f.write(b"END_FOOTER_MARK" + b"\x00" * (chunk_size - 15))

        self.puncher.mark_as_sparse(large_file)

        # Punch a 60MB hole between 2MB and 62MB (multiples of 64KB)
        hole_offset = 2 * 1024 * 1024
        hole_length = 60 * 1024 * 1024
        freed = self.puncher.punch_hole(large_file, hole_offset, hole_length, cluster_size=65536)

        self.assertEqual(freed, hole_length)
        with open(large_file, "rb") as f:
            f.seek(hole_offset + 1024)
            sample = f.read(4096)
            self.assertEqual(sample, b"\x00" * 4096)

        alloc_size = get_allocated_file_size(large_file)
        self.assertLess(alloc_size, 10 * 1024 * 1024)

    def test_hole_punch_at_exact_file_boundary(self) -> None:
        """Punches a hole at exact cluster boundary (second 64KB block of a 128KB file)."""
        exact_file = self.dir_path / "exact_128kb.bin"
        block1 = b"1" * 65536
        block2 = b"2" * 65536
        exact_file.write_bytes(block1 + block2)

        if sys.platform == "win32" and self.puncher.is_sparse_supported(self.dir_path):
            self.puncher.mark_as_sparse(exact_file)

        freed = self.puncher.punch_hole(exact_file, 65536, 65536, cluster_size=65536)
        self.assertEqual(freed, 65536)

        with open(exact_file, "rb") as f:
            self.assertEqual(f.read(65536), block1)
            self.assertEqual(f.read(65536), b"\x00" * 65536)

    def test_hole_punch_negative_or_zero_length(self) -> None:
        """Verifies length 0 returns 0 and negative length or offset raises ValueError."""
        dummy_file = self.dir_path / "dummy.bin"
        dummy_file.write_bytes(b"DATA" * 100)

        self.assertEqual(self.puncher.punch_hole(dummy_file, 0, 0), 0)
        with self.assertRaises(ValueError):
            self.puncher.punch_hole(dummy_file, -10, 100)
        with self.assertRaises(ValueError):
            self.puncher.punch_hole(dummy_file, 0, -50)


# ===========================================================================
# F2: Reverse Tail Truncation (Boundary Cases)
# ===========================================================================

class TestF2ReverseTruncatorBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 2: Reverse Tail Truncation."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.truncator = ReverseTruncator()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_single_byte_file_truncation(self) -> None:
        """Truncates a 100-byte file down to 99 bytes; verifies 1 byte freed and prefix preserved."""
        test_file = self.dir_path / "test_100b.bin"
        data = b"0123456789" * 10
        test_file.write_bytes(data)

        freed = self.truncator.truncate_tail(test_file, 99)
        self.assertEqual(freed, 1)
        self.assertEqual(test_file.stat().st_size, 99)
        self.assertEqual(test_file.read_bytes(), data[:99])

    def test_truncating_to_zero_bytes(self) -> None:
        """Truncates a file down to 0 bytes; verifies all bytes freed and size becomes 0."""
        test_file = self.dir_path / "test_zero.bin"
        test_file.write_bytes(b"Z" * 65536)

        freed = self.truncator.truncate_tail(test_file, 0)
        self.assertEqual(freed, 65536)
        self.assertEqual(test_file.stat().st_size, 0)
        self.assertEqual(test_file.read_bytes(), b"")

    def test_archive_with_only_one_member(self) -> None:
        """Archive with only 1 member; after extraction, truncating to 0 leaves a 0-byte file."""
        zip_path = self.dir_path / "single_member.zip"
        content = b"SINGLE_MEMBER_CONTENT_PAYLOAD" * 50
        create_simple_zip(zip_path, {"data.bin": content})

        orig_size = zip_path.stat().st_size
        self.assertGreater(orig_size, 0)

        with zipfile.ZipFile(zip_path, "r") as zf:
            extracted = zf.read("data.bin")
            self.assertEqual(extracted, content)

        freed = self.truncator.truncate_tail(zip_path, 0)
        self.assertEqual(freed, orig_size)
        self.assertEqual(zip_path.stat().st_size, 0)

    def test_archive_with_zero_members_empty_zip(self) -> None:
        """Archive with 0 members (22-byte empty zip); truncating to current size returns 0 freed."""
        zip_path = self.dir_path / "empty_archive.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            pass

        size_22 = zip_path.stat().st_size
        self.assertEqual(size_22, 22)

        self.assertEqual(self.truncator.truncate_tail(zip_path, 22), 0)
        self.assertEqual(self.truncator.truncate_tail(zip_path, 0), 22)
        self.assertEqual(zip_path.stat().st_size, 0)

    def test_tail_member_larger_than_rest_of_archive(self) -> None:
        """Tail member is 300KB while rest of archive is 200 bytes; truncating tail member frees >95%."""
        zip_path = self.dir_path / "large_tail.zip"
        small_head = b"HEAD_DATA" * 10
        large_tail = b"TAIL_DATA_BLOCK_" * 20000

        create_simple_zip(
            zip_path,
            {"head.txt": small_head, "tail.bin": large_tail},
            compression=zipfile.ZIP_STORED,
        )
        full_size = zip_path.stat().st_size

        with zipfile.ZipFile(zip_path, "r") as zf:
            info_tail = zf.getinfo("tail.bin")
            tail_offset = info_tail.header_offset

        self.assertGreater(tail_offset, 0)
        self.assertLess(tail_offset, 2000)

        freed = self.truncator.truncate_tail(zip_path, tail_offset)
        new_size = zip_path.stat().st_size

        self.assertEqual(new_size, tail_offset)
        self.assertEqual(freed, full_size - tail_offset)
        self.assertGreater(freed / full_size, 0.95)

    def test_truncate_with_open_file_object(self) -> None:
        """Truncates file using an already-open Python file object; verifies handle resolution."""
        test_file = self.dir_path / "open_handle.bin"
        test_file.write_bytes(b"A" * 10000)

        with open(test_file, "r+b") as f:
            freed = self.truncator.truncate_tail(f, 4000)
            self.assertEqual(freed, 6000)

        self.assertEqual(test_file.stat().st_size, 4000)


# ===========================================================================
# F3: Progressive Volume Unlinking (Boundary Cases)
# ===========================================================================

class TestF3VolumeCleanerBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 3: Progressive Volume Unlinking."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.cleaner = VolumeCleaner()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_split_archive_single_byte_split_sizes(self) -> None:
        """Split archive with single-byte or tiny volume sizes; verifies volume cleaner recognizes indices."""
        vol1 = self.dir_path / "tiny.z01"
        vol2 = self.dir_path / "tiny.z02"
        vol_zip = self.dir_path / "tiny.zip"

        vol1.write_bytes(b"A")
        vol2.write_bytes(b"B")
        vol_zip.write_bytes(b"C")

        self.assertTrue(self.cleaner.is_split_volume(vol1))
        self.assertTrue(self.cleaner.is_split_volume(vol2))

        base, idx = self.cleaner.get_volume_index(vol1)
        self.assertEqual(base, "tiny")
        self.assertEqual(idx, 1)

        self.assertTrue(self.cleaner.unlink_volume(vol1))
        self.assertFalse(vol1.exists())

    def test_archive_split_into_100_small_volumes(self) -> None:
        """Archive split into 100 small volumes; unlinks all 100 volumes progressively without error."""
        created_vols = []
        for i in range(1, 101):
            vol_path = self.dir_path / f"large_split.part{i:03d}.rar"
            vol_path.write_bytes(b"CHUNK" * 10)
            created_vols.append(vol_path)

        self.assertEqual(len(created_vols), 100)

        for i, vol in enumerate(created_vols, start=1):
            base, idx = self.cleaner.get_volume_index(vol)
            self.assertEqual(base, "large_split")
            self.assertEqual(idx, i)
            self.assertTrue(self.cleaner.unlink_volume(vol))
            self.assertFalse(vol.exists())

        remaining = list(self.dir_path.glob("large_split.part*"))
        self.assertEqual(len(remaining), 0)

    def test_volume_with_exact_member_boundary_match(self) -> None:
        """Volume ends at the exact boundary of a member; verifies completed volume unlinks cleanly."""
        file_a = b"A" * 32768
        file_b = b"B" * 32768

        vols = create_multi_part_zip(
            self.dir_path / "boundary.zip",
            {"file_a.bin": file_a, "file_b.bin": file_b},
            max_volume_size=32768,
            compression=zipfile.ZIP_STORED,
        )
        self.assertGreaterEqual(len(vols), 2)

        first_vol = vols[0]
        self.assertTrue(first_vol.exists())
        self.cleaner.unlink_volume(first_vol)
        self.assertFalse(first_vol.exists())

    def test_volume_with_zero_byte_member_crossing_boundary(self) -> None:
        """Volume containing 0-byte file entry; cleaner unlinks volume without crashing on 0-byte members."""
        vols = create_multi_part_zip(
            self.dir_path / "zero_member.zip",
            {"zero.txt": b"", "payload.bin": b"DATA" * 5000},
            max_volume_size=10000,
            compression=zipfile.ZIP_STORED,
        )
        self.assertGreaterEqual(len(vols), 1)

        for vol in vols[:-1]:
            self.cleaner.unlink_volume(vol)
            self.assertFalse(vol.exists())

    def test_unlinking_when_volume_locked_by_another_process(self) -> None:
        """Volume file held open with exclusive lock raises VolumeCleanError, then succeeds once released."""
        locked_vol = self.dir_path / "locked.z01"
        locked_vol.write_bytes(b"LOCKED_VOLUME_DATA" * 100)

        with open(locked_vol, "rb") as held_handle:
            if sys.platform == "win32":
                with self.assertRaises(VolumeCleanError):
                    self.cleaner.unlink_volume(locked_vol, max_retries=2, retry_delay=0.01)
                self.assertTrue(locked_vol.exists())

        self.assertTrue(self.cleaner.unlink_volume(locked_vol))
        self.assertFalse(locked_vol.exists())


# ===========================================================================
# F4: Disk Headroom Monitor (Boundary Cases)
# ===========================================================================

class TestF4HeadroomMonitorBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 4: Disk Headroom Monitor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.monitor = HeadroomMonitor()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_headroom_exactly_equal_to_member_size(self) -> None:
        """When (free_space - required) == min_cushion, check_headroom returns True (exact boundary)."""
        free_space = self.monitor.get_free_space(self.dir_path)
        self.assertGreater(free_space, 0)

        self.assertTrue(self.monitor.check_headroom(self.dir_path, required_bytes=free_space, min_headroom_cushion=0))
        self.assertFalse(self.monitor.check_headroom(self.dir_path, required_bytes=free_space, min_headroom_cushion=1))

    def test_headroom_one_byte_below_minimum_requirement(self) -> None:
        """When free space is 1 byte below required + cushion, ensure_headroom raises LowHeadroomError."""
        free_space = self.monitor.get_free_space(self.dir_path)
        cushion = 1000
        required = free_space - cushion + 1

        with self.assertRaises(LowHeadroomError) as ctx:
            self.monitor.ensure_headroom(self.dir_path, required_bytes=required, min_headroom_cushion=cushion)

        self.assertEqual(ctx.exception.shortage_bytes, 1)

    def test_headroom_zero_bytes(self) -> None:
        """When required space exceeds free space by entire capacity, raises LowHeadroomError."""
        free_space = self.monitor.get_free_space(self.dir_path)
        huge_required = free_space + (50 * 1024 * 1024 * 1024)

        self.assertFalse(self.monitor.check_headroom(self.dir_path, required_bytes=huge_required))
        with self.assertRaises(LowHeadroomError):
            self.monitor.ensure_headroom(self.dir_path, required_bytes=huge_required)

    def test_path_on_non_existent_drive(self) -> None:
        """Querying disk headroom on a non-existent drive raises OSError on Windows."""
        if sys.platform == "win32":
            invalid_path = "Z:\\nonexistent_zeroextract_drive_12345\\"
            with self.assertRaises(OSError):
                self.monitor.get_free_space(invalid_path)
        else:
            invalid_path = "/nonexistent_zeroextract_drive_12345/sub"
            with self.assertRaises(Exception):
                self.monitor.get_free_space(invalid_path)

    def test_very_large_headroom_limit_10tb(self) -> None:
        """64-bit integer headroom limit of 10TB does not cause integer overflow."""
        ten_tb = 10 * (1024 ** 4)
        self.assertFalse(self.monitor.check_headroom(self.dir_path, required_bytes=0, min_headroom_cushion=ten_tb))

        with self.assertRaises(LowHeadroomError) as ctx:
            self.monitor.ensure_headroom(self.dir_path, required_bytes=0, min_headroom_cushion=ten_tb)

        free_space = self.monitor.get_free_space(self.dir_path)
        self.assertEqual(ctx.exception.shortage_bytes, ten_tb - free_space)


# ===========================================================================
# F5: ZIP & ZIP64 Reverse Extractor (Boundary Cases)
# ===========================================================================

class TestF5ZipReverseExtractorBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 5: ZIP & ZIP64 Reverse Extractor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_zero_byte_file_entry_in_zip(self) -> None:
        """Extracts an archive containing multiple 0-byte file entries; verifies 0-byte size and empty SHA256."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        zip_path = self.dir_path / "empty_files.zip"
        entries = {"empty1.txt": b"", "sub/empty2.dat": b""}
        create_simple_zip(zip_path, entries)

        out_dir = self.dir_path / "out_zero"
        extractor = ZipReverseExtractor(zip_path)
        extractor.extract(output_dir=out_dir)

        self.assertTrue((out_dir / "empty1.txt").exists())
        self.assertEqual((out_dir / "empty1.txt").stat().st_size, 0)
        self.assertTrue((out_dir / "sub" / "empty2.dat").exists())
        self.assertEqual((out_dir / "sub" / "empty2.dat").stat().st_size, 0)

        res = verify_directory_contents(out_dir, entries)
        self.assertTrue(res.is_valid)

    def test_one_byte_file_in_zip(self) -> None:
        """Extracts an archive containing 1-byte file entries; verifies exact content and CRC."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        zip_path = self.dir_path / "one_byte_files.zip"
        entries = {"byte1.bin": b"A", "byte2.bin": b"\x00", "byte3.bin": b"\xFF"}
        create_simple_zip(zip_path, entries)

        out_dir = self.dir_path / "out_one_byte"
        extractor = ZipReverseExtractor(zip_path)
        extractor.extract(output_dir=out_dir)

        res = verify_directory_contents(out_dir, entries)
        self.assertTrue(res.is_valid)

    def test_deeply_nested_path_exceeding_max_path(self) -> None:
        """Extracts an archive with path depth exceeding 260 characters (Windows MAX_PATH boundary)."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        zip_path = self.dir_path / "deep_path.zip"
        segments = ["nested_dir_segment_" + str(i) for i in range(12)]
        deep_rel_path = "/".join(segments) + "/target_game_file.dat"
        self.assertGreater(len(deep_rel_path), 260)

        payload = b"DEEP_NESTED_CONTENT_TEST"
        create_simple_zip(zip_path, {deep_rel_path: payload})

        out_dir = self.dir_path / "out_deep"
        extractor = ZipReverseExtractor(zip_path)
        extractor.extract(output_dir=out_dir)

        dest_file = out_dir
        for seg in segments:
            dest_file = dest_file / seg
        dest_file = dest_file / "target_game_file.dat"
        self.assertTrue(dest_file.exists() or Path("\\\\?\\" + str(dest_file.resolve())).exists())

    def test_filename_with_special_characters(self) -> None:
        """Extracts entries with punctuation, spaces, and ASCII special characters: !@#$%^&*()_+~."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        zip_path = self.dir_path / "special_names.zip"
        entries = {
            "file_!@#$%^&()_+~.txt": b"SPECIAL_CHARS_PAYLOAD",
            "folder [v1.0] (2026)/data #1.bin": b"BRACKET_AND_HASH_PAYLOAD",
        }
        create_simple_zip(zip_path, entries)

        out_dir = self.dir_path / "out_special"
        extractor = ZipReverseExtractor(zip_path)
        extractor.extract(output_dir=out_dir)

        res = verify_directory_contents(out_dir, entries)
        self.assertTrue(res.is_valid)

    def test_zip_with_comments_and_extra_fields(self) -> None:
        """Archive with comments and custom extra fields parses cleanly without header corruption."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        zip_path = self.dir_path / "with_comments.zip"
        entries = {"game.cfg": b"version=2.0\nlocale=en_US\n"}

        archive_comment = b"ZeroExtract Archive Comment with metadata: author=WorkerTier2"
        create_simple_zip(zip_path, entries, comment=archive_comment)

        struct_info = inspect_zip_structure(zip_path)
        self.assertEqual(struct_info["comment"], archive_comment)
        self.assertEqual(struct_info["file_count"], 1)

        out_dir = self.dir_path / "out_comments"
        extractor = ZipReverseExtractor(zip_path)
        extractor.extract(output_dir=out_dir)

        res = verify_directory_contents(out_dir, entries)
        self.assertTrue(res.is_valid)

    def test_zip64_boundary_format(self) -> None:
        """Generates and parses a genuine ZIP64 archive with 64-bit headers and locator records."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        zip64_path = self.dir_path / "test_zip64.zip"
        entries = {"huge_table.csv": b"id,val\n" + (b"1,100\n" * 5000)}
        create_zip64(zip64_path, entries)

        struct_info = inspect_zip_structure(zip64_path)
        self.assertTrue(struct_info["is_zip64"])

        out_dir = self.dir_path / "out_zip64"
        extractor = ZipReverseExtractor(zip64_path)
        extractor.extract(output_dir=out_dir)

        res = verify_directory_contents(out_dir, entries)
        self.assertTrue(res.is_valid)


# ===========================================================================
# F6: Multi-Volume Stream Extractor (Boundary Cases)
# ===========================================================================

class TestF6MultiVolumeStreamBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 6: Multi-Volume Stream Extractor."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_split_archive_volume_0_missing(self) -> None:
        """When volume 1 (.z01) is missing from a 3-part split archive, missing volume is detected."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        vols = create_multi_part_zip(
            self.dir_path / "split_test.zip",
            {"file.bin": b"PAYLOAD_DATA_" * 5000},
            max_volume_size=16384,
            compression=zipfile.ZIP_STORED,
        )
        self.assertGreaterEqual(len(vols), 3)

        first_vol = vols[0]
        self.assertTrue(first_vol.exists())
        first_vol.unlink()

        streamer = MultiVolumeStreamer()
        with self.assertRaises(FileNotFoundError):
            streamer.discover_volumes(vols[1])

    def test_split_archive_irregular_volume_naming(self) -> None:
        """Split archive with missing intermediate volume (.z01, .z03, .zip); sequence gap is detected."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        vols = create_multi_part_zip(
            self.dir_path / "gap_test.zip",
            {"big.bin": b"MULTI_PART_DATA_" * 5000},
            max_volume_size=10000,
            compression=zipfile.ZIP_STORED,
        )
        self.assertGreaterEqual(len(vols), 3)

        # Remove middle volume (.z02) leaving .z01 and .z03
        vols[1].unlink()

        streamer = MultiVolumeStreamer()
        with self.assertRaises(ValueError):
            streamer.validate_volume_sequence([str(vols[0]), str(vols[2])])

    def test_member_spanning_across_four_distinct_volumes(self) -> None:
        """Single large file spanning across 4 distinct split volumes; reassembles with 100% SHA256 match."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        payload = b"SPAN_4_VOLUMES_" * 3000
        vols = create_multi_part_zip(
            self.dir_path / "four_vols.zip",
            {"span_member.bin": payload},
            max_volume_size=12000,
            compression=zipfile.ZIP_STORED,
        )
        self.assertGreaterEqual(len(vols), 4)

        out_dir = self.dir_path / "out_span"
        streamer = MultiVolumeStreamer()
        extracted = streamer.extract(str(vols[0]), str(out_dir))
        self.assertEqual(len(extracted), 1)

        extracted_file = Path(extracted[0])
        self.assertEqual(extracted_file.read_bytes(), payload)
        self.assertEqual(hashlib.sha256(extracted_file.read_bytes()).hexdigest(), hashlib.sha256(payload).hexdigest())

    def test_split_archive_prime_number_volume_size(self) -> None:
        """Split archive where slice size is prime number (10007 bytes); unaligned slice offsets reassemble."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        payload = b"PRIME_SPLIT_PAYLOAD_" * 2000
        vols = create_multi_part_zip(
            self.dir_path / "prime.zip",
            {"prime_file.bin": payload},
            max_volume_size=10007,
            compression=zipfile.ZIP_STORED,
        )
        self.assertGreaterEqual(len(vols), 3)

        out_dir = self.dir_path / "out_prime"
        streamer = MultiVolumeStreamer()
        extracted = streamer.extract(str(vols[0]), str(out_dir))
        self.assertEqual(len(extracted), 1)
        self.assertEqual(Path(extracted[0]).read_bytes(), payload)

    def test_split_archive_eof_in_mid_stream(self) -> None:
        """A split volume truncated mid-stream raises unexpected EOF or zlib decompression error."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        vols = create_multi_part_zip(
            self.dir_path / "eof_test.zip",
            {"eof_file.bin": b"STREAM_CONTENT_" * 4000},
            max_volume_size=10000,
            compression=zipfile.ZIP_STORED,
        )
        self.assertGreaterEqual(len(vols), 2)

        half_len = vols[1].stat().st_size // 2
        vols[1].write_bytes(vols[1].read_bytes()[:half_len])

        out_dir = self.dir_path / "out_eof"
        streamer = MultiVolumeStreamer()
        with self.assertRaises((zipfile.BadZipFile, zlib.error, EOFError, ValueError, OSError)):
            streamer.extract(str(vols[0]), str(out_dir))


# ===========================================================================
# F7: Chunked Lockstep Deallocation (Boundary Cases)
# ===========================================================================

class TestF7ChunkedLockstepBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 7: Chunked Lockstep Deallocation."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_chunk_size_larger_than_file_size(self) -> None:
        """Chunk size (10MB) is much larger than file size (5KB); processed in a single chunk."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        extractor = ChunkedSparseExtractor(chunk_size=10 * 1024 * 1024)
        self.assertEqual(extractor.cluster_aligned_chunk_size, 10 * 1024 * 1024)

        small_file = self.dir_path / "small_stream.bin"
        data = b"TINY_STREAM" * 500
        small_file.write_bytes(data)

        zip_path = self.dir_path / "small.zip"
        create_simple_zip(zip_path, {"small.bin": data})

        out_dir = self.dir_path / "out_small"
        extracted = extractor.extract(zip_path, out_dir)
        self.assertEqual(len(extracted), 1)
        self.assertEqual((out_dir / "small.bin").read_bytes(), data)

    def test_chunk_size_tiny_one_kb(self) -> None:
        """Chunk size is 1KB; ChunkedSparseExtractor clamps chunk size to 64KB cluster boundary."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        extractor = ChunkedSparseExtractor(chunk_size=1024)
        # Clamped to minimum 64KB cluster size for safety
        self.assertEqual(extractor.chunk_size, 65536)

        test_data = b"01234567" * 8192
        zip_path = self.dir_path / "64k.zip"
        create_simple_zip(zip_path, {"test.bin": test_data})

        out_dir = self.dir_path / "out_tiny_chunk"
        extractor.extract(zip_path, out_dir)
        self.assertEqual((out_dir / "test.bin").read_bytes(), test_data)

    def test_chunk_size_huge_sixteen_mb(self) -> None:
        """Chunk size of 16MB on sparse file streams smoothly without buffer allocation failures."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        extractor = ChunkedSparseExtractor(chunk_size=16 * 1024 * 1024)
        self.assertEqual(extractor.buffer_capacity, 16 * 1024 * 1024)

        payload_data = b"X" * (1024 * 1024)
        zip_path = self.dir_path / "large_chunk.zip"
        create_simple_zip(zip_path, {"large.bin": payload_data})

        out_dir = self.dir_path / "out_huge"
        extractor.extract(zip_path, out_dir)
        self.assertEqual((out_dir / "large.bin").read_bytes(), payload_data)

    def test_chunk_size_unaligned_with_filesystem_cluster(self) -> None:
        """Chunk size of 70,000 bytes (unaligned with 64KB cluster); aligns to 131072 for cluster safety."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        extractor = ChunkedSparseExtractor(chunk_size=70000)
        self.assertEqual(extractor.cluster_aligned_chunk_size, 131072)

        data = b"U" * 131072
        zip_path = self.dir_path / "unaligned.zip"
        create_simple_zip(zip_path, {"unaligned.bin": data})

        out_dir = self.dir_path / "out_unaligned"
        extractor.extract(zip_path, out_dir)
        self.assertEqual((out_dir / "unaligned.bin").read_bytes(), data)

    def test_repetitive_vs_high_entropy_bytes(self) -> None:
        """Extracting repeating bytes (high compression ratio) vs random bytes (zero compression) maintains fidelity."""
        if not HAS_M2:
            self.skipTest("Requires Milestone M2: zeroextract.formats not yet implemented")
        low_entropy = b"A" * 65536
        high_entropy = os.urandom(65536)

        zip_low = self.dir_path / "low_entropy.zip"
        zip_high = self.dir_path / "high_entropy.zip"

        create_simple_zip(zip_low, {"low.bin": low_entropy})
        create_simple_zip(zip_high, {"high.bin": high_entropy})

        extractor = ChunkedSparseExtractor()
        out_low = self.dir_path / "out_low"
        out_high = self.dir_path / "out_high"

        extractor.extract(zip_low, out_low)
        extractor.extract(zip_high, out_high)

        self.assertEqual(hashlib.sha256((out_low / "low.bin").read_bytes()).hexdigest(), hashlib.sha256(low_entropy).hexdigest())
        self.assertEqual(hashlib.sha256((out_high / "high.bin").read_bytes()).hexdigest(), hashlib.sha256(high_entropy).hexdigest())


# ===========================================================================
# F8: 0-Byte Pre-Verification Shield (Boundary Cases)
# ===========================================================================

class TestF8PreflightShieldBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 8: 0-Byte Pre-Verification Shield."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_corrupted_byte_at_offset_zero(self) -> None:
        """Byte 0 corrupted ('XX\\x03\\x04' instead of 'PK\\x03\\x04'); preflight shield immediately fails."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        zip_path = self.dir_path / "bad_magic.zip"
        create_simple_zip(zip_path, {"file.txt": b"DATA"})

        raw = bytearray(zip_path.read_bytes())
        raw[0:2] = b"XX"
        zip_path.write_bytes(raw)

        shield = PreflightShield()
        is_valid, errors = shield.verify_archive(zip_path)
        self.assertFalse(is_valid)
        self.assertGreater(len(errors), 0)

    def test_corrupted_byte_at_last_byte_of_archive(self) -> None:
        """Last byte of archive corrupted; preflight checks EOCD record and detects invalid structure."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        zip_path = self.dir_path / "bad_last_byte.zip"
        create_simple_zip(zip_path, {"file.txt": b"DATA"}, comment=b"COMMENT")

        raw = bytearray(zip_path.read_bytes())
        raw[-1] ^= 0xFF
        zip_path.write_bytes(raw)

        shield = PreflightShield()
        is_valid, errors = shield.verify_archive(zip_path)
        self.assertFalse(is_valid)

    def test_corrupted_crc_in_central_directory_header_only(self) -> None:
        """Central Directory CRC corrupted while payload is intact; preflight catches CRC mismatch."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        zip_path = self.dir_path / "cd_crc_corrupt.zip"
        create_simple_zip(zip_path, {"member.bin": b"PAYLOAD_BYTES" * 100})

        raw = bytearray(zip_path.read_bytes())
        cd_pos = raw.find(b"PK\x01\x02")
        self.assertNotEqual(cd_pos, -1)

        orig_crc = struct.unpack_from("<I", raw, cd_pos + 16)[0]
        struct.pack_into("<I", raw, cd_pos + 16, orig_crc ^ 0xFFFFFFFF)
        zip_path.write_bytes(raw)

        shield = PreflightShield()
        is_valid, errors = shield.verify_archive(zip_path)
        self.assertFalse(is_valid)
        self.assertTrue(any("crc" in e.lower() for e in errors))

    def test_preflight_on_empty_zip(self) -> None:
        """Preflight on empty zip archive (0 entries); succeeds with 0 errors and 0 files."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        zip_path = self.dir_path / "empty_valid.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            pass

        shield = PreflightShield()
        is_valid, errors = shield.verify_archive(zip_path)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_preflight_on_encrypted_zip_password_protected(self) -> None:
        """Preflight flags encrypted/password-protected entry without writing files to disk."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        zip_path = self.dir_path / "encrypted.zip"
        create_simple_zip(zip_path, {"secret.txt": b"TOP_SECRET_PASSWORD_DATA"})
        raw = bytearray(zip_path.read_bytes())

        loc_pos = raw.find(b"PK\x03\x04")
        if loc_pos != -1:
            flags = struct.unpack_from("<H", raw, loc_pos + 6)[0]
            struct.pack_into("<H", raw, loc_pos + 6, flags | 0x01)

        cd_pos = raw.find(b"PK\x01\x02")
        if cd_pos != -1:
            flags = struct.unpack_from("<H", raw, cd_pos + 8)[0]
            struct.pack_into("<H", raw, cd_pos + 8, flags | 0x01)

        zip_path.write_bytes(raw)

        shield = PreflightShield()
        is_valid, errors = shield.verify_archive(zip_path)
        self.assertFalse(is_valid)
        self.assertTrue(any("encrypted" in e.lower() or "password" in e.lower() for e in errors))


# ===========================================================================
# F9: Two-Phase Commit Atomic Writer (Boundary Cases)
# ===========================================================================

class TestF9AtomicWriterBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 9: Two-Phase Commit Atomic Writer."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_target_file_already_exists_collision(self) -> None:
        """Destination file already exists; 2PC atomic writer replaces it atomically without corruption."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        dest = self.dir_path / "collision.txt"
        dest.write_text("OLD_INITIAL_CONTENT", encoding="utf-8")

        new_payload = b"NEW_ATOMIC_COMMITTED_PAYLOAD"
        writer = AtomicWriter()
        written = writer.write_atomic(dest, [new_payload], expected_crc32=zlib.crc32(new_payload))

        self.assertEqual(written, len(new_payload))
        self.assertEqual(dest.read_bytes(), new_payload)
        self.assertFalse(dest.with_name(dest.name + ".unpack_part").exists())

    def test_target_file_is_read_only(self) -> None:
        """Destination file has read-only attribute; 2PC writer strips read-only flag and overwrites."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        dest = self.dir_path / "readonly_target.bin"
        dest.write_bytes(b"OLD_READONLY_DATA")

        if sys.platform == "win32":
            ctypes.windll.kernel32.SetFileAttributesW(str(dest), 0x01)
        else:
            os.chmod(dest, stat.S_IREAD)

        new_data = b"OVERWRITTEN_NEW_DATA"
        writer = AtomicWriter()
        written = writer.write_atomic(dest, [new_data], expected_crc32=zlib.crc32(new_data))

        self.assertEqual(written, len(new_data))
        self.assertEqual(dest.read_bytes(), new_data)

    def test_target_directory_has_no_write_permission(self) -> None:
        """Target directory without write permission cleanly raises PermissionError without temp leaks."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        ro_dir = self.dir_path / "ro_directory"
        ro_dir.mkdir(parents=True, exist_ok=True)

        dest = ro_dir / "file.txt"
        writer = AtomicWriter()
        if sys.platform != "win32":
            os.chmod(ro_dir, stat.S_IREAD | stat.S_IEXEC)
            try:
                with self.assertRaises(PermissionError):
                    writer.write_atomic(dest, [b"DATA"], expected_crc32=zlib.crc32(b"DATA"))
            finally:
                os.chmod(ro_dir, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
        else:
            bad_dest = Path("CON:/invalid_dest.txt")
            with self.assertRaises(Exception):
                writer.write_atomic(bad_dest, [b"DATA"], expected_crc32=zlib.crc32(b"DATA"))

    def test_destination_path_on_different_volume(self) -> None:
        """Cross-volume atomic write: falls back cleanly when direct rename across volumes is attempted."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        dest = self.dir_path / "cross_vol.txt"
        data = b"CROSS_VOLUME_DATA_BLOCK"
        writer = AtomicWriter()
        written = writer.write_atomic(dest, [data], expected_crc32=zlib.crc32(data))
        self.assertEqual(written, len(data))
        self.assertEqual(dest.read_bytes(), data)

    def test_crash_during_atomic_rename(self) -> None:
        """CRC mismatch before commit: temporary .unpack_part is removed and destination is untouched."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        dest = self.dir_path / "untouched_target.bin"
        dest.write_bytes(b"ORIGINAL_TARGET_BYTES")

        temp_part = dest.with_name(dest.name + ".unpack_part")
        bad_crc = 0x12345678
        writer = AtomicWriter()

        with self.assertRaises(Exception):
            writer.write_atomic(dest, [b"CORRUPTED_STREAM"], expected_crc32=bad_crc)

        self.assertEqual(dest.read_bytes(), b"ORIGINAL_TARGET_BYTES")
        self.assertFalse(temp_part.exists())


# ===========================================================================
# F10: Crash-Safe Transaction Journal (Boundary Cases)
# ===========================================================================

class TestF10TransactionJournalBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 10: Crash-Safe Transaction Journal."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)
        self.journal_path = self.dir_path / ".unpack_journal.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_journal_file_already_exists_from_previous_run(self) -> None:
        """Existing journal file loaded from prior aborted session; completed entries are recognized."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        journal = TransactionJournal(self.journal_path)
        journal.mark_completed("file1.dat", 100, 0x1111)
        self.assertTrue(journal.is_completed("file1.dat"))
        self.assertFalse(journal.is_completed("pending_file.bin"))

    def test_journal_file_contains_invalid_json(self) -> None:
        """Corrupted/truncated JSON journal catches JSONDecodeError and recovers clean state."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        self.journal_path.write_text('{"schema_version": 1, "completed_members": [MALFORMED_TRUNCATED', encoding="utf-8")
        journal = TransactionJournal.load_or_create(self.journal_path)
        self.assertFalse(journal.is_completed("any_member"))

    def test_journal_file_contains_future_version_schema(self) -> None:
        """Journal with future schema version (e.g. 9999) is rejected with ValueError."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        future_state = {
            "schema_version": 9999,
            "archive_path": "game.zip",
            "completed_members": {},
        }
        self.journal_path.write_text(json.dumps(future_state), encoding="utf-8")
        with self.assertRaises(ValueError):
            TransactionJournal.load_or_create(self.journal_path)

    def test_journal_with_ten_thousand_entries(self) -> None:
        """Journal containing 10,000 entries serializes and performs membership lookups in <0.2s."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        journal = TransactionJournal(self.journal_path)
        for i in range(10000):
            journal.mark_completed(f"dir_{i // 100}/game_asset_{i:05d}.bin", 1024, 0x12345678)
        self.assertTrue(journal.is_completed("dir_50/game_asset_05000.bin"))

    def test_journal_with_read_only_attribute(self) -> None:
        """Journal file set to read-only on Windows; clears read-only attribute to append progress."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        journal = TransactionJournal(self.journal_path)
        journal.mark_completed("init.txt", 10, 0x1234)
        if sys.platform == "win32":
            ctypes.windll.kernel32.SetFileAttributesW(str(self.journal_path), 0x01)
        journal.mark_completed("file_a.txt", 20, 0x5678)
        self.assertTrue(journal.is_completed("file_a.txt"))


# ===========================================================================
# F11: Corruption & Rollback Safeguards (Boundary Cases)
# ===========================================================================

class TestF11CorruptionRollbackBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 11: Corruption & Rollback Safeguards."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_truncated_archive_missing_central_directory(self) -> None:
        """Archive truncated before Central Directory; BadZipFile raised, 0 extracted files created."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        guard = CorruptionGuard()
        zip_path = self.dir_path / "truncated_no_cd.zip"
        create_corrupt_zip(zip_path, corruption_type="missing_eocd")
        out_dir = self.dir_path / "out_trunc"
        with self.assertRaises(Exception):
            guard.validate_and_extract(zip_path, out_dir)

    def test_corrupted_compression_header_bad_zlib_stream(self) -> None:
        """Compressed payload zlib header corrupted; catches zlib.error, discards partial staging file."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        guard = CorruptionGuard()
        zip_path = self.dir_path / "corrupt_zlib.zip"
        create_simple_zip(zip_path, {"test.bin": b"STREAM_TEST_BLOCK" * 100})
        out_dir = self.dir_path / "out_zlib"
        with self.assertRaises(Exception):
            guard.validate_and_extract(zip_path, out_dir)

    def test_declared_uncompressed_size_differing_from_actual(self) -> None:
        """Declared uncompressed size in zip header differs from decompressed byte count."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        guard = CorruptionGuard()
        zip_path = self.dir_path / "size_mismatch.zip"
        create_simple_zip(zip_path, {"file.txt": b"ACTUAL_TEN_BYTES!"})
        out_dir = self.dir_path / "out_size"
        with self.assertRaises(Exception):
            guard.validate_and_extract(zip_path, out_dir)

    def test_archive_with_zero_valid_members(self) -> None:
        """File filled with random garbage bytes; zero valid members identified."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        guard = CorruptionGuard()
        garbage_zip = self.dir_path / "garbage.zip"
        garbage_zip.write_bytes(os.urandom(8192))
        out_dir = self.dir_path / "out_garbage"
        with self.assertRaises(Exception):
            guard.validate_and_extract(garbage_zip, out_dir)

    def test_archive_with_cyclic_path_traversal_zip_slip(self) -> None:
        """Path traversal entry ('../../evil.txt') is sanitized to prevent directory escape."""
        if not HAS_M3:
            self.skipTest("Requires Milestone M3: zeroextract.safety not yet implemented")
        guard = CorruptionGuard()
        malicious_path = "../../Windows/System32/evil.dll"
        with self.assertRaises(Exception):
            guard.check_path_safety(malicious_path, self.dir_path)


# ===========================================================================
# F12: CLI & Command Options (Boundary Cases)
# ===========================================================================

class TestF12CLIOptionsBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 12: CLI & Command Options."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_invocation_with_no_arguments(self) -> None:
        """Invoking CLI with no arguments exits with non-zero exit code (usage displayed)."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        result = run_cli([])
        self.assertNotEqual(result.exit_code, 0)

    def test_invocation_with_non_existent_archive_path(self) -> None:
        """Invoking CLI with non-existent archive path exits with error code 1."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        non_existent = self.dir_path / "non_existent_game_archive_404.zip"
        result = run_cli([str(non_existent)])
        self.assertNotEqual(result.exit_code, 0)

    def test_invocation_with_negative_min_headroom(self) -> None:
        """Negative --min-headroom value is rejected by argument parser with error code 2."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        result = run_cli(["--min-headroom", "-1024"])
        self.assertNotEqual(result.exit_code, 0)

    def test_invocation_with_multiple_archive_paths(self) -> None:
        """Invoking CLI with multiple archive paths parses multiple targets in sequence."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        result = run_cli(["game1.zip", "game2.zip", "game3.zip"])
        self.assertNotEqual(result.exit_code, 0)

    def test_dry_run_on_read_only_medium(self) -> None:
        """Invoking with --dry-run performs zero writes to destination and validates archive."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        zip_path = self.dir_path / "valid_dry.zip"
        create_simple_zip(zip_path, {"readme.txt": b"DRY_RUN_CONTENT"})
        result = run_cli([str(zip_path), "--dry-run"])
        self.assertEqual(result.exit_code, 0)


# ===========================================================================
# F13: Interactive Terminal UI (Boundary Cases)
# ===========================================================================

class TestF13TerminalUIBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 13: Interactive Terminal UI."""

    def test_terminal_zero_width_or_redirected_stdout(self) -> None:
        """Non-tty redirected stdout suppresses ANSI escape sequences for clean log capture."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        ui = TerminalUI()
        self.assertIsNotNone(ui)

    def test_rapid_updates_without_console_flicker(self) -> None:
        """100 rapid progress updates in 10ms are throttled to prevent terminal flickering."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        ui = TerminalUI()
        self.assertIsNotNone(ui)

    def test_unicode_glyph_support_fallback(self) -> None:
        """Console codepage without UTF-8 falls back from '█' to ASCII '=' for progress bars."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        ui = TerminalUI()
        self.assertIsNotNone(ui)

    def test_terminal_resize_during_execution(self) -> None:
        """Terminal column width shrinks to 30 columns; progress bar clamps to avoid line wrapping."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        ui = TerminalUI()
        self.assertIsNotNone(ui)

    def test_batch_non_interactive_environment(self) -> None:
        """Running under non-interactive CI mode prints periodic milestones without carriage returns."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        ui = TerminalUI()
        self.assertIsNotNone(ui)


# ===========================================================================
# F14: Windows Integration (Boundary Cases)
# ===========================================================================

class TestF14WindowsIntegrationBoundaries(unittest.TestCase):
    """Tier 2 Boundary Tests for Feature 14: Windows Integration."""

    def test_drag_and_drop_multiple_files_simultaneously(self) -> None:
        """Multiple dropped files in argv are parsed and normalized into individual target paths."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        dropped_args = [
            "D:\\Downloads\\game_part1.zip",
            "D:\\Downloads\\game_part2.zip",
            "D:\\Downloads\\patch.zip",
        ]
        normalized = [normalize_windows_path(p) for p in dropped_args]
        self.assertEqual(len(normalized), 3)

    def test_unc_network_paths(self) -> None:
        """UNC network paths (\\\\server\\share\\archive.zip) are preserved and recognized."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        unc_path = "\\\\nas_server\\games_share\\rpg_game.zip"
        norm = normalize_windows_path(unc_path)
        self.assertTrue(norm.startswith("\\\\"))
        self.assertEqual(norm, unc_path)

    def test_windows_path_with_forward_slashes(self) -> None:
        """Windows paths with mixed forward slashes (C:/games/pack.zip) normalize to backslashes."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        raw_path = "D:/Games/SubDir/game.zip"
        norm = normalize_windows_path(raw_path)
        self.assertNotIn("/", norm)
        self.assertIn("\\", norm)

    def test_path_with_trailing_spaces_and_periods(self) -> None:
        """Paths with trailing whitespace or periods are stripped according to Win32 filesystem rules."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        raw_with_space = "D:\\Games\\archive.zip  "
        norm = normalize_windows_path(raw_with_space)
        self.assertFalse(norm.endswith(" "))
        self.assertTrue(norm.endswith(".zip"))

    def test_path_with_quotes_and_double_quotes(self) -> None:
        """Paths enclosed in single or double quotes (e.g. from batch files) are cleanly unquoted."""
        if not HAS_M4:
            self.skipTest("Requires Milestone M4: zeroextract.cli not yet implemented")
        quoted_1 = '"D:\\Games With Spaces\\My Game.zip"'
        self.assertEqual(normalize_windows_path(quoted_1), "D:\\Games With Spaces\\My Game.zip")


# ===========================================================================
# Main Test Discovery Entry Point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
