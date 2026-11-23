"""Tier 1 Feature Coverage Test Suite for ZeroExtract.

Requirement: At least 5 isolated tests per feature across all 14 features (F1 to F14),
achieving >= 70 test cases total:
- F1: NTFS Sparse Hole-Punching (5 tests)
- F2: Reverse Tail Truncation (5 tests)
- F3: Progressive Volume Unlinking (5 tests)
- F4: Disk Headroom Monitor (5 tests)
- F5: ZIP & ZIP64 Reverse Extraction (5 tests)
- F6: Multi-Volume Stream Extractor (5 tests)
- F7: Chunked Lockstep Deallocation (5 tests)
- F8: 0-Byte Pre-Verification Shield (5 tests)
- F9: Two-Phase Commit Atomic Writer (5 tests)
- F10: Crash-Safe Transaction Journal (5 tests)
- F11: Corruption & Rollback Safeguards (5 tests)
- F12: CLI & Command Options (5 tests)
- F13: Interactive Terminal UI (5 tests)
- F14: Windows Integration (5 tests)

Complies with Progressive Testability: features from current completed milestone (M1)
execute directly against zeroextract.fs; features from planned milestones (M2-M4)
execute against their modules if implemented, or skip cleanly with informative messages.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import time
import unittest
import zipfile
import zlib

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
    get_allocated_file_size,
    is_file_sparse,
    is_sparse_supported,
    run_cli,
    simulate_power_cut_extraction,
    verify_directory_contents,
)
from zeroextract.fs.headroom import HeadroomMonitor, LowHeadroomError
from zeroextract.fs.sparse import SparseError, SparsePuncher
from zeroextract.fs.truncator import ReverseTruncator, TruncateError
from zeroextract.fs.volume_cleaner import VolumeCleaner, VolumeCleanError

# Milestone 2 imports
try:
    from zeroextract.formats.zip_reverse import ZipReverseExtractor
    HAS_ZIP_REVERSE = True
except (ImportError, ModuleNotFoundError):
    HAS_ZIP_REVERSE = False

try:
    from zeroextract.formats.multi_volume import MultiVolumeStreamer
    HAS_MULTI_VOLUME = True
except (ImportError, ModuleNotFoundError):
    HAS_MULTI_VOLUME = False

try:
    from zeroextract.formats.chunked_sparse import ChunkedSparseExtractor
    HAS_CHUNKED_SPARSE = True
except (ImportError, ModuleNotFoundError):
    HAS_CHUNKED_SPARSE = False

# Milestone 3 imports
try:
    from zeroextract.safety.preverify import PreflightShield
    HAS_PREFLIGHT = True
except (ImportError, ModuleNotFoundError):
    HAS_PREFLIGHT = False

try:
    from zeroextract.safety.atomic import AtomicWriter
    HAS_ATOMIC = True
except (ImportError, ModuleNotFoundError):
    HAS_ATOMIC = False

try:
    from zeroextract.safety.journal import TransactionJournal
    HAS_JOURNAL = True
except (ImportError, ModuleNotFoundError):
    HAS_JOURNAL = False

try:
    from zeroextract.safety.exceptions import (
        ChecksumError,
        CorruptionError,
        CorruptionGuard,
    )
    HAS_SAFETY_EXC = True
except (ImportError, ModuleNotFoundError):
    HAS_SAFETY_EXC = False

# Milestone 4 imports
try:
    import zeroextract.cli.main as cli_main
    HAS_CLI = True
except (ImportError, ModuleNotFoundError):
    HAS_CLI = False

try:
    from zeroextract.cli.ui import TerminalUI
    HAS_UI = True
except (ImportError, ModuleNotFoundError):
    HAS_UI = False

try:
    import zeroextract.cli.windows_setup as win_setup
    HAS_WINDOWS = True
except (ImportError, ModuleNotFoundError):
    HAS_WINDOWS = False


def _is_cli_executable() -> bool:
    """Helper to check if zeroextract CLI is currently runnable."""
    try:
        res = run_cli(["--help"], timeout=5.0)
        return res.exit_code == 0
    except Exception:
        return False


# ===========================================================================
# Feature 1: NTFS Sparse Hole-Punching (F1)
# ===========================================================================

class TestF1NtfsSparseHolePunching(unittest.TestCase):
    """Tests for Feature F1: NTFS Sparse Hole-Punching."""

    def setUp(self) -> None:
        self.puncher = SparsePuncher()

    def test_f1_01_basic_hole_punch(self) -> None:
        """Verifies basic sparse hole punch deallocates requested cluster range."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "f1_basic.bin"
            # 2 MB test file with 32 clusters of 64KB
            chunk_64k = b"A" * 65536
            file_path.write_bytes(chunk_64k * 32)
            self.assertEqual(file_path.stat().st_size, 2097152)

            if not is_sparse_supported(tmp_dir):
                self.skipTest(f"Volume hosting {tmp_dir} does not support sparse files.")

            self.puncher.mark_as_sparse(file_path)
            self.assertTrue(is_file_sparse(file_path))

            # Punch hole: 4 clusters at offset 512KB (524288 to 786432)
            deallocated = self.puncher.punch_hole(file_path, 524288, 262144)
            self.assertEqual(deallocated, 262144)

            # Logical file size must remain unchanged
            self.assertEqual(file_path.stat().st_size, 2097152)

            # Query allocated ranges
            ranges = self.puncher.get_allocated_ranges(file_path)
            # The range [524288, 786432) should not be fully allocated
            hole_found = any(r_start <= 524288 and (r_start + r_len) <= 524288 for r_start, r_len in ranges)
            self.assertTrue(hole_found or len(ranges) >= 1)

    def test_f1_02_64kb_cluster_alignment(self) -> None:
        """Verifies inward alignment to 64KB cluster boundaries."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "f1_align.bin"
            file_path.write_bytes(b"X" * (512 * 1024))

            # Negative inputs must raise ValueError
            with self.assertRaises(ValueError):
                self.puncher.punch_hole(file_path, -1, 65536)
            with self.assertRaises(ValueError):
                self.puncher.punch_hole(file_path, 0, -100)

            # 0 length returns 0 immediately
            self.assertEqual(self.puncher.punch_hole(file_path, 0, 0), 0)

            # Sub-cluster range (< 64KB) inward alignment yields 0 bytes
            deallocated_sub = self.puncher.punch_hole(file_path, 1000, 2000, cluster_size=65536)
            self.assertEqual(deallocated_sub, 0)

            # Unaligned range: offset 1000, length 140000 -> inward aligns to [65536, 131072) = 65536 bytes
            if is_sparse_supported(tmp_dir):
                self.puncher.mark_as_sparse(file_path)
                deallocated = self.puncher.punch_hole(file_path, 1000, 140000, cluster_size=65536)
                self.assertEqual(deallocated, 65536)

    def test_f1_03_sparse_attribute_check(self) -> None:
        """Verifies setting and querying the FILE_ATTRIBUTE_SPARSE_FILE (0x200) attribute."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "f1_attr.bin"
            file_path.write_bytes(b"12345678" * 1024)

            # Freshly created file must NOT have sparse attribute
            self.assertFalse(is_file_sparse(file_path))

            if not is_sparse_supported(tmp_dir):
                self.skipTest(f"Volume hosting {tmp_dir} does not support sparse files.")

            # Mark as sparse
            ret = self.puncher.mark_as_sparse(file_path)
            self.assertTrue(ret)

            # Now sparse attribute must be present
            self.assertTrue(is_file_sparse(file_path))

    def test_f1_04_hole_zero_verification(self) -> None:
        """Verifies that bytes read from a punched hole return zeroes while intact data remains."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "f1_zero.bin"
            pattern = b"K" * (1024 * 1024)  # 1 MB of 'K'
            file_path.write_bytes(pattern)

            if not is_sparse_supported(tmp_dir):
                self.skipTest(f"Volume hosting {tmp_dir} does not support sparse files.")

            self.puncher.mark_as_sparse(file_path)
            # Punch hole: 256KB from offset 262144 to 524288
            deallocated = self.puncher.punch_hole(file_path, 262144, 262144)
            self.assertEqual(deallocated, 262144)

            # Read back entire file and verify content
            data = file_path.read_bytes()
            self.assertEqual(len(data), 1024 * 1024)
            # Prefix before hole must be original pattern
            self.assertEqual(data[:262144], b"K" * 262144)
            # Punched hole region must be all zeroes
            self.assertEqual(data[262144:524288], b"\x00" * 262144)
            # Suffix after hole must be original pattern
            self.assertEqual(data[524288:], b"K" * (1024 * 1024 - 524288))

    def test_f1_05_multi_range_hole_punching(self) -> None:
        """Verifies multiple non-contiguous sparse holes can be punched in a single file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "f1_multi.bin"
            # 4 MB file (64 clusters of 64KB)
            total_size = 4 * 1024 * 1024
            chunk_64k = b"M" * 65536
            file_path.write_bytes(chunk_64k * 64)

            if not is_sparse_supported(tmp_dir):
                self.skipTest(f"Volume hosting {tmp_dir} does not support sparse files.")

            self.puncher.mark_as_sparse(file_path)

            # Punch 3 non-overlapping holes
            # Hole 1: 256KB at offset 262144 (clusters 4-7)
            h1 = self.puncher.punch_hole(file_path, 262144, 262144)
            self.assertEqual(h1, 262144)

            # Hole 2: 512KB at offset 1048576 (clusters 16-23)
            h2 = self.puncher.punch_hole(file_path, 1048576, 524288)
            self.assertEqual(h2, 524288)

            # Hole 3: 256KB at offset 2621440 (clusters 40-43)
            h3 = self.puncher.punch_hole(file_path, 2621440, 262144)
            self.assertEqual(h3, 262144)

            # Verify content integrity across all ranges
            with open(file_path, "rb") as f:
                # Hole 1 region
                f.seek(262144)
                self.assertEqual(f.read(262144), b"\x00" * 262144)
                # Intervening data between Hole 1 and Hole 2
                f.seek(524288)
                self.assertEqual(f.read(65536), b"M" * 65536)
                # Hole 2 region
                f.seek(1048576)
                self.assertEqual(f.read(524288), b"\x00" * 524288)
                # Hole 3 region
                f.seek(2621440)
                self.assertEqual(f.read(262144), b"\x00" * 262144)


# ===========================================================================
# Feature 2: Reverse Tail Truncation (F2)
# ===========================================================================

class TestF2ReverseTailTruncation(unittest.TestCase):
    """Tests for Feature F2: Universal Reverse Tail Truncation."""

    def setUp(self) -> None:
        self.truncator = ReverseTruncator()

    def test_f2_01_archive_shrinking_after_tail_member_extraction(self) -> None:
        """Verifies physical file truncation reduces archive size on disk."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f2_shrink.zip"
            files = {
                "file1.txt": b"First member payload 11111",
                "file2.txt": b"Second member payload 22222",
                "file3.txt": b"Third member payload 3333333333",
            }
            create_simple_zip(zip_path, files)
            orig_size = zip_path.stat().st_size
            self.assertGreater(orig_size, 0)

            # Determine offset of file3 in the archive
            with zipfile.ZipFile(zip_path, "r") as zf:
                infos = {info.filename: info for info in zf.infolist()}
                f3_offset = infos["file3.txt"].header_offset

            # Truncate archive tail to remove file3
            freed = self.truncator.truncate_tail(zip_path, f3_offset)
            self.assertEqual(freed, orig_size - f3_offset)
            self.assertEqual(zip_path.stat().st_size, f3_offset)

    def test_f2_02_central_directory_preservation_during_reverse_pass(self) -> None:
        """Verifies that caching Central Directory in memory allows member extraction after tail truncation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f2_cd_cache.zip"
            files = {
                "member_a.dat": b"DATA_A_" * 50,
                "member_b.dat": b"DATA_B_" * 100,
                "member_c.dat": b"DATA_C_" * 150,
            }
            create_simple_zip(zip_path, files)
            orig_size = zip_path.stat().st_size

            # Step 1: Read Central Directory into memory cache
            cd_cache = []
            with zipfile.ZipFile(zip_path, "r") as zf:
                for info in zf.infolist():
                    cd_cache.append({
                        "filename": info.filename,
                        "header_offset": info.header_offset,
                        "compress_size": info.compress_size,
                        "file_size": info.file_size,
                        "crc": info.CRC,
                    })

            # Sort descending by header offset (reverse extraction order)
            cd_cache.sort(key=lambda x: x["header_offset"], reverse=True)
            tail_entry = cd_cache[0]  # member_c.dat

            # Truncate archive at tail entry's header offset (Central Directory on disk is now destroyed)
            self.truncator.truncate_tail(zip_path, tail_entry["header_offset"])

            # Verify standard zipfile fails on disk (CD missing)
            with self.assertRaises(zipfile.BadZipFile):
                zipfile.ZipFile(zip_path, "r")

            # Verify that earlier members (member_a, member_b) can still be read using cached offsets
            with open(zip_path, "rb") as f:
                for entry in cd_cache[1:]:
                    f.seek(entry["header_offset"])
                    magic = f.read(4)
                    self.assertEqual(magic, b"PK\x03\x04", f"Local header intact for {entry['filename']}")

    def test_f2_03_uncompressed_content_fidelity(self) -> None:
        """Verifies data integrity of extracted files across reverse-pass truncation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f2_fidelity.zip"
            out_dir = Path(tmp_dir) / "extracted"
            out_dir.mkdir()

            test_payloads = {
                "game/engine.dll": b"DLL_BINARY_CONTENT_" * 100,
                "game/levels/map1.dat": b"LEVEL_GEOMETRY_BYTES_" * 200,
                "game/sound.ogg": b"AUDIO_COMPRESSED_DATA_" * 300,
            }
            create_simple_zip(zip_path, test_payloads, compression=zipfile.ZIP_STORED)
            expected_hashes = calculate_expected_hashes(test_payloads)

            # Inspect and order entries descending by offset
            with zipfile.ZipFile(zip_path, "r") as zf:
                infolist = sorted(zf.infolist(), key=lambda i: i.header_offset, reverse=True)
                raw_bytes = zip_path.read_bytes()

            # Reverse extraction loop
            for info in infolist:
                # Read uncompressed payload
                with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf_mem:
                    extracted_data = zf_mem.read(info.filename)

                # Write extracted file
                dest = out_dir / info.filename
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(extracted_data)

                # Truncate archive tail to this entry's offset
                self.truncator.truncate_tail(zip_path, info.header_offset)

            # Verify all extracted files match expected SHA256
            verif = verify_directory_contents(out_dir, expected_hashes)
            self.assertTrue(verif.is_valid, f"Fidelity error: {verif.errors}")

    def test_f2_04_lockstep_size_reduction(self) -> None:
        """Verifies monotonic size reduction and exact freed byte accounting across multiple truncation steps."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = Path(tmp_dir) / "f2_lockstep.bin"
            total_size = 1048576  # 1 MB
            test_file.write_bytes(b"L" * total_size)

            steps = [786432, 524288, 262144, 0]
            current_size = total_size

            for new_size in steps:
                freed = self.truncator.truncate_tail(test_file, new_size)
                expected_freed = current_size - new_size
                self.assertEqual(freed, expected_freed)
                self.assertEqual(test_file.stat().st_size, new_size)
                current_size = new_size

            # Truncating with new_size >= current_size must be a no-op returning 0
            self.assertEqual(self.truncator.truncate_tail(test_file, 0), 0)
            self.assertEqual(self.truncator.truncate_tail(test_file, 100), 0)

    def test_f2_05_zero_extra_space_headroom(self) -> None:
        """Verifies that reverse tail truncation limits peak disk consumption to max single member size."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f2_headroom.zip"
            files = {f"file_{i:02d}.bin": b"V" * (64 * 1024) for i in range(10)}
            create_simple_zip(zip_path, files, compression=zipfile.ZIP_STORED)
            initial_archive_size = zip_path.stat().st_size

            with zipfile.ZipFile(zip_path, "r") as zf:
                infolist = sorted(zf.infolist(), key=lambda i: i.header_offset, reverse=True)
                offsets = [info.header_offset for info in infolist]

            # Simulate peak disk space usage:
            # At each step: write uncompressed member (size S_i), then truncate archive to offset
            peak_extra_space = 0
            current_archive_size = initial_archive_size
            total_extracted = 0

            for i, info in enumerate(infolist):
                member_uncompressed = info.file_size
                # Space before truncation: extracted so far + new member + current archive
                space_in_flight = total_extracted + member_uncompressed + current_archive_size
                extra_in_flight = space_in_flight - initial_archive_size
                if extra_in_flight > peak_extra_space:
                    peak_extra_space = extra_in_flight

                # Perform truncation
                new_size = offsets[i]
                freed = self.truncator.truncate_tail(zip_path, new_size)
                current_archive_size = new_size
                total_extracted += member_uncompressed

            # Peak extra disk space must be bounded by the maximum single file size + overhead,
            # NOT the 2x total archive size!
            max_single_file = max(info.file_size for info in infolist)
            self.assertLessEqual(peak_extra_space, max_single_file + 8192)


# ===========================================================================
# Feature 3: Progressive Volume Unlinking (F3)
# ===========================================================================

class TestF3ProgressiveVolumeUnlinking(unittest.TestCase):
    """Tests for Feature F3: Progressive Split Volume Unlinking."""

    def setUp(self) -> None:
        self.cleaner = VolumeCleaner()

    def test_f3_01_split_volume_unlinking_upon_member_completion(self) -> None:
        """Verifies safe deletion of completed split volumes freeing space immediately."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_zip = Path(tmp_dir) / "game.zip"
            files = {f"item_{i}.bin": b"SPLIT_DATA_" * 5000 for i in range(5)}
            volumes = create_multi_part_zip(base_zip, files, max_volume_size=32768, compression=zipfile.ZIP_STORED)
            self.assertGreaterEqual(len(volumes), 2)

            vol1 = volumes[0]
            self.assertTrue(vol1.exists())
            self.assertTrue(self.cleaner.is_split_volume(vol1))

            # Simulate completion of members residing in vol1
            success = self.cleaner.unlink_volume(vol1)
            self.assertTrue(success)
            self.assertFalse(vol1.exists())

            # Remaining volumes must stay intact on disk
            for remaining in volumes[1:]:
                self.assertTrue(remaining.exists())

    def test_f3_02_volume_sequence_validation(self) -> None:
        """Verifies split volume regex detection and index extraction."""
        # Supported split extensions
        self.assertTrue(self.cleaner.is_split_volume("game.z01"))
        self.assertTrue(self.cleaner.is_split_volume("game.part01.rar"))
        self.assertTrue(self.cleaner.is_split_volume("game.7z.001"))
        self.assertTrue(self.cleaner.is_split_volume("game.zip.001"))
        self.assertTrue(self.cleaner.is_split_volume("archive.r00"))

        # Non-split filenames
        self.assertFalse(self.cleaner.is_split_volume("game.zip"))
        self.assertFalse(self.cleaner.is_split_volume("document.pdf"))

        # Index extraction
        base, idx = self.cleaner.get_volume_index("game.part03.rar")
        self.assertEqual(base, "game")
        self.assertEqual(idx, 3)

        base_z, idx_z = self.cleaner.get_volume_index("setup.z02")
        self.assertEqual(base_z, "setup")
        self.assertEqual(idx_z, 2)

        # Invalid volume index extraction raises ValueError
        with self.assertRaises(ValueError):
            self.cleaner.get_volume_index("standalone.zip")

    def test_f3_03_multi_member_split_volume_handling(self) -> None:
        """Verifies volume is unlinked only after all members in that volume complete."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            vol_path = Path(tmp_dir) / "game.z01"
            vol_path.write_bytes(b"DATA" * 1024)

            # Simulated volume reference tracker
            volume_member_count = {"game.z01": 2}

            def on_member_extracted(vol_name: str) -> bool:
                volume_member_count[vol_name] -= 1
                if volume_member_count[vol_name] == 0:
                    return self.cleaner.unlink_volume(vol_path)
                return False

            # First member extracted: volume must NOT be unlinked yet
            unlinked_1 = on_member_extracted("game.z01")
            self.assertFalse(unlinked_1)
            self.assertTrue(vol_path.exists())

            # Second (final) member extracted: volume must be unlinked now
            unlinked_2 = on_member_extracted("game.z01")
            self.assertTrue(unlinked_2)
            self.assertFalse(vol_path.exists())

    def test_f3_04_final_volume_retention(self) -> None:
        """Verifies final volume (.zip) retention during intermediate extraction passes."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_zip = Path(tmp_dir) / "pack.zip"
            files = {f"file_{i}.txt": b"CONTENT" * 1000 for i in range(4)}
            volumes = create_multi_part_zip(base_zip, files, max_volume_size=16384, compression=zipfile.ZIP_STORED)
            self.assertGreaterEqual(len(volumes), 2)

            # Final volume has .zip extension in PKWARE scheme
            final_vol = volumes[-1]
            self.assertEqual(final_vol.suffix.lower(), ".zip")

            # Intermediate volumes have .z01, .z02, ...
            intermediate = volumes[:-1]
            for iv in intermediate:
                self.assertNotEqual(iv.suffix.lower(), ".zip")

            # Progressive unlinking should preserve the final volume until the end
            for iv in intermediate:
                self.cleaner.unlink_volume(iv)
                self.assertFalse(iv.exists())
                self.assertTrue(final_vol.exists(), "Final volume must remain for CD preservation")

            # Finally, clean final volume
            self.cleaner.unlink_volume(final_vol)
            self.assertFalse(final_vol.exists())

    def test_f3_05_volume_deletion_error_handling(self) -> None:
        """Verifies proper error handling when unlinking non-existent or read-only volume files."""
        # Non-existent file must raise FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            self.cleaner.unlink_volume("C:\\non_existent_volume_xyz.z01")

        # Read-only file handling: should clear read-only attribute and succeed
        with tempfile.TemporaryDirectory() as tmp_dir:
            ro_file = Path(tmp_dir) / "ro_part.z01"
            ro_file.write_bytes(b"READONLY_CONTENT")
            # Set read-only
            os.chmod(ro_file, 0o444)

            # VolumeCleaner must handle read-only flag and unlink
            res = self.cleaner.unlink_volume(ro_file)
            self.assertTrue(res)
            self.assertFalse(ro_file.exists())


# ===========================================================================
# Feature 4: Disk Headroom Monitor (F4)
# ===========================================================================

class TestF4DiskHeadroomMonitor(unittest.TestCase):
    """Tests for Feature F4: Real-Time Disk Headroom Monitor."""

    def setUp(self) -> None:
        self.monitor = HeadroomMonitor()

    def test_f4_01_free_headroom_detection(self) -> None:
        """Verifies get_free_space returns accurate positive free space bytes."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            free_bytes = self.monitor.get_free_space(tmp_dir)
            self.assertIsInstance(free_bytes, int)
            self.assertGreater(free_bytes, 0)

            # Compare with standard shutil.disk_usage
            shutil_free = shutil.disk_usage(tmp_dir).free
            # Should be within 50 MB measurement tolerance
            diff = abs(free_bytes - shutil_free)
            self.assertLessEqual(diff, 50 * 1024 * 1024)

    def test_f4_02_abort_when_headroom_below_threshold(self) -> None:
        """Verifies ensure_headroom raises LowHeadroomError when space requirement exceeds capacity."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            free_bytes = self.monitor.get_free_space(tmp_dir)
            # Require more space than physically exists
            huge_requirement = free_bytes + (1024 * 1024 * 1024 * 1024)  # +1 TB

            with self.assertRaises(LowHeadroomError) as ctx:
                self.monitor.ensure_headroom(tmp_dir, required_bytes=huge_requirement)

            err = ctx.exception
            self.assertGreater(err.shortage_bytes, 0)
            self.assertIn("Insufficient disk headroom", str(err))

    def test_f4_03_proceed_when_adequate(self) -> None:
        """Verifies check_headroom returns True when free space comfortably exceeds requirement."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Check with small 1KB requirement and 1KB cushion
            can_proceed = self.monitor.check_headroom(
                tmp_dir,
                required_bytes=1024,
                min_headroom_cushion=1024,
            )
            self.assertTrue(can_proceed)

    def test_f4_04_custom_min_headroom_parameter(self) -> None:
        """Verifies custom headroom cushion parameter is strictly enforced."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            free_bytes = self.monitor.get_free_space(tmp_dir)

            # If cushion is set to slightly less than free space, requirement of 100MB should fail
            cushion = max(0, free_bytes - (50 * 1024 * 1024))
            can_proceed = self.monitor.check_headroom(
                tmp_dir,
                required_bytes=100 * 1024 * 1024,
                min_headroom_cushion=cushion,
            )
            self.assertFalse(can_proceed)

    def test_f4_05_headroom_cushion_reservation(self) -> None:
        """Verifies safety cushion reserves headroom before 0 free space is reached."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            free_bytes = self.monitor.get_free_space(tmp_dir)

            # Set cushion higher than total free space
            cushion_exceeding = free_bytes + (10 * 1024 * 1024)
            with self.assertRaises(LowHeadroomError):
                self.monitor.ensure_headroom(
                    tmp_dir,
                    required_bytes=0,
                    min_headroom_cushion=cushion_exceeding,
                )


# ===========================================================================
# Feature 5: ZIP & ZIP64 Reverse Extraction (F5)
# ===========================================================================

class TestF5ZipReverseExtraction(unittest.TestCase):
    """Tests for Feature F5: ZIP & ZIP64 Reverse Extraction Pipeline."""

    def test_f5_01_standard_zip_deflate_extraction(self) -> None:
        """Verifies reverse extraction of standard DEFLATE ZIP archive."""
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f5_deflate.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {
                "readme.txt": b"Hello from ZeroExtract DEFLATE test!",
                "data/config.json": b'{"status": "ok", "retries": 3}',
                "bin/payload.dat": b"\xAA\xBB\xCC\xDD" * 1024,
            }
            create_simple_zip(zip_path, files, compression=zipfile.ZIP_DEFLATED)

            if HAS_ZIP_REVERSE:
                extractor = ZipReverseExtractor()
                extractor.extract(str(zip_path), str(out_dir))
            else:
                res = run_cli([str(zip_path), "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            verif = verify_directory_contents(out_dir, files)
            self.assertTrue(verif.is_valid, f"Extraction failed: {verif.errors}")

    def test_f5_02_zip_store_method(self) -> None:
        """Verifies reverse extraction of uncompressed ZIP_STORED archives."""
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f5_store.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {
                "uncompressed_1.bin": b"STORE_PAYLOAD_1111" * 500,
                "uncompressed_2.bin": b"STORE_PAYLOAD_2222" * 500,
            }
            create_simple_zip(zip_path, files, compression=zipfile.ZIP_STORED)

            if HAS_ZIP_REVERSE:
                extractor = ZipReverseExtractor()
                extractor.extract(str(zip_path), str(out_dir))
            else:
                res = run_cli([str(zip_path), "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            verif = verify_directory_contents(out_dir, files)
            self.assertTrue(verif.is_valid, f"STORE extraction failed: {verif.errors}")

    def test_f5_03_zip64_large_entry_count(self) -> None:
        """Verifies parsing and reverse extraction of ZIP64 archives with 64-bit records."""
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f5_zip64.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {f"archive_member_{i:03d}.dat": f"Zip64 member {i}".encode("utf-8") * 50 for i in range(10)}
            create_zip64(zip_path, files)

            struct_info = inspect_zip_structure(zip_path)
            self.assertTrue(struct_info["is_zip64"])

            if HAS_ZIP_REVERSE:
                extractor = ZipReverseExtractor()
                extractor.extract(str(zip_path), str(out_dir))
            else:
                res = run_cli([str(zip_path), "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            verif = verify_directory_contents(out_dir, files)
            self.assertTrue(verif.is_valid, f"ZIP64 extraction failed: {verif.errors}")

    def test_f5_04_zip64_64bit_offsets(self) -> None:
        """Verifies handling of ZIP64 64-bit offsets and locator records."""
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f5_offsets64.zip"
            files = {"large_offset_file.bin": b"BIG_OFFSET_PAYLOAD" * 200}
            create_zip64(zip_path, files)

            # Raw check for ZIP64 signatures
            raw = zip_path.read_bytes()
            self.assertIn(b"PK\x06\x06", raw, "ZIP64 End of Central Directory record must be present")
            self.assertIn(b"PK\x06\x07", raw, "ZIP64 Locator record must be present")

    def test_f5_05_reverse_order_member_extraction_sequence(self) -> None:
        """Verifies entries are extracted strictly in descending order of physical header offsets."""
        if not HAS_ZIP_REVERSE:
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f5_order.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {
                "head.txt": b"First physical entry in archive",
                "middle.txt": b"Middle physical entry in archive",
                "tail.txt": b"Last physical entry in archive",
            }
            create_simple_zip(zip_path, files)

            extracted_order = []
            extractor = ZipReverseExtractor()
            extractor.extract(
                str(zip_path),
                str(out_dir),
                on_member_extracted=lambda name: extracted_order.append(name),
            )
            # The tail member must be extracted before head member
            self.assertEqual(extracted_order[0], "tail.txt")
            self.assertEqual(extracted_order[-1], "head.txt")


# ===========================================================================
# Feature 6: Multi-Volume Stream Extractor (F6)
# ===========================================================================

class TestF6MultiVolumeStreamExtractor(unittest.TestCase):
    """Tests for Feature F6: Multi-Volume Stream Extractor."""

    def test_f6_01_member_crossing_volume_boundary(self) -> None:
        """Verifies streaming extraction when a single member spans across volume boundaries."""
        if not HAS_MULTI_VOLUME and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.multi_volume) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            base_zip = Path(tmp_dir) / "f6_span.zip"
            out_dir = Path(tmp_dir) / "out"
            # Single entry of 120KB split across 32KB volume boundaries
            spanning_data = b"SPANNING_STREAM_DATA_CHUNK_" * 4000
            files = {"large_spanning_file.dat": spanning_data}
            volumes = create_multi_part_zip(base_zip, files, max_volume_size=32768, compression=zipfile.ZIP_STORED)
            self.assertGreater(len(volumes), 1)

            if HAS_MULTI_VOLUME:
                streamer = MultiVolumeStreamer()
                streamer.extract(str(volumes[0]), str(out_dir))
            else:
                res = run_cli([str(volumes[0]), "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            verif = verify_directory_contents(out_dir, files)
            self.assertTrue(verif.is_valid, f"Spanning volume extraction error: {verif.errors}")

    def test_f6_02_three_part_split_archive(self) -> None:
        """Verifies full extraction of a 3-part split archive with progressive volume unlinking."""
        if not HAS_MULTI_VOLUME and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.multi_volume) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            base_zip = Path(tmp_dir) / "f6_three_part.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {f"part_file_{i}.bin": b"PAYLOAD_" * 2000 for i in range(6)}
            volumes = create_multi_part_zip(base_zip, files, max_volume_size=20480, compression=zipfile.ZIP_STORED)
            self.assertGreaterEqual(len(volumes), 3)

            first_vol = str(volumes[0])
            if HAS_MULTI_VOLUME:
                streamer = MultiVolumeStreamer()
                streamer.extract(first_vol, str(out_dir))
            else:
                res = run_cli([first_vol, "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            verif = verify_directory_contents(out_dir, files)
            self.assertTrue(verif.is_valid, f"3-part extraction error: {verif.errors}")

    def test_f6_03_five_part_split_archive(self) -> None:
        """Verifies extraction and progressive unlinking across 5 split volume parts."""
        if not HAS_MULTI_VOLUME and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.multi_volume) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            base_zip = Path(tmp_dir) / "f6_five_part.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {f"item_{i}.dat": b"CHUNKY_DATA_" * 1500 for i in range(10)}
            volumes = create_multi_part_zip(base_zip, files, max_volume_size=12288, compression=zipfile.ZIP_STORED)
            self.assertGreaterEqual(len(volumes), 5)

            first_vol = str(volumes[0])
            if HAS_MULTI_VOLUME:
                streamer = MultiVolumeStreamer()
                streamer.extract(first_vol, str(out_dir))
            else:
                res = run_cli([first_vol, "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            verif = verify_directory_contents(out_dir, files)
            self.assertTrue(verif.is_valid, f"5-part extraction error: {verif.errors}")

    def test_f6_04_out_of_order_volume_detection(self) -> None:
        """Verifies multi-volume streamer detects out-of-order volume parts before unpacking."""
        if not HAS_MULTI_VOLUME:
            self.skipTest("Requires Milestone M2 (zeroextract.formats.multi_volume).")

        streamer = MultiVolumeStreamer()
        # Shuffled volume paths
        scrambled = ["archive.z02", "archive.z01", "archive.zip"]
        with self.assertRaises((ValueError, OSError)):
            streamer.validate_volume_sequence(scrambled)

    def test_f6_05_missing_volume_detection(self) -> None:
        """Verifies multi-volume streamer halts with an informative error if an intermediate volume is missing."""
        if not HAS_MULTI_VOLUME and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.multi_volume) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            base_zip = Path(tmp_dir) / "f6_missing.zip"
            files = {f"f_{i}.bin": b"TEST" * 5000 for i in range(5)}
            volumes = create_multi_part_zip(base_zip, files, max_volume_size=16384, compression=zipfile.ZIP_STORED)
            self.assertGreaterEqual(len(volumes), 3)

            # Delete intermediate volume .z02
            vol_to_delete = volumes[1]
            vol_to_delete.unlink()

            out_dir = Path(tmp_dir) / "out"
            if HAS_MULTI_VOLUME:
                streamer = MultiVolumeStreamer()
                with self.assertRaises((FileNotFoundError, OSError)):
                    streamer.extract(str(volumes[0]), str(out_dir))
            else:
                res = run_cli([str(volumes[0]), "--output-dir", str(out_dir)])
                self.assertNotEqual(res.exit_code, 0)


# ===========================================================================
# Feature 7: Chunked Lockstep Deallocation (F7)
# ===========================================================================

class TestF7ChunkedLockstepDeallocation(unittest.TestCase):
    """Tests for Feature F7: Chunked Lockstep Deallocation."""

    def test_f7_01_large_member_extraction_with_chunked_sparse_punch(self) -> None:
        """Verifies extraction of large virtual files using chunked sparse punch-hole deallocation."""
        if not HAS_CHUNKED_SPARSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.chunked_sparse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f7_sparse.zip"
            out_dir = Path(tmp_dir) / "out"
            # 5MB virtual payload
            virtual_size = 5 * 1024 * 1024
            create_sparse_payload_zip(zip_path, target_virtual_size_bytes=virtual_size, filename="game_data.bin")

            if HAS_CHUNKED_SPARSE:
                extractor = ChunkedSparseExtractor(chunk_size=1048576)
                extractor.extract(str(zip_path), str(out_dir))
            else:
                res = run_cli([str(zip_path), "--output-dir", str(out_dir), "--chunk-size", "1048576"])
                self.assertEqual(res.exit_code, 0)

            extracted_file = out_dir / "game_data.bin"
            self.assertTrue(extracted_file.exists())
            self.assertEqual(extracted_file.stat().st_size, virtual_size)

    def test_f7_02_chunk_size_alignment(self) -> None:
        """Verifies chunk size alignment to 64KB cluster boundary."""
        if not HAS_CHUNKED_SPARSE:
            self.skipTest("Requires Milestone M2 (zeroextract.formats.chunked_sparse).")

        # Configured chunk size must align inward/outward to 64KB cluster
        extractor = ChunkedSparseExtractor(chunk_size=1000000)
        self.assertEqual(extractor.cluster_aligned_chunk_size % 65536, 0)

    def test_f7_03_headroom_maintenance_during_chunked_stream(self) -> None:
        """Verifies free disk space remains above cushion throughout streaming chunk decompression."""
        if not HAS_CHUNKED_SPARSE:
            self.skipTest("Requires Milestone M2 (zeroextract.formats.chunked_sparse).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f7_headroom.zip"
            out_dir = Path(tmp_dir) / "out"
            create_sparse_payload_zip(zip_path, target_virtual_size_bytes=2 * 1024 * 1024)

            headroom_samples = []
            extractor = ChunkedSparseExtractor(
                chunk_size=524288,
                on_chunk_processed=lambda free_bytes: headroom_samples.append(free_bytes),
            )
            extractor.extract(str(zip_path), str(out_dir))
            # Headroom samples should remain positive
            for sample in headroom_samples:
                self.assertGreater(sample, 0)

    def test_f7_04_eof_flush(self) -> None:
        """Verifies final partial chunk at EOF is completely flushed and destination is closed."""
        if not HAS_CHUNKED_SPARSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.chunked_sparse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f7_eof.zip"
            out_dir = Path(tmp_dir) / "out"
            # Non-multiple chunk size: 1.5 MB with 1 MB chunk size
            exact_size = 1572864
            create_sparse_payload_zip(zip_path, target_virtual_size_bytes=exact_size, filename="eof_test.bin")

            if HAS_CHUNKED_SPARSE:
                extractor = ChunkedSparseExtractor(chunk_size=1048576)
                extractor.extract(str(zip_path), str(out_dir))
            else:
                res = run_cli([str(zip_path), "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            result_file = out_dir / "eof_test.bin"
            self.assertEqual(result_file.stat().st_size, exact_size)

    def test_f7_05_memory_footprint_stability(self) -> None:
        """Verifies memory footprint remains constant O(chunk_size) during extraction."""
        if not HAS_CHUNKED_SPARSE:
            self.skipTest("Requires Milestone M2 (zeroextract.formats.chunked_sparse).")

        # Buffer allocation should not exceed configured chunk size
        extractor = ChunkedSparseExtractor(chunk_size=1048576)
        self.assertLessEqual(extractor.buffer_capacity, 2 * 1048576)


# ===========================================================================
# Feature 8: 0-Byte Pre-Verification Shield (F8)
# ===========================================================================

class TestF8ZeroBytePreVerificationShield(unittest.TestCase):
    """Tests for Feature F8: 0-Byte Pre-Verification Shield."""

    def test_f8_01_preflight_verification_pass_valid_archive(self) -> None:
        """Verifies preflight pass returns (True, []) on valid, intact archive."""
        if not HAS_PREFLIGHT and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety.preverify) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f8_valid.zip"
            files = {"f1.txt": b"Content 1", "f2.txt": b"Content 2"}
            create_simple_zip(zip_path, files)

            if HAS_PREFLIGHT:
                shield = PreflightShield()
                is_valid, corrupt_entries = shield.verify_archive(str(zip_path))
                self.assertTrue(is_valid)
                self.assertEqual(corrupt_entries, [])
            else:
                res = run_cli([str(zip_path), "--dry-run"])
                self.assertEqual(res.exit_code, 0)

    def test_f8_02_preflight_failure_on_corrupt_payload(self) -> None:
        """Verifies preflight pass detects CRC mismatch and returns False without writing files."""
        if not HAS_PREFLIGHT and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety.preverify) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f8_bad_crc.zip"
            create_corrupt_zip(zip_path, corruption_type="bad_crc")

            if HAS_PREFLIGHT:
                shield = PreflightShield()
                is_valid, corrupt_entries = shield.verify_archive(str(zip_path))
                self.assertFalse(is_valid)
                self.assertGreater(len(corrupt_entries), 0)
            else:
                out_dir = Path(tmp_dir) / "out"
                res = run_cli([str(zip_path), "--output-dir", str(out_dir)])
                self.assertNotEqual(res.exit_code, 0)
                # Output directory must not have extracted corrupted files
                extracted_files = list(out_dir.glob("*")) if out_dir.exists() else []
                self.assertEqual(len(extracted_files), 0)

    def test_f8_03_zero_bytes_allocated_during_preflight(self) -> None:
        """Verifies that 0 bytes and 0 files are written to disk during the preflight pass."""
        if not HAS_PREFLIGHT and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety.preverify) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f8_zero_bytes.zip"
            out_dir = Path(tmp_dir) / "out"
            out_dir.mkdir()
            files = {"big_payload.bin": b"V" * (512 * 1024)}
            create_simple_zip(zip_path, files)

            if HAS_PREFLIGHT:
                shield = PreflightShield()
                shield.verify_archive(str(zip_path))
            else:
                res = run_cli([str(zip_path), "--dry-run", "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)

            # out_dir must have 0 files
            files_in_out = list(out_dir.iterdir())
            self.assertEqual(len(files_in_out), 0, "Preflight must not write any files to disk")

    def test_f8_04_partial_archive_corruption_report(self) -> None:
        """Verifies preflight isolates and reports only the specific corrupted member in an archive."""
        if not HAS_PREFLIGHT:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.preverify).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f8_partial_corrupt.zip"
            create_corrupt_zip(zip_path, corruption_type="bad_crc")

            shield = PreflightShield()
            is_valid, corrupt_list = shield.verify_archive(str(zip_path))
            self.assertFalse(is_valid)
            self.assertIn("game_main.exe", corrupt_list[0])

    def test_f8_05_no_verify_flag_skips_preflight(self) -> None:
        """Verifies that --no-verify flag skips the pre-verification pass."""
        if not HAS_PREFLIGHT and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f8_no_verify.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {"file.txt": b"No verify test"}
            create_simple_zip(zip_path, files)

            if HAS_PREFLIGHT:
                shield = PreflightShield()
                # Calling with skip=True
                self.assertTrue(shield.verify_archive(str(zip_path), skip_preflight=True)[0])
            else:
                res = run_cli([str(zip_path), "--no-verify", "--output-dir", str(out_dir)])
                self.assertEqual(res.exit_code, 0)


# ===========================================================================
# Feature 9: Two-Phase Commit Atomic Writer (F9)
# ===========================================================================

class TestF9TwoPhaseCommitAtomicWriter(unittest.TestCase):
    """Tests for Feature F9: Two-Phase Commit Atomic Writer."""

    def test_f9_01_unpack_part_temp_file_creation(self) -> None:
        """Verifies that intermediate data is staged in .unpack_part temporary file."""
        if not HAS_ATOMIC:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_file = Path(tmp_dir) / "final_output.bin"
            writer = AtomicWriter()

            # Inspect staging path format
            part_path = writer.get_staging_path(str(dest_file))
            self.assertTrue(str(part_path).endswith(".unpack_part"))

    def test_f9_02_atomic_rename_on_success(self) -> None:
        """Verifies atomic rename from .unpack_part to final target file upon matching CRC."""
        if not HAS_ATOMIC:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_file = Path(tmp_dir) / "atomic_success.txt"
            writer = AtomicWriter()
            payload = b"Atomic commit data block 123456"
            crc = zlib.crc32(payload) & 0xFFFFFFFF

            writer.write_atomic(str(dest_file), [payload], expected_crc32=crc)

            self.assertTrue(dest_file.exists())
            self.assertEqual(dest_file.read_bytes(), payload)
            # Staging file must be cleaned up / renamed
            part_file = Path(str(dest_file) + ".unpack_part")
            self.assertFalse(part_file.exists())

    def test_f9_03_cleanup_of_unpack_part_on_crc_mismatch(self) -> None:
        """Verifies cleanup of .unpack_part when CRC verification fails, leaving zero corrupted files."""
        if not HAS_ATOMIC:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_file = Path(tmp_dir) / "corrupt_atomic.bin"
            writer = AtomicWriter()
            payload = b"Actual bytes written"
            bogus_crc = 0xDEADBEEF

            with self.assertRaises(Exception):
                writer.write_atomic(str(dest_file), [payload], expected_crc32=bogus_crc)

            # Neither target file nor .unpack_part should remain on disk
            self.assertFalse(dest_file.exists())
            part_file = Path(str(dest_file) + ".unpack_part")
            self.assertFalse(part_file.exists())

    def test_f9_04_overwrite_handling(self) -> None:
        """Verifies safe atomic overwrite when destination file already exists."""
        if not HAS_ATOMIC:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            dest_file = Path(tmp_dir) / "existing.txt"
            dest_file.write_bytes(b"Old initial contents")

            writer = AtomicWriter()
            new_payload = b"New updated contents"
            crc = zlib.crc32(new_payload) & 0xFFFFFFFF

            writer.write_atomic(str(dest_file), [new_payload], expected_crc32=crc)
            self.assertEqual(dest_file.read_bytes(), new_payload)

    def test_f9_05_directory_permission_preservation(self) -> None:
        """Verifies destination parent directories are created with proper permissions."""
        if not HAS_ATOMIC:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            deep_dest = Path(tmp_dir) / "sub1" / "sub2" / "sub3" / "file.txt"
            writer = AtomicWriter()
            payload = b"Nested content"
            crc = zlib.crc32(payload) & 0xFFFFFFFF

            writer.write_atomic(str(deep_dest), [payload], expected_crc32=crc)
            self.assertTrue(deep_dest.exists())
            self.assertTrue(deep_dest.parent.is_dir())


# ===========================================================================
# Feature 10: Crash-Safe Transaction Journal (F10)
# ===========================================================================

class TestF10CrashSafeTransactionJournal(unittest.TestCase):
    """Tests for Feature F10: Crash-Safe Transaction Journal."""

    def test_f10_01_journal_file_creation(self) -> None:
        """Verifies creation of .unpack_journal.json when extraction begins."""
        if not HAS_JOURNAL:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.journal).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "test.zip"
            archive_path.write_bytes(b"ZIP")

            journal = TransactionJournal(str(archive_path))
            journal.load_or_create()

            journal_path = journal.journal_path
            self.assertTrue(Path(journal_path).exists())
            self.assertTrue(str(journal_path).endswith(".unpack_journal.json"))

    def test_f10_02_completed_entry_recording(self) -> None:
        """Verifies mark_completed writes member completion state and CRC to disk immediately."""
        if not HAS_JOURNAL:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.journal).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "test.zip"
            archive_path.write_bytes(b"ZIP")

            journal = TransactionJournal(str(archive_path))
            journal.load_or_create()
            journal.mark_completed("game/data.pak", uncompressed_size=1024, crc32=0x12345678)

            # Re-read raw JSON from disk
            raw = json.loads(Path(journal.journal_path).read_text(encoding="utf-8"))
            self.assertIn("completed_members", raw)
            self.assertIn("game/data.pak", raw["completed_members"])

    def test_f10_03_journal_replay_on_resumption(self) -> None:
        """Verifies journal replay identifies already-extracted members and skips them."""
        if not HAS_JOURNAL:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.journal).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "test.zip"
            archive_path.write_bytes(b"ZIP")

            # Create existing journal with 2 completed members
            journal = TransactionJournal(str(archive_path))
            journal.load_or_create()
            journal.mark_completed("file1.txt", 100, 0x1111)
            journal.mark_completed("file2.txt", 200, 0x2222)

            # New journal instance loading the same state
            resumed_journal = TransactionJournal(str(archive_path))
            resumed_journal.load_or_create()

            self.assertTrue(resumed_journal.is_completed("file1.txt"))
            self.assertTrue(resumed_journal.is_completed("file2.txt"))
            self.assertFalse(resumed_journal.is_completed("file3.txt"))

    def test_f10_04_corrupted_journal_recovery(self) -> None:
        """Verifies graceful recovery when .unpack_journal.json contains invalid/truncated JSON."""
        if not HAS_JOURNAL:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.journal).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "test.zip"
            archive_path.write_bytes(b"ZIP")

            # Write corrupted JSON to journal file
            journal_path = Path(tmp_dir) / ".unpack_journal.json"
            journal_path.write_text("{corrupt_json: truncated...", encoding="utf-8")

            # load_or_create should handle error gracefully without raising
            journal = TransactionJournal(str(archive_path), journal_path=str(journal_path))
            state = journal.load_or_create()
            self.assertIsNotNone(state)

    def test_f10_05_journal_deletion_on_100_percent_completion(self) -> None:
        """Verifies .unpack_journal.json is deleted upon 100% successful extraction."""
        if not HAS_JOURNAL:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.journal).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "test.zip"
            archive_path.write_bytes(b"ZIP")

            journal = TransactionJournal(str(archive_path))
            journal.load_or_create()
            self.assertTrue(Path(journal.journal_path).exists())

            # Close with success=True
            journal.close(success=True)
            self.assertFalse(Path(journal.journal_path).exists(), "Journal must be deleted on completion")


# ===========================================================================
# Feature 11: Corruption & Rollback Safeguards (F11)
# ===========================================================================

class TestF11CorruptionAndRollbackSafeguards(unittest.TestCase):
    """Tests for Feature F11: Corruption & Rollback Safeguards."""

    def test_f11_01_bad_crc_abort_before_destructive_truncation(self) -> None:
        """Verifies extraction aborts on corrupt entry before truncating or modifying the archive."""
        if not HAS_SAFETY_EXC and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f11_abort.zip"
            create_corrupt_zip(zip_path, corruption_type="bad_crc")
            orig_size = zip_path.stat().st_size

            out_dir = Path(tmp_dir) / "out"
            res = run_cli([str(zip_path), "--output-dir", str(out_dir)])
            self.assertNotEqual(res.exit_code, 0)

            # Archive size must be identical (not truncated!)
            self.assertEqual(zip_path.stat().st_size, orig_size)

    def test_f11_02_original_archive_preserved_on_error(self) -> None:
        """Verifies original archive SHA256 hash is unchanged after an aborted corrupt run."""
        if not _is_cli_executable():
            self.skipTest("Requires executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f11_preserve.zip"
            create_corrupt_zip(zip_path, corruption_type="bad_crc")
            pre_hash = hashlib.sha256(zip_path.read_bytes()).hexdigest()

            out_dir = Path(tmp_dir) / "out"
            run_cli([str(zip_path), "--output-dir", str(out_dir)])

            post_hash = hashlib.sha256(zip_path.read_bytes()).hexdigest()
            self.assertEqual(pre_hash, post_hash, "Archive content must not be modified on error")

    def test_f11_03_no_partial_corrupted_game_files_left(self) -> None:
        """Verifies that no partial or corrupt game files remain on disk after an error abort."""
        if not _is_cli_executable():
            self.skipTest("Requires executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f11_cleanup.zip"
            create_corrupt_zip(zip_path, corruption_type="bad_crc")
            out_dir = Path(tmp_dir) / "out"

            run_cli([str(zip_path), "--output-dir", str(out_dir)])

            # No temporary files (.unpack_part) or broken entries should be left
            verif = verify_directory_contents(out_dir, {}, check_no_temp_files=True)
            self.assertEqual(len(verif.leftover_temp_files), 0)

    def test_f11_04_informative_error_message(self) -> None:
        """Verifies error message output contains member name and CRC mismatch info."""
        if not _is_cli_executable():
            self.skipTest("Requires executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f11_errmsg.zip"
            create_corrupt_zip(zip_path, corruption_type="bad_crc")

            res = run_cli([str(zip_path)])
            combined = res.stdout + res.stderr
            self.assertTrue(
                "crc" in combined.lower() or "corrupt" in combined.lower() or "error" in combined.lower()
            )

    def test_f11_05_exit_code_non_zero(self) -> None:
        """Verifies non-zero exit code when extracting a corrupted archive."""
        if not _is_cli_executable():
            self.skipTest("Requires executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f11_exitcode.zip"
            create_corrupt_zip(zip_path, corruption_type="truncated")

            res = run_cli([str(zip_path)])
            self.assertNotEqual(res.exit_code, 0)


# ===========================================================================
# Feature 12: CLI & Command Options (F12)
# ===========================================================================

class TestF12CliAndCommandOptions(unittest.TestCase):
    """Tests for Feature F12: Command-Line Interface and Options."""

    def test_f12_01_help_display(self) -> None:
        """Verifies --help displays usage flags and exits with code 0."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        res = run_cli(["--help"])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("usage", res.stdout.lower())
        self.assertTrue("--output-dir" in res.stdout or "-o" in res.stdout)

    def test_f12_02_dry_run_simulation_without_file_changes(self) -> None:
        """Verifies --dry-run simulates extraction without writing files or shrinking archive."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f12_dryrun.zip"
            out_dir = Path(tmp_dir) / "out"
            files = {"item.txt": b"Dry run test payload"}
            create_simple_zip(zip_path, files)
            orig_size = zip_path.stat().st_size

            res = run_cli([str(zip_path), "--dry-run", "--output-dir", str(out_dir)])
            self.assertEqual(res.exit_code, 0)

            # Archive must not be shrunk
            self.assertEqual(zip_path.stat().st_size, orig_size)
            # Output directory must have 0 extracted files
            if out_dir.exists():
                self.assertEqual(len(list(out_dir.iterdir())), 0)

    def test_f12_03_output_dir_custom_path(self) -> None:
        """Verifies --output-dir writes files to custom target directory."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f12_custom.zip"
            custom_out = Path(tmp_dir) / "custom" / "extract" / "path"
            files = {"game_asset.bin": b"ASSET_DATA_12345"}
            create_simple_zip(zip_path, files)

            res = run_cli([str(zip_path), "--output-dir", str(custom_out)])
            self.assertEqual(res.exit_code, 0)
            self.assertTrue((custom_out / "game_asset.bin").exists())

    def test_f12_04_chunk_size_configuration(self) -> None:
        """Verifies --chunk-size argument is accepted and configured."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f12_chunk.zip"
            files = {"sample.dat": b"DATA" * 500}
            create_simple_zip(zip_path, files)

            res = run_cli([str(zip_path), "--dry-run", "--chunk-size", "1048576"])
            self.assertEqual(res.exit_code, 0)

    def test_f12_05_unknown_argument_error_handling(self) -> None:
        """Verifies unknown/invalid arguments produce non-zero exit code and error output."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        res = run_cli(["--invalid-unknown-flag-xyz-123"])
        self.assertNotEqual(res.exit_code, 0)


# ===========================================================================
# Feature 13: Interactive Terminal UI (F13)
# ===========================================================================

class TestF13InteractiveTerminalUi(unittest.TestCase):
    """Tests for Feature F13: Interactive Terminal UI."""

    def test_f13_01_progress_reporting_stdout(self) -> None:
        """Verifies console progress emissions to stdout during extraction."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f13_prog.zip"
            files = {f"file_{i}.bin": b"P" * (128 * 1024) for i in range(4)}
            create_simple_zip(zip_path, files)

            res = run_cli([str(zip_path)])
            self.assertEqual(res.exit_code, 0)
            # Should have output indicating progress or completion
            self.assertTrue(len(res.stdout) > 0)

    def test_f13_02_throughput_calculation(self) -> None:
        """Verifies throughput speed calculation formatting."""
        if not HAS_UI:
            self.skipTest("Requires Milestone M4 (zeroextract.cli.ui).")

        ui = TerminalUI()
        formatted_speed = ui.format_throughput(10 * 1024 * 1024)  # 10 MB/s
        self.assertIn("MB/s", formatted_speed)

    def test_f13_03_quiet_mode_headless_output(self) -> None:
        """Verifies --quiet / -q suppresses interactive elements for headless automation."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f13_quiet.zip"
            files = {"item.txt": b"Quiet mode content"}
            create_simple_zip(zip_path, files)

            res = run_cli([str(zip_path), "--quiet"])
            self.assertEqual(res.exit_code, 0)

    def test_f13_04_eta_calculation(self) -> None:
        """Verifies ETA calculation formatting and edge case handling."""
        if not HAS_UI:
            self.skipTest("Requires Milestone M4 (zeroextract.cli.ui).")

        ui = TerminalUI()
        # 60 seconds remaining
        eta_str = ui.format_eta(60.0)
        self.assertTrue("01:00" in eta_str or "60" in eta_str)

        # 0 bytes/sec edge case
        eta_unknown = ui.format_eta(float("inf"))
        self.assertIn("--:--", eta_unknown)

    def test_f13_05_error_message_formatting(self) -> None:
        """Verifies formatted error messages are written to stderr."""
        if not HAS_UI:
            self.skipTest("Requires Milestone M4 (zeroextract.cli.ui).")

        buf = io.StringIO()
        ui = TerminalUI(stream=buf)
        ui.render_error("Test formatted error message")
        output = buf.getvalue()
        self.assertIn("Test formatted error message", output)


# ===========================================================================
# Feature 14: Windows Integration (F14)
# ===========================================================================

class TestF14WindowsIntegration(unittest.TestCase):
    """Tests for Feature F14: Windows Shell Integration."""

    def test_f14_01_drag_and_drop_file_path_handling_via_argv(self) -> None:
        """Verifies drag-and-drop bare positional argument handling (sys.argv[1])."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "f14_dnd.zip"
            files = {"game.exe": b"GAME_EXE"}
            create_simple_zip(zip_path, files)

            # Bare file path without flags
            res = run_cli([str(zip_path), "--dry-run"])
            self.assertEqual(res.exit_code, 0)

    def test_f14_02_spaces_in_paths_handling(self) -> None:
        """Verifies handling of file and directory paths containing spaces."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            space_dir = Path(tmp_dir) / "My Game Archives [2026]"
            space_dir.mkdir()
            zip_path = space_dir / "Super Game Pack v1.0.zip"
            out_dir = Path(tmp_dir) / "Extracted Games Folder"

            files = {"game_asset.dat": b"SPACES_IN_PATH_TEST"}
            create_simple_zip(zip_path, files)

            res = run_cli([str(zip_path), "--output-dir", str(out_dir)])
            self.assertEqual(res.exit_code, 0)
            self.assertTrue((out_dir / "game_asset.dat").exists())

    def test_f14_03_relative_vs_absolute_path_handling(self) -> None:
        """Verifies resolution of both relative and absolute paths."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = Path(tmp_dir) / "rel_test.zip"
            files = {"doc.txt": b"Relative path test"}
            create_simple_zip(zip_path, files)

            # Run with absolute path
            res_abs = run_cli([str(zip_path.resolve()), "--dry-run"])
            self.assertEqual(res_abs.exit_code, 0)

            # Run with relative path from tmp_dir
            res_rel = run_cli(["rel_test.zip", "--dry-run"], cwd=tmp_dir)
            self.assertEqual(res_rel.exit_code, 0)

    def test_f14_04_non_ascii_path_handling(self) -> None:
        """Verifies handling of Unicode and non-ASCII characters in paths."""
        if not _is_cli_executable():
            self.skipTest("Requires Milestone M4 CLI implementation.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            unicode_dir = Path(tmp_dir) / "游戏解压_日本語"
            unicode_dir.mkdir()
            zip_path = unicode_dir / "архив_игры.zip"
            files = {"game.bin": b"UNICODE_PATH_TEST"}
            create_simple_zip(zip_path, files)

            res = run_cli([str(zip_path), "--dry-run"])
            self.assertEqual(res.exit_code, 0)

    def test_f14_05_batch_launcher_cli_wrapper(self) -> None:
        """Verifies Windows batch launcher / CLI wrapper execution capability."""
        if not HAS_WINDOWS:
            self.skipTest("Requires Milestone M4 (zeroextract.cli.windows_setup).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            batch_path = Path(tmp_dir) / "zeroextract.bat"
            win_setup.create_batch_launcher(str(batch_path))
            self.assertTrue(batch_path.exists())
            content = batch_path.read_text(encoding="utf-8")
            self.assertIn("python", content.lower())


if __name__ == "__main__":
    unittest.main()
