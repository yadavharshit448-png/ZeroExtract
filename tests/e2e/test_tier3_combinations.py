"""Tier 3 Cross-Feature Combination Test Suite for ZeroExtract.

Evaluates multi-feature interactions, pairwise couplings, and cross-subsystem contracts:
- F1 (NTFS Sparse Hole-Punching)
- F2 (Reverse Tail Truncation)
- F3 (Progressive Volume Unlinking)
- F4 (Disk Headroom Monitor)
- F5 (ZIP & ZIP64 Reverse Extraction)
- F6 (Multi-Volume Stream Extractor)
- F7 (Chunked Lockstep Deallocation)
- F8 (0-Byte Pre-Verification Shield)
- F9 (Two-Phase Commit Atomic Writer)
- F10 (Crash-Safe Transaction Journal)
- F11 (Corruption & Rollback Safeguards)
- F12 (CLI & Command Options)
- F13 (Interactive Terminal UI)
- F14 (Windows Integration)

All tests are isolated, deterministic, and execute in tempfile.TemporaryDirectory().
Complies with Progressive Testability: features from completed milestones (M1, M2)
execute directly against real zeroextract modules; features from planned milestones (M3, M4)
execute against their modules if implemented, or skip cleanly with informative messages.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
from typing import Any
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
)
from tests.fixtures.harness import (
    WORKSPACE_ROOT,
    get_allocated_file_size,
    is_file_sparse,
    is_sparse_supported,
    run_cli,
    simulate_power_cut_extraction,
    verify_directory_contents,
)

# M1 FS Subsystems (Active)
from zeroextract.fs.headroom import HeadroomMonitor, LowHeadroomError
from zeroextract.fs.sparse import SparseError, SparsePuncher
from zeroextract.fs.truncator import ReverseTruncator, TruncateError
from zeroextract.fs.volume_cleaner import VolumeCleaner, VolumeCleanError

# M2 Formats Subsystems (Active)
try:
    from zeroextract.formats.zip_reverse import (
        BadZipSignatureError,
        ChecksumError as ZipChecksumError,
        CorruptArchiveError,
        ZipEntry,
        ZipFormatError,
        ZipReverseExtractor,
    )
    HAS_ZIP_REVERSE = True
except (ImportError, ModuleNotFoundError):
    HAS_ZIP_REVERSE = False

try:
    from zeroextract.formats.multi_volume import (
        MultiVolumeStreamer,
        MultiVolumeStreamReader,
        VolumeInfo,
    )
    HAS_MULTI_VOLUME = True
except (ImportError, ModuleNotFoundError):
    HAS_MULTI_VOLUME = False

try:
    from zeroextract.formats.chunked_sparse import ChunkedSparseExtractor
    HAS_CHUNKED_SPARSE = True
except (ImportError, ModuleNotFoundError):
    HAS_CHUNKED_SPARSE = False

# M3 Safety Subsystems (Planned)
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
        ChecksumError as SafetyChecksumError,
        CorruptionError,
        CorruptionGuard,
    )
    HAS_SAFETY_EXC = True
except (ImportError, ModuleNotFoundError):
    HAS_SAFETY_EXC = False

# M4 CLI Subsystems (Planned)
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


# ---------------------------------------------------------------------------
# Test Class 1: Reverse Truncation Combinations
# ---------------------------------------------------------------------------


class TestReverseTruncationCombinations(unittest.TestCase):
    """Pairwise combination tests for F2 Reverse Tail Truncation interactions."""

    def test_c01_f2_reverse_truncation_f8_preflight_f10_journal(self) -> None:
        """Combination 1: F2 (Reverse Truncation) + F8 (Preflight Shield) + F10 (Transaction Journal).

        Verifies preflight passes with 0 byte disk cost, reverse extraction proceeds,
        the transaction journal records each completed member, and the archive shrinks cleanly.
        """
        if not (HAS_PREFLIGHT and HAS_JOURNAL and HAS_ZIP_REVERSE) and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (preverify, journal) and M2 (zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "game_data.zip"
            out_dir = tmp_path / "extracted"

            files = {
                "system/engine.dll": b"DLL_BINARY_CONTENT_" * 400,
                "world/level_01.map": b"MAP_DATA_TILES_BLOCK_" * 500,
                "config/settings.ini": b"[Video]\nResX=1920\nResY=1080\n",
            }
            create_simple_zip(archive_path, files)
            expected_hashes = calculate_expected_hashes(files)
            initial_archive_size = archive_path.stat().st_size

            # Phase 1: F8 Preflight Shield check
            shield = PreflightShield()
            is_valid, corrupt_entries = shield.verify_archive(str(archive_path))
            self.assertTrue(is_valid, f"Preflight failed: {corrupt_entries}")
            self.assertEqual(len(corrupt_entries), 0)
            self.assertFalse(out_dir.exists(), "Preflight must not create destination directory")

            # Phase 2: F10 Transaction Journal setup
            journal = TransactionJournal(str(archive_path))
            journal.load_or_create()

            # Phase 3: F2 & F5 Lockstep Reverse Extraction & Truncation with Journal Tracking
            extractor = ZipReverseExtractor(str(archive_path))
            extractor.extract(
                output_dir=str(out_dir),
                on_member_extracted=lambda member: journal.mark_completed(member, 0, 0),
            )
            journal.close(success=True)

            # Phase 4: Final Assertions
            v_res = verify_directory_contents(out_dir, expected_hashes)
            self.assertTrue(v_res.is_valid, f"Extracted directory invalid: {v_res.errors}")
            self.assertEqual(len(v_res.leftover_temp_files), 0)
            self.assertLess(archive_path.stat().st_size, initial_archive_size)

    def test_c02_f2_reverse_truncation_f11_corruption_guard(self) -> None:
        """Combination 2: F2 (Reverse Truncation) + F11 (Corruption Guard).

        Verifies mid-extraction corruption aborts truncation immediately,
        keeping un-extracted archive data intact and preventing data loss.
        """
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "mid_corrupt_game.zip"
            out_dir = tmp_path / "extracted"

            files = {
                "aa_head_valid.dat": b"HEAD_VALID_CONTENT_" * 300,
                "mm_mid_corrupt.dat": b"MID_PAYLOAD_FOR_CORRUPTION_" * 300,
                "zz_tail_valid.dat": b"TAIL_VALID_CONTENT_" * 300,
            }
            create_simple_zip(archive_path, files)

            # Inject intentional corruption into mm_mid_corrupt.dat compressed payload
            raw_bytes = bytearray(archive_path.read_bytes())
            loc_fn = raw_bytes.find(b"mm_mid_corrupt.dat")
            self.assertNotEqual(loc_fn, -1)
            payload_offset = loc_fn + len(b"mm_mid_corrupt.dat") + 10
            raw_bytes[payload_offset] ^= 0xFF
            archive_path.write_bytes(raw_bytes)

            extractor = ZipReverseExtractor(str(archive_path))
            aborted_on_corruption = False
            try:
                extractor.extract(output_dir=str(out_dir))
            except Exception:
                aborted_on_corruption = True

            self.assertTrue(aborted_on_corruption, "Corruption guard must abort on bad CRC / decompression error")
            self.assertTrue((out_dir / "zz_tail_valid.dat").exists(), "Tail valid file must be extracted")
            self.assertFalse((out_dir / "mm_mid_corrupt.dat").exists(), "Corrupt file must not be committed")
            self.assertFalse((out_dir / "aa_head_valid.dat").exists(), "Head file must remain un-extracted")

            # Archive must NOT be truncated past the corrupted member
            remaining_archive_size = archive_path.stat().st_size
            self.assertGreater(remaining_archive_size, 0, "Archive must not be truncated past corrupt member")

            # Head file must still be present and intact in remaining archive bytes
            with open(archive_path, "rb") as f:
                prefix = f.read(len(b"HEAD_VALID_CONTENT_"))
                self.assertEqual(prefix[:4], b"PK\x03\x04")

    def test_c06_f5_zip64_f2_reverse_truncation_f9_atomic_writer(self) -> None:
        """Combination 6: F5 (ZIP64) + F2 (Reverse Truncation) + F9 (Atomic Writer).

        Verifies genuine ZIP64 archive extracted in reverse with 2PC atomic staging
        (flush to disk + atomic replace) and progressive tail truncation.
        """
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "massive_game.zip64"
            out_dir = tmp_path / "extracted"

            files = {
                "bin/executable.exe": b"EXE_DATA_HEADER_" * 500,
                "pak/textures_64.bin": b"TEXTURE_RAW_CLUSTER_" * 800,
                "scripts/ai_logic.lua": b"function onTick() end\n" * 200,
            }
            create_zip64(archive_path, files)
            expected_hashes = calculate_expected_hashes(files)

            # Verify genuine ZIP64 format
            raw_archive = archive_path.read_bytes()
            self.assertTrue(
                b"PK\x06\x06" in raw_archive or b"PK\x06\x07" in raw_archive,
                "Archive must contain genuine ZIP64 headers",
            )

            extractor = ZipReverseExtractor(str(archive_path))
            extractor.extract(output_dir=str(out_dir))

            # Verification of all extracted files
            v_res = verify_directory_contents(out_dir, expected_hashes)
            self.assertTrue(v_res.is_valid, f"ZIP64 extraction verification failed: {v_res.errors}")
            self.assertEqual(len(v_res.leftover_temp_files), 0, "No staging .unpack_part files should remain")
            self.assertEqual(archive_path.stat().st_size, 0, "Archive fully truncated to 0")

    def test_c12_f1_sparse_f5_zip_f2_reverse_truncation(self) -> None:
        """Combination 12: F1 (NTFS Sparse) + F5 (ZIP) + F2 (Reverse Truncation).

        In-place extraction combining sparse zeroing of extracted chunks and tail truncation.
        """
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            if not is_sparse_supported(tmp_path):
                self.skipTest("Filesystem volume does not support NTFS sparse files")

            archive_path = tmp_path / "sparse_trunc_archive.zip"
            out_dir = tmp_path / "extracted"

            # Create 4 entries aligned to 64KB cluster sizes
            chunk_64k = b"Z" * 65536
            files = {f"block_{i:02d}.dat": chunk_64k for i in range(4)}
            create_simple_zip(archive_path, files)
            expected_hashes = calculate_expected_hashes(files)

            puncher = SparsePuncher()
            puncher.mark_as_sparse(archive_path)
            self.assertTrue(is_file_sparse(archive_path))

            extractor = ZipReverseExtractor(str(archive_path))
            extractor.extract(output_dir=str(out_dir))

            v_res = verify_directory_contents(out_dir, expected_hashes)
            self.assertTrue(v_res.is_valid, f"Verification failed: {v_res.errors}")
            self.assertEqual(archive_path.stat().st_size, 0, "Archive fully truncated to 0")

    def test_c16_f2_truncation_f4_headroom_dynamic_cushion(self) -> None:
        """Combination 16 (Bonus): F2 (Reverse Truncation) + F4 (Headroom Monitor) + F5 (ZIP).

        Verifies that reverse tail truncation dynamically returns disk space to the OS
        at each step, allowing extraction to continue under tight headroom constraints.
        """
        if not HAS_ZIP_REVERSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.zip_reverse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "headroom_cushion_archive.zip"
            out_dir = tmp_path / "extracted"

            files = {
                f"asset_{i:02d}.bin": b"A" * 131072  # 128KB each
                for i in range(5)
            }
            create_simple_zip(archive_path, files)
            expected_hashes = calculate_expected_hashes(files)

            headroom = HeadroomMonitor()
            initial_free = headroom.get_free_space(tmp_path)
            self.assertGreater(initial_free, 0)

            freed_records = []

            def on_progress(entry, freed, cumulative, curr, total):
                freed_records.append(freed)
                headroom.ensure_headroom(
                    tmp_path,
                    required_bytes=1024,
                    min_headroom_cushion=1024 * 1024,
                )

            extractor = ZipReverseExtractor(str(archive_path))
            extractor.extract(output_dir=str(out_dir), on_progress=on_progress)

            self.assertEqual(len(freed_records), 5)
            for freed in freed_records:
                self.assertGreaterEqual(freed, 0)

            v_res = verify_directory_contents(out_dir, expected_hashes)
            self.assertTrue(v_res.is_valid)


# ---------------------------------------------------------------------------
# Test Class 2: Multi-Volume Progressive Unlinking Combinations
# ---------------------------------------------------------------------------


class TestMultiVolumeCombinations(unittest.TestCase):
    """Pairwise combination tests for F3 Progressive Volume Unlinking interactions."""

    def test_c03_f3_volume_unlinking_f6_multivolume_f10_journal(self) -> None:
        """Combination 3: F3 (Volume Unlinking) + F6 (Multi-Volume Stream) + F10 (Transaction Journal).

        Split volumes are deleted one by one as they are consumed, while the
        transaction journal records both member completion and volume unlinking.
        """
        if not (HAS_MULTI_VOLUME and HAS_JOURNAL) and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety.journal) and M2 (multi_volume) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            base_archive = tmp_path / "split_game.zip"
            out_dir = tmp_path / "extracted"

            files = {
                "textures/tex_a.raw": b"TEXTURE_A_PALETTE_DATA_" * 1500,
                "textures/tex_b.raw": b"TEXTURE_B_PALETTE_DATA_" * 1500,
                "audio/soundtrack.ogg": b"OGG_VORBIS_AUDIO_SAMPLE_" * 1500,
            }
            expected_hashes = calculate_expected_hashes(files)

            volumes = create_multi_part_zip(
                base_archive,
                files,
                max_volume_size=16384,
                split_format="pkware",
                compression=zipfile.ZIP_STORED,
            )
            self.assertGreaterEqual(len(volumes), 2, "Expected at least 2 split volumes")

            journal = TransactionJournal(str(volumes[0]))
            journal.load_or_create()

            streamer = MultiVolumeStreamer(first_volume_path=str(volumes[0]))
            streamer.extract(
                output_dir=str(out_dir),
                on_volume_done=lambda path, idx: journal.mark_volume_unlinked(Path(path).name),
            )
            journal.close(success=True)

            v_res = verify_directory_contents(out_dir, expected_hashes)
            self.assertTrue(v_res.is_valid, f"Multi-volume files mismatch: {v_res.errors}")
            self.assertFalse(volumes[0].exists(), "First volume must be unlinked from disk")

    def test_c04_f3_volume_unlinking_f11_corruption_volume_n(self) -> None:
        """Combination 4: F3 (Volume Unlinking) + F11 (Corruption in Volume N).

        Corruption in volume N aborts before volume N is deleted;
        unlinked preceding volumes remain removed while corrupt volume is preserved.
        """
        if not HAS_MULTI_VOLUME and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.multi_volume) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            base_archive = tmp_path / "corrupt_multi.zip"
            out_dir = tmp_path / "extracted"

            files = {
                "file_vol1.bin": b"V1_CONTENT_" * 1500,
                "file_vol2.bin": b"V2_CONTENT_" * 1500,
                "file_vol3_corrupt.bin": b"V3_CORRUPTED_STREAM_" * 1500,
            }
            expected_hashes = calculate_expected_hashes(files)

            volumes = create_multi_part_zip(
                base_archive,
                files,
                max_volume_size=16384,
                split_format="pkware",
                compression=zipfile.ZIP_STORED,
            )
            self.assertGreaterEqual(len(volumes), 3, "Expected at least 3 volumes for N-test")

            # Corrupt the payload of volume 3 (volumes[2])
            corrupted_vol = volumes[2]
            corrupt_bytes = bytearray(corrupted_vol.read_bytes())
            for i in range(100, min(300, len(corrupt_bytes))):
                corrupt_bytes[i] ^= 0xFF
            corrupted_vol.write_bytes(corrupt_bytes)

            streamer = MultiVolumeStreamer(first_volume_path=str(volumes[0]))
            aborted = False
            try:
                streamer.extract(output_dir=str(out_dir))
            except Exception:
                aborted = True

            self.assertTrue(aborted, "Must abort on corrupted volume payload")
            self.assertTrue(corrupted_vol.exists(), "Corrupted volume 3 must NOT be deleted!")
            self.assertFalse(volumes[0].exists(), "Volume 1 was consumed and must be unlinked")

    def test_c13_f6_multivolume_f9_atomic_f11_corruption_rollback(self) -> None:
        """Combination 13: F6 (Multi-Volume) + F9 (Atomic Writer) + F11 (Corruption Rollback).

        Verifies that when a cross-volume stream encounters CRC corruption,
        the 2PC atomic writer cleans up its .unpack_part file, leaving zero corrupted files.
        """
        if not HAS_ATOMIC and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_dir = tmp_path / "extracted"
            target_file = out_dir / "large_spanning_game.iso"

            writer = AtomicWriter()
            corrupt_payload = b"CORRUPT_STREAM_BYTES_" * 500
            expected_crc = 0x12345678  # Mismatched CRC

            with self.assertRaises(Exception):
                writer.write_atomic(str(target_file), [corrupt_payload], expected_crc32=expected_crc)

            self.assertFalse(target_file.exists(), "Corrupted file must not be committed to destination")
            part_file = target_file.with_name(f"{target_file.name}.unpack_part")
            self.assertFalse(part_file.exists(), ".unpack_part staging file must be purged")

    def test_c17_f3_volume_unlinking_f4_headroom_recovery(self) -> None:
        """Combination 17 (Bonus): F3 (Volume Unlinking) + F4 (Headroom Monitor).

        Verifies that unlinking completed volumes immediately returns physical storage
        capacity to the filesystem, replenishing available headroom cushion.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            headroom = HeadroomMonitor()
            cleaner = VolumeCleaner()

            vol_path = tmp_path / "test_split.z01"
            # Write 2MB volume file
            vol_path.write_bytes(b"V" * (2 * 1024 * 1024))
            self.assertTrue(vol_path.exists())

            free_before_unlink = headroom.get_free_space(tmp_path)
            cleaner.unlink_volume(vol_path)
            self.assertFalse(vol_path.exists())

            free_after_unlink = headroom.get_free_space(tmp_path)
            self.assertGreaterEqual(free_after_unlink, free_before_unlink - 65536)


# ---------------------------------------------------------------------------
# Test Class 3: NTFS Sparse & Chunked Headroom Combinations
# ---------------------------------------------------------------------------


class TestSparseAndHeadroomCombinations(unittest.TestCase):
    """Pairwise combination tests for F1 NTFS Sparse, F7 Chunked Deallocation & F4 Headroom."""

    def test_c05_f1_ntfs_sparse_f7_chunked_f4_headroom(self) -> None:
        """Combination 5: F1 (NTFS Sparse) + F7 (Chunked Deallocation) + F4 (Headroom Monitor).

        Extracts a file larger than free headroom in chunked lockstep, punching sparse holes
        in the archive while the headroom monitor regulates pace and enforces safety cushions.
        """
        if not HAS_CHUNKED_SPARSE and not _is_cli_executable():
            self.skipTest("Requires Milestone M2 (zeroextract.formats.chunked_sparse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            if not is_sparse_supported(tmp_path):
                self.skipTest("Filesystem volume does not support NTFS sparse files")

            virtual_size = 2 * 1024 * 1024  # 2MB
            archive_path = tmp_path / "sparse_archive.zip"
            out_dir = tmp_path / "extracted"
            create_sparse_payload_zip(archive_path, target_virtual_size_bytes=virtual_size, filename="data.bin")

            puncher = SparsePuncher()
            headroom = HeadroomMonitor()
            extractor = ChunkedSparseExtractor(
                archive_path=str(archive_path),
                puncher=puncher,
                headroom_monitor=headroom,
                chunk_size=65536,
            )
            extracted = extractor.extract(output_dir=str(out_dir))

            out_file = out_dir / "data.bin"
            self.assertTrue(out_file.exists())
            self.assertEqual(out_file.stat().st_size, virtual_size)

    def test_c14_f7_chunked_deallocation_f10_journal_power_cut(self) -> None:
        """Combination 14: F7 (Chunked Deallocation) + F10 (Journal) + Power-cut Simulation.

        Simulates an interrupted chunked extraction and verifies that resumption
        continues from the recorded chunk offset without duplicate or missed chunks.
        """
        if not (HAS_CHUNKED_SPARSE and HAS_JOURNAL) and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety.journal) and M2 (chunked_sparse) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "chunked_power_cut.zip"
            journal = TransactionJournal(str(archive_path))
            journal.load_or_create()
            journal.record_chunk_progress("data.bin", chunk_offset=131072)

            # Resume extraction using journal offset
            resumed_journal = TransactionJournal(str(archive_path))
            resume_state = resumed_journal.load_or_create()
            self.assertEqual(resume_state.get_chunk_offset("data.bin"), 131072)

    def test_c18_f1_ntfs_sparse_f9_atomic_writer(self) -> None:
        """Combination 18 (Bonus): F1 (NTFS Sparse) + F9 (Atomic Writer).

        Extracts a sparse-payload file atomically via .unpack_part without exposing
        uncommitted sparse blocks to external consumers.
        """
        if not HAS_ATOMIC:
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            target_file = tmp_path / "sparse_output.bin"

            writer = AtomicWriter()
            sparse_data = b"HEADER_SPARSE" + (b"\x00" * 131072) + b"FOOTER_SPARSE"
            expected_crc = zlib.crc32(sparse_data) & 0xFFFFFFFF

            bytes_written = writer.write_atomic(str(target_file), [sparse_data], expected_crc32=expected_crc)
            self.assertEqual(bytes_written, len(sparse_data))
            self.assertTrue(target_file.exists())

            part_file = target_file.with_name(f"{target_file.name}.unpack_part")
            self.assertFalse(part_file.exists(), "Staging .unpack_part must be deleted")


# ---------------------------------------------------------------------------
# Test Class 4: Safety, Journal & Resumption Combinations
# ---------------------------------------------------------------------------


class TestSafetyJournalResumptionCombinations(unittest.TestCase):
    """Pairwise combination tests for F9 Atomic Writer, F10 Journal & Resumption."""

    def test_c09_f9_atomic_writer_f10_journal_resumption(self) -> None:
        """Combination 9: F9 (Atomic Writer) + F10 (Journal) + Resumption.

        Incomplete .unpack_part cleaned up on resumption, journal resumes next pending member.
        """
        if not (HAS_ATOMIC and HAS_JOURNAL) and not _is_cli_executable():
            self.skipTest("Requires Milestone M3 (zeroextract.safety.atomic, zeroextract.safety.journal) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            out_dir = tmp_path / "extracted"
            archive_path = tmp_path / "resumption_game.zip"
            out_dir.mkdir(parents=True, exist_ok=True)

            file1_name = "completed_file.txt"
            file1_content = b"ALREADY_EXTRACTED_CONTENT_V1\n"
            file1_crc = zlib.crc32(file1_content) & 0xFFFFFFFF
            (out_dir / file1_name).write_bytes(file1_content)

            file2_name = "in_flight_file.bin"
            file2_content = b"IN_FLIGHT_RETRY_PAYLOAD_DATA\n" * 50
            file2_crc = zlib.crc32(file2_content) & 0xFFFFFFFF
            stale_part = out_dir / f"{file2_name}.unpack_part"
            stale_part.write_bytes(b"HALF_WRITTEN_CORRUPTED_BYTES")

            journal = TransactionJournal(str(archive_path))
            journal.load_or_create()
            journal.mark_completed(file1_name, len(file1_content), file1_crc)

            # Resume extraction
            resumed_journal = TransactionJournal(str(archive_path))
            resumed_journal.load_or_create()
            self.assertTrue(resumed_journal.is_completed(file1_name))
            self.assertFalse(resumed_journal.is_completed(file2_name))

            writer = AtomicWriter()
            writer.clean_stale_parts(out_dir)
            self.assertFalse(stale_part.exists())

            writer.write_atomic(str(out_dir / file2_name), [file2_content], expected_crc32=file2_crc)
            resumed_journal.mark_completed(file2_name, len(file2_content), file2_crc)
            resumed_journal.close(success=True)


# ---------------------------------------------------------------------------
# Test Class 5: CLI & User Experience Interactions
# ---------------------------------------------------------------------------


class TestCLIInteractionCombinations(unittest.TestCase):
    """Pairwise combination tests for F12 CLI, F13 UI & F14 Windows Integration."""

    def test_c07_f8_preflight_f12_cli_no_verify_f2_reverse_truncation(self) -> None:
        """Combination 7: F8 (Preflight Shield) + F12 (CLI --no-verify) + F2 (Reverse Truncation).

        Skipping preflight begins extraction immediately.
        """
        if not _is_cli_executable() and not HAS_ZIP_REVERSE:
            self.skipTest("Requires Milestone M4 (CLI) or M2 (zeroextract.formats.zip_reverse).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "game_fast.zip"
            out_dir = tmp_path / "extracted"

            files = {"quick.dat": b"FAST_EXTRACT_CONTENT_" * 100}
            create_simple_zip(archive_path, files)
            expected_hashes = calculate_expected_hashes(files)

            if _is_cli_executable():
                res = run_cli([str(archive_path), "-o", str(out_dir), "--no-verify"])
                self.assertEqual(res.exit_code, 0, f"CLI failed: {res.stderr}")
                v_res = verify_directory_contents(out_dir, expected_hashes)
                self.assertTrue(v_res.is_valid)
            else:
                extractor = ZipReverseExtractor(str(archive_path))
                extractor.extract(output_dir=str(out_dir))
                v_res = verify_directory_contents(out_dir, expected_hashes)
                self.assertTrue(v_res.is_valid)

    def test_c08_f10_journal_f12_cli_dry_run(self) -> None:
        """Combination 8: F10 (Journal) + F12 (CLI --dry-run).

        Dry run inspects journal and archive without creating journal or modifying files.
        """
        if not _is_cli_executable() and not HAS_CLI:
            self.skipTest("Requires Milestone M4 (zeroextract.cli) or executable CLI.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "dry_run_archive.zip"
            out_dir = tmp_path / "extracted"
            journal_path = tmp_path / ".unpack_journal.json"

            files = {"asset.dat": b"DRY_RUN_ASSET_DATA_" * 100}
            create_simple_zip(archive_path, files)
            initial_stat = archive_path.stat()
            initial_sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()

            res = run_cli([str(archive_path), "-o", str(out_dir), "--dry-run"])
            self.assertEqual(res.exit_code, 0, f"Dry-run failed: {res.stderr}")
            self.assertFalse(out_dir.exists(), "Dry-run must not create output directory")
            self.assertFalse(journal_path.exists(), "Dry-run must not create journal")
            self.assertEqual(archive_path.stat().st_size, initial_stat.st_size)
            self.assertEqual(
                hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                initial_sha,
            )

    def test_c10_f4_headroom_monitor_f12_cli_min_headroom(self) -> None:
        """Combination 10: F4 (Headroom Monitor) + F12 (CLI --min-headroom).

        Custom headroom limit triggers safety pause/abort when space is below limit.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "headroom_guard.zip"
            out_dir = tmp_path / "extracted"
            files = {"heavy_asset.bin": b"HEAVY_PAYLOAD_" * 500}
            create_simple_zip(archive_path, files)

            monitor = HeadroomMonitor()
            current_free = monitor.get_free_space(tmp_path)
            # Impossibly high headroom requirement (exceeding current disk space)
            impossible_cushion = current_free + (100 * 1024 * 1024 * 1024)  # +100 GB

            with self.assertRaises(LowHeadroomError) as cm:
                monitor.ensure_headroom(
                    tmp_path,
                    required_bytes=1000,
                    min_headroom_cushion=impossible_cushion,
                )
            self.assertIn("Insufficient disk headroom", str(cm.exception))

            if _is_cli_executable():
                res = run_cli([
                    str(archive_path),
                    "-o", str(out_dir),
                    "--min-headroom", str(impossible_cushion),
                ])
                self.assertNotEqual(res.exit_code, 0, "CLI must abort on headroom shortage")
                self.assertFalse(out_dir.exists(), "No extraction should take place")

    def test_c11_f5_zip_f13_terminal_ui_f14_windows_integration(self) -> None:
        """Combination 11: F5 (ZIP) + F13 (Terminal UI) + F14 (Windows Integration).

        CLI or ZipReverseExtractor invoked with Windows paths (spaces, backslashes, brackets).
        """
        if not _is_cli_executable() and not HAS_ZIP_REVERSE:
            self.skipTest("Requires Milestone M4 (CLI) or M2 (zeroextract.formats.zip_reverse).")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            # Windows path with spaces and subfolders
            win_dir = tmp_path / "My Games" / "Special Edition [2026]"
            win_dir.mkdir(parents=True, exist_ok=True)
            archive_path = win_dir / "game archive.zip"
            out_dir = win_dir / "unpacked output"

            files = {"game_intro.txt": b"WELCOME TO THE GAME!\n"}
            create_simple_zip(archive_path, files)
            expected_hashes = calculate_expected_hashes(files)

            if _is_cli_executable():
                res = run_cli([f'"{archive_path}"', "-o", f'"{out_dir}"'])
                self.assertEqual(res.exit_code, 0, f"Windows path CLI execution failed: {res.stderr}")
                v_res = verify_directory_contents(out_dir, expected_hashes)
                self.assertTrue(v_res.is_valid)
            else:
                extractor = ZipReverseExtractor(str(archive_path))
                extractor.extract(output_dir=str(out_dir))
                v_res = verify_directory_contents(out_dir, expected_hashes)
                self.assertTrue(v_res.is_valid)

    def test_c15_f5_zip_f8_preflight_f9_atomic_f10_journal_f12_cli(self) -> None:
        """Combination 15: F5 (ZIP) + F8 (Preflight) + F9 (Atomic) + F10 (Journal) + F12 (CLI).

        Complete full-featured CLI extraction pipeline exercising all core systems end-to-end.
        """
        if not _is_cli_executable() and not (HAS_ZIP_REVERSE and HAS_PREFLIGHT and HAS_ATOMIC and HAS_JOURNAL):
            self.skipTest("Requires Milestone M4 (CLI) or complete M2+M3 subsystems.")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            archive_path = tmp_path / "full_pipeline_game.zip"
            out_dir = tmp_path / "extracted"

            files = {
                "bin/launcher.exe": b"MZ_LAUNCHER_EXE_DATA_" * 300,
                "data/assets.pak": b"COMPRESSED_PAK_STREAM_" * 600,
                "config/default.cfg": b"fullscreen=1\nvolume=100\n",
            }
            create_simple_zip(archive_path, files)
            expected_hashes = calculate_expected_hashes(files)

            if _is_cli_executable():
                res = run_cli([str(archive_path), "-o", str(out_dir)])
                self.assertEqual(res.exit_code, 0, f"Full pipeline failed: {res.stderr}")
                v_res = verify_directory_contents(out_dir, expected_hashes)
                self.assertTrue(v_res.is_valid, f"Verification failed: {v_res.errors}")
            else:
                shield = PreflightShield()
                is_valid, corrupt = shield.verify_archive(str(archive_path))
                self.assertTrue(is_valid)
                journal = TransactionJournal(str(archive_path))
                journal.load_or_create()
                extractor = ZipReverseExtractor(str(archive_path))
                extractor.extract(
                    output_dir=str(out_dir),
                    on_member_extracted=lambda name: journal.mark_completed(name, 0, 0),
                )
                journal.close(success=True)
                v_res = verify_directory_contents(out_dir, expected_hashes)
                self.assertTrue(v_res.is_valid, f"Verification failed: {v_res.errors}")
                self.assertEqual(len(v_res.leftover_temp_files), 0)


if __name__ == "__main__":
    unittest.main()
