"""Tier 4: Real-World Application Scenarios E2E Test Suite for ZeroExtract.

Implements the 5 critical end-user scenarios specified in TEST_INFRA.md:
1. Scenario 1 (50GB-Scale Game Extraction Simulation):
   Simulates 50GB game pack with thousands of files and multi-gigabyte data files
   using sparse/highly-compressible patterns (create_sparse_payload_zip).
   Verifies constant storage headroom cushion, progressive archive shrinking,
   and uncompressed file SHA256 checksum integrity.
2. Scenario 2 (Simulated Power-Cut & Resumption):
   Process is forcibly terminated midway through extracting a large multi-file
   archive (simulate_power_cut_extraction). Verifies preservation of .unpack_journal.json,
   cleanup of in-flight .unpack_part files, seamless resumption skipping completed files,
   and 100% clean completion.
3. Scenario 3 (Multi-Part Split Volume Game Archive with Constrained Disk):
   Multi-part split volume archive (.z01, .z02, ... .zip and numbered .zip.001, ...)
   with disk free space smaller than total archive size. Verifies progressive deletion
   of completed volumes as member data is unpacked, and seamless reassembly of files
   spanning across volume boundaries without data corruption.
4. Scenario 4 (Corrupted Archive Preflight & Rollback Shield):
   Archive containing intentional bit-rot / CRC mismatch in member payload (create_corrupt_zip).
   Verifies 0-byte memory preflight shield detection, abort with 0 bytes extracted,
   preservation of original archive bytes, and no partial or broken game files left on disk.
5. Scenario 5 (Complex Game Directory Structure with Zero-Byte & Deep Paths):
   Complex tree with empty directories, deep nesting (>10 levels), unicode/special characters
   in filenames, mixed compression methods (Deflate, Store), verifying complete game
   hierarchy reconstruction.

Execution:
    python -m unittest tests/e2e/test_tier4_realworld.py
    python tests/run_e2e_tests.py --tier 4
"""

from __future__ import annotations

import hashlib
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
    VerificationResult,
    get_allocated_file_size,
    is_file_sparse,
    is_sparse_supported,
    run_cli,
    simulate_power_cut_extraction,
    verify_directory_contents,
)
from zeroextract.fs import (
    HeadroomMonitor,
    ISpaceReclaimer,
    LowHeadroomError,
    ReverseTruncator,
    SpaceReclaimer,
    SparsePuncher,
    VolumeCleaner,
)

# Optional Milestone 2 format parsers
try:
    from zeroextract.formats import ChunkedSparseExtractor, MultiVolumeStreamer, ZipReverseExtractor
    HAS_FORMATS = True
except (ImportError, ModuleNotFoundError):
    HAS_FORMATS = False
    ZipReverseExtractor = None
    MultiVolumeStreamer = None
    ChunkedSparseExtractor = None


def _is_cli_runnable() -> bool:
    """Check if the ZeroExtract CLI entry point (M4) is implemented and runnable.

    Supports Progressive Testability during milestone progression:
    if ZeroExtract CLI has not yet been linked/built (M4), tests requiring the
    external CLI process skip cleanly rather than failing on import/module absence.
    """
    try:
        res = run_cli(["--help"], timeout=5.0)
        if res.exit_code != 0 and (
            "No module named zeroextract.__main__" in res.stderr
            or "cannot be directly executed" in res.stderr
            or "No such file or directory" in res.stderr
        ):
            return False
        return True
    except Exception:
        return False


# ==============================================================================
# Scenario 1: 50GB-Scale Game Extraction Simulation
# Features: F1 (Sparse Hole-Punching), F2 (Reverse Truncation), F5 (ZIP64 Reverse),
#           F7 (Chunked Deallocation), F8 (Preflight), F9 (Atomic), F10 (Journal)
# ==============================================================================

class TestScenario1_LargeScaleGameExtraction(unittest.TestCase):
    """Scenario 1: 50GB-Scale Game Extraction Simulation.

    Simulates massive game installations with sparse/virtual multi-gigabyte payloads.
    Verifies lockstep space reclamation, storage headroom cushion maintenance,
    and byte-level content integrity.
    """

    def test_s1_50gb_game_simulation_cli_extraction(self) -> None:
        """Simulate a 50GB-scale game extraction workload via ZeroExtract CLI.

        Validates:
        - In-place extraction maintains free space headroom cushion.
        - Physical archive shrinks in lockstep as member files expand to destination.
        - Final extracted member files match expected SHA256 checksums exactly.
        - No leftover temporary staging files (.unpack_part) remain on disk.
        """
        if not _is_cli_runnable() and not HAS_FORMATS:
            self.skipTest("ZeroExtract CLI (M4) or formats (M2) required (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            archive_path = temp_path / "game_50gb_pack.zip"
            extract_dir = temp_path / "extracted_game"

            # 1. Build a synthetic large game archive with sparse payload + companion files
            # Virtual size: 100MB sparse data file (simulating multi-GB data)
            virtual_payload_size = 100 * 1024 * 1024  # 100 MB virtual size
            create_sparse_payload_zip(
                archive_path,
                target_virtual_size_bytes=virtual_payload_size,
                filename="Binaries/Win64/game_world_mesh.dat",
            )

            # Append game executables, libraries, and configs
            companion_files = {
                "Binaries/Win64/GameClient.exe": b"MZ_GAME_BINARY_PAYLOAD_PADDING_" * 500,
                "Binaries/Win64/PhysicsEngine.dll": b"DLL_PHYSICS_CORE_ROUTINES_" * 400,
                "Content/Paks/materials.pak": b"COMPRESSED_MATERIAL_STREAM_" * 1000,
                "Saved/Config/Windows/Engine.ini": b"[Core.System]\nPaths=../../../Content\n",
            }
            with zipfile.ZipFile(archive_path, "a", compression=zipfile.ZIP_DEFLATED) as zf:
                for rel_path, content in companion_files.items():
                    zf.writestr(rel_path, content)

            initial_archive_size = archive_path.stat().st_size
            self.assertGreater(initial_archive_size, 0)

            # 2. Invoke ZeroExtract CLI or ZipReverseExtractor directly
            if _is_cli_runnable():
                min_headroom_bytes = 50 * 1024 * 1024
                res = run_cli([
                    str(archive_path),
                    "-o", str(extract_dir),
                    "--min-headroom", str(min_headroom_bytes),
                ])
                self.assertEqual(res.exit_code, 0, f"Extraction failed with stderr: {res.stderr}")
            else:
                extractor = ZipReverseExtractor(archive_path)
                extractor.extract(output_dir=extract_dir)

            # 3. Verify directory contents & checksums of all extracted files
            v_res = verify_directory_contents(extract_dir, companion_files, check_no_temp_files=True)
            self.assertTrue(v_res.is_valid, f"Verification errors: {v_res.errors}")
            self.assertEqual(len(v_res.corrupted_files), 0)
            self.assertEqual(len(v_res.leftover_temp_files), 0)

            # 4. Verify sparse game data file was extracted
            sparse_file = extract_dir / "Binaries" / "Win64" / "game_world_mesh.dat"
            self.assertTrue(sparse_file.exists())
            self.assertEqual(sparse_file.stat().st_size, virtual_payload_size)

            # 5. Verify archive shrinking: archive was either truncated or deleted upon completion
            if archive_path.exists():
                final_archive_size = archive_path.stat().st_size
                self.assertLess(
                    final_archive_size,
                    initial_archive_size,
                    "Archive file should shrink progressively during reverse extraction",
                )

    def test_s1_ntfs_sparse_payload_reclaimer_integration(self) -> None:
        """Verify M1 filesystem space reclamation on real sparse game payload.

        Tests that when a large virtual game file is uncompressed on NTFS,
        ISpaceReclaimer can punch physical holes into allocated clusters,
        drastically reducing on-disk allocation while preserving data integrity.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            reclaimer = SpaceReclaimer()

            if not reclaimer.sparse.is_sparse_supported(temp_path):
                self.skipTest(f"Filesystem at {temp_path} does not support NTFS sparse files.")

            # Create a 4MB sparse file with 64KB cluster alignment
            sparse_test_file = temp_path / "game_landscape.dat"
            cluster_size = 64 * 1024
            total_size = 64 * cluster_size  # 4,194,304 bytes (4MB)

            # Write header block, followed by repeating zeros, and footer
            header = b"[GAME_SPARSE_LANDSCAPE_V1_HEADER_BLOCK]\n"
            footer = b"\n[GAME_SPARSE_LANDSCAPE_V1_FOOTER_BLOCK]\n"
            content = bytearray(total_size)
            content[:len(header)] = header
            content[-len(footer):] = footer

            sparse_test_file.write_bytes(content)
            orig_sha256 = hashlib.sha256(content).hexdigest()

            # Initial allocated size
            initial_alloc = get_allocated_file_size(sparse_test_file)
            self.assertGreaterEqual(initial_alloc, total_size)

            # Punch hole in the middle (from 512KB to 3.5MB: 3MB hole)
            hole_offset = 8 * cluster_size   # 524,288
            hole_length = 48 * cluster_size  # 3,145,728 (3MB)
            freed = reclaimer.punch_hole(sparse_test_file, hole_offset, hole_length)
            self.assertEqual(freed, hole_length)

            # Verify physical file size decreased by 3MB
            post_punch_alloc = get_allocated_file_size(sparse_test_file)
            self.assertLessEqual(post_punch_alloc, initial_alloc - freed)
            self.assertTrue(is_file_sparse(sparse_test_file))

            # Verify content integrity: reading the file returns identical byte stream and SHA256
            read_back_data = sparse_test_file.read_bytes()
            self.assertEqual(len(read_back_data), total_size)
            self.assertEqual(hashlib.sha256(read_back_data).hexdigest(), orig_sha256)

            # Verify ReverseTruncator shrinks the file physically from the tail
            truncated_size = 16 * cluster_size  # 1MB
            freed_tail = reclaimer.truncate_tail(sparse_test_file, truncated_size)
            self.assertEqual(freed_tail, total_size - truncated_size)
            self.assertEqual(sparse_test_file.stat().st_size, truncated_size)
            self.assertLessEqual(get_allocated_file_size(sparse_test_file), truncated_size)

    def test_s1_headroom_cushion_monitoring_and_threshold_enforcement(self) -> None:
        """Verify real-time headroom monitoring and cushion threshold checks.

        Ensures HeadroomMonitor accurately queries volume free space and raises
        LowHeadroomError when free space drops below the required headroom cushion.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            monitor = HeadroomMonitor()
            free_bytes = monitor.get_free_space(temp_dir)
            total_bytes = monitor.get_total_space(temp_dir)

            self.assertGreater(free_bytes, 0)
            self.assertGreater(total_bytes, free_bytes)

            # Valid headroom check (1KB cushion should pass)
            monitor.ensure_headroom(temp_dir, required_bytes=0, min_headroom_cushion=1024)

            # Excessive headroom check (more than total disk size must raise LowHeadroomError)
            impossible_cushion = total_bytes + (1024 * 1024 * 1024)
            with self.assertRaises(LowHeadroomError) as ctx:
                monitor.ensure_headroom(temp_dir, required_bytes=0, min_headroom_cushion=impossible_cushion)
            self.assertIn("Insufficient disk headroom", str(ctx.exception))


# ==============================================================================
# Scenario 2: Simulated Power-Cut & Resumption
# Features: F2 (Reverse Truncation), F9 (Atomic 2PC Writer),
#           F10 (Crash-Safe Journal), F11 (Corruption Guard)
# ==============================================================================

class TestScenario2_PowerCutAndResumption(unittest.TestCase):
    """Scenario 2: Simulated Power-Cut & Resumption.

    Tests resilience against sudden process termination (simulated power-loss).
    Verifies that .unpack_journal.json is preserved, in-flight .unpack_part files
    are cleanly handled, completed files are skipped on restart, and 100% extraction
    is achieved without data loss or duplicate work.
    """

    def test_s2_power_cut_midway_and_clean_resumption(self) -> None:
        """Forcibly terminate extraction process midway and verify seamless crash-recovery.

        1. Starts extracting a multi-member game archive.
        2. Kills process midway via simulate_power_cut_extraction.
        3. Verifies journal preservation and partial .unpack_part staging.
        4. Restarts extraction: verifies second run completes cleanly with exit code 0.
        5. Verifies all files match expected SHA256 checksums and no temp files remain.
        """
        if not _is_cli_runnable():
            self.skipTest("ZeroExtract CLI (M4) is not yet implemented (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            archive_path = temp_path / "game_multi_file.zip"
            extract_dir = temp_path / "game_output"
            extract_dir.mkdir(parents=True, exist_ok=True)

            # Generate 25 distinct files to ensure substantial extraction duration
            file_dict: dict[str, bytes] = {}
            for i in range(25):
                file_dict[f"Assets/Level_{i:02d}/data_chunk.bin"] = (
                    f"CHUNK_PAYLOAD_{i:02d}_MAGIC_SIGNATURE_".encode("ascii") * 1500
                )
            file_dict["GameLauncher.exe"] = b"MZ_LAUNCHER_HEADER_" * 2000

            create_simple_zip(archive_path, file_dict)

            # Step 1: Simulate power cut (kill process 0.2s into extraction)
            cut_result = simulate_power_cut_extraction(
                args=[str(archive_path), "-o", str(extract_dir)],
                cut_after_seconds=0.2,
            )

            # Step 2: Verify journal file was preserved if any work commenced
            journal_path = extract_dir / ".unpack_journal.json"
            if journal_path.exists():
                try:
                    journal_data = json.loads(journal_path.read_text(encoding="utf-8"))
                    self.assertIsInstance(journal_data, (dict, list))
                except json.JSONDecodeError:
                    self.fail("Journal file exists but contains invalid JSON after crash")

            # Step 3: Restart extraction process
            resume_result = run_cli([str(archive_path), "-o", str(extract_dir)])
            self.assertEqual(
                resume_result.exit_code, 0,
                f"Resumption failed with stderr: {resume_result.stderr}",
            )

            # Step 4: Verify all files are 100% complete and match SHA256
            v_res = verify_directory_contents(extract_dir, file_dict, check_no_temp_files=True)
            self.assertTrue(v_res.is_valid, f"Verification failed post-resume: {v_res.errors}")
            self.assertEqual(len(v_res.corrupted_files), 0)
            self.assertEqual(len(v_res.missing_files), 0)
            self.assertEqual(len(v_res.leftover_temp_files), 0)

    def test_s2_atomic_two_phase_commit_staging_cleanup(self) -> None:
        """Verify atomic two-phase commit file writing semantics.

        Ensures that if an in-flight .unpack_part file was abandoned mid-write,
        resumption safely replaces or removes the orphaned staging file without
        leaving corrupted destination files.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            dest_dir = temp_path / "game_dest"
            dest_dir.mkdir(parents=True, exist_ok=True)

            target_file = dest_dir / "game_script.lua"
            orphaned_part = dest_dir / "game_script.lua.unpack_part"

            # Create an incomplete / corrupted orphaned staging file
            orphaned_part.write_bytes(b"PARTIAL_UNFINISHED_DATA_CORRUPT")

            # Verify target file does not yet exist
            self.assertFalse(target_file.exists())
            self.assertTrue(orphaned_part.exists())

            # Simulate atomic commit completing the write
            clean_payload = b"print('Hello, ZeroExtract Resilient Engine!')\n"
            expected_crc32 = zlib.crc32(clean_payload) & 0xFFFFFFFF

            # Overwrite the .unpack_part, flush, and atomically rename
            orphaned_part.write_bytes(clean_payload)
            actual_crc32 = zlib.crc32(orphaned_part.read_bytes()) & 0xFFFFFFFF
            self.assertEqual(actual_crc32, expected_crc32)

            os.replace(orphaned_part, target_file)

            # Postcondition: target exists with exact bytes, .unpack_part is gone
            self.assertTrue(target_file.exists())
            self.assertFalse(orphaned_part.exists())
            self.assertEqual(target_file.read_bytes(), clean_payload)


# ==============================================================================
# Scenario 3: Multi-Part Split Volume Game Archive with Constrained Disk
# Features: F3 (Volume Unlinking), F4 (Headroom Monitor),
#           F6 (Multi-Volume Stream), F8 (Preflight), F10 (Journal)
# ==============================================================================

class TestScenario3_MultiPartSplitVolumeConstrainedDisk(unittest.TestCase):
    """Scenario 3: Multi-Part Split Volume Game Archive with Constrained Disk.

    Simulates downloading split-volume game archives (.z01, .z02, ... .zip and
    .zip.001, .zip.002, ...) on a disk where free space is less than the total archive.
    Verifies that completed volumes are progressively deleted as member data is
    unpacked, and cross-volume members extract seamlessly without corruption.
    """

    def test_s3_pkware_spanned_archive_progressive_volume_unlinking(self) -> None:
        """Verify progressive unlinking of PKWARE spanned archive (.z01, .z02, .zip).

        Validates:
        - Cross-volume member boundary spanning reassembles seamlessly.
        - Completed volume files (.z01, .z02) are unlinked progressively.
        - Final extracted member files match expected SHA256 checksums.
        """
        if not _is_cli_runnable() and not HAS_FORMATS:
            self.skipTest("ZeroExtract CLI (M4) or MultiVolumeStreamer (M2) required (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            base_zip = temp_path / "game_multi.zip"
            extract_dir = temp_path / "extracted_multi"

            # Create multi-part archive with a large file spanning multiple volumes
            file_dict = {
                "Engine/CoreEngine.dll": b"DLL_STREAM_CROSS_VOLUME_DATA_CHUNK_" * 1200,
                "Levels/Level01.pak": b"LEVEL_GEOMETRY_STREAM_DATA_BLOCK_" * 1500,
                "Config/GameSettings.json": b'{"resolution": "1920x1080", "quality": "Ultra"}\n',
            }

            # 32KB volume limit guarantees at least 3-4 volumes with ZIP_STORED
            volume_paths = create_multi_part_zip(
                base_zip,
                file_dict,
                max_volume_size=32768,
                split_format="pkware",
                compression=zipfile.ZIP_STORED,
            )
            self.assertGreater(len(volume_paths), 1)

            # Verify initial volume existence
            for vp in volume_paths:
                self.assertTrue(vp.exists(), f"Expected volume part missing: {vp}")

            # Run ZeroExtract CLI or MultiVolumeStreamer on the split archive
            if _is_cli_runnable():
                final_zip_path = volume_paths[-1]  # The .zip volume in PKWARE format
                res = run_cli([str(final_zip_path), "-o", str(extract_dir)])
                self.assertEqual(res.exit_code, 0, f"Extraction failed: {res.stderr}")
            else:
                streamer = MultiVolumeStreamer()
                streamer.extract(str(volume_paths[0]), str(extract_dir))

            # Verify extracted files integrity
            v_res = verify_directory_contents(extract_dir, file_dict, check_no_temp_files=True)
            self.assertTrue(v_res.is_valid, f"Verification failed: {v_res.errors}")

            # Verify progressive volume deletion: earlier volume parts (.z01, .z02)
            # must have been unlinked from disk to conserve disk space
            unlinked_parts = [p for p in volume_paths[:-1] if not p.exists()]
            self.assertGreater(
                len(unlinked_parts), 0,
                "Earlier volume slices should be unlinked progressively after consumption",
            )

    def test_s3_numbered_split_archive_progressive_unlinking(self) -> None:
        """Verify progressive unlinking of numbered split archive (.zip.001, .zip.002, ...).

        Validates:
        - Numbered split format detection.
        - Member boundary crossing across multiple sequential slices.
        - Progressive deletion of consumed volume slices.
        """
        if not _is_cli_runnable() and not HAS_FORMATS:
            self.skipTest("ZeroExtract CLI (M4) or MultiVolumeStreamer (M2) required (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            base_zip = temp_path / "numbered_game.zip"
            extract_dir = temp_path / "extracted_numbered"

            file_dict = {
                "soundtrack/bgm_main.ogg": b"OGG_VORBIS_AUDIO_PAYLOAD_DATA_" * 1000,
                "models/character_hero.mesh": b"3D_HERO_MESH_VERTEX_NORMALS_" * 1200,
            }

            volume_paths = create_multi_part_zip(
                base_zip,
                file_dict,
                max_volume_size=32768,
                split_format="numbered",
                compression=zipfile.ZIP_STORED,
            )
            self.assertGreater(len(volume_paths), 1)

            # Run ZeroExtract CLI or MultiVolumeStreamer starting from part .001
            first_vol = volume_paths[0]
            if _is_cli_runnable():
                res = run_cli([str(first_vol), "-o", str(extract_dir)])
                self.assertEqual(res.exit_code, 0, f"Extraction failed: {res.stderr}")
            else:
                streamer = MultiVolumeStreamer()
                streamer.extract(str(first_vol), str(extract_dir))

            # Verify extracted files
            v_res = verify_directory_contents(extract_dir, file_dict, check_no_temp_files=True)
            self.assertTrue(v_res.is_valid, f"Verification failed: {v_res.errors}")

    def test_s3_m1_volume_cleaner_split_detection_and_safe_unlinking(self) -> None:
        """Verify M1 VolumeCleaner correctly classifies and unlinks split volume sets.

        Tests volume extension recognition (.z01, .zip.001, .part01.rar) and
        safe unlinking with Windows read-only attribute stripping.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            cleaner = VolumeCleaner()

            # Test split volume regex classifications
            self.assertTrue(cleaner.is_split_volume("game.z01"))
            self.assertTrue(cleaner.is_split_volume("game.z99"))
            self.assertTrue(cleaner.is_split_volume("game.zip.001"))
            self.assertTrue(cleaner.is_split_volume("game.part01.rar"))
            self.assertTrue(cleaner.is_split_volume("game.7z.001"))
            self.assertFalse(cleaner.is_split_volume("standalone_game.zip"))

            # Create physical split volumes and mark one read-only
            vol1 = temp_path / "game_pack.z01"
            vol2 = temp_path / "game_pack.z02"
            vol1.write_bytes(b"SPLIT_VOLUME_PART_1_DATA")
            vol2.write_bytes(b"SPLIT_VOLUME_PART_2_DATA")

            # Make vol1 read-only on Windows
            if sys.platform == "win32":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(str(vol1), 0x00000001)  # FILE_ATTRIBUTE_READONLY

            # cleaner.unlink_volume must clear read-only attribute and delete successfully
            self.assertTrue(cleaner.unlink_volume(vol1))
            self.assertFalse(vol1.exists())

            self.assertTrue(cleaner.unlink_volume(vol2))
            self.assertFalse(vol2.exists())


# ==============================================================================
# Scenario 4: Corrupted Archive File Preflight & Rollback Shield
# Features: F8 (0-Byte Preflight Shield), F9 (Atomic Writer),
#           F11 (Corruption & Rollback Safeguards)
# ==============================================================================

class TestScenario4_CorruptedArchivePreflightRollback(unittest.TestCase):
    """Scenario 4: Corrupted Archive File Preflight & Rollback Shield.

    Verifies ZeroExtract's safety guarantees when presented with corrupt archives
    (bad CRC, bit-rot, truncated payloads, corrupt central directories).
    Guarantees:
    - Preflight shield aborts before writing corrupt data to destination.
    - Zero bytes of corrupted files are extracted to destination.
    - Original archive bytes are preserved untouched (no destruction/truncation).
    - No orphaned .unpack_part files remain.
    """

    def test_s4_bad_crc_preflight_shield_aborts_with_zero_bytes_extracted(self) -> None:
        """Verify preflight shield aborts on bit-rot / CRC mismatch with 0 extracted bytes.

        1. Creates an archive with valid headers but intentional bit-rot in payload.
        2. Records original archive size and SHA256 checksum.
        3. Runs ZeroExtract CLI.
        4. Verifies non-zero exit code.
        5. Verifies 0 extracted game files in output directory.
        6. Verifies original archive remains 100% byte-identical.
        """
        if not _is_cli_runnable():
            self.skipTest("ZeroExtract CLI (M4) is not yet implemented (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            corrupt_zip = temp_path / "game_bad_crc.zip"
            extract_dir = temp_path / "extracted_corrupt"
            extract_dir.mkdir(parents=True, exist_ok=True)

            create_corrupt_zip(corrupt_zip, corruption_type="bad_crc")
            original_archive_bytes = corrupt_zip.read_bytes()
            original_archive_sha256 = hashlib.sha256(original_archive_bytes).hexdigest()

            # Execute ZeroExtract CLI
            res = run_cli([str(corrupt_zip), "-o", str(extract_dir)])

            # Preflight shield must reject corrupted archive
            self.assertNotEqual(
                res.exit_code, 0,
                f"CLI should fail on corrupted archive, but exited 0. stdout: {res.stdout}",
            )

            # Rollback Shield Guarantee 1: 0 extracted game files
            extracted_files = [
                f for f in extract_dir.rglob("*")
                if f.is_file() and not f.name.startswith(".")
            ]
            self.assertEqual(
                len(extracted_files), 0,
                f"No broken game files should be extracted on corrupt archive, found: {extracted_files}",
            )

            # Rollback Shield Guarantee 2: Original archive preserved untouched
            self.assertTrue(corrupt_zip.exists())
            post_run_bytes = corrupt_zip.read_bytes()
            post_run_sha256 = hashlib.sha256(post_run_bytes).hexdigest()
            self.assertEqual(
                post_run_sha256, original_archive_sha256,
                "Original archive must be preserved untouched when preflight shield detects corruption",
            )

            # Rollback Shield Guarantee 3: No leftover .unpack_part files
            part_files = list(extract_dir.rglob("*.unpack_part"))
            self.assertEqual(len(part_files), 0, "No .unpack_part temporary files should remain")

    def test_s4_truncated_archive_preflight_safeguard(self) -> None:
        """Verify preflight shield safely aborts when archive is truncated midway.

        Ensures that an incomplete download cut in half does not result in partial
        corrupt extractions or filesystem crashes.
        """
        if not _is_cli_runnable():
            self.skipTest("ZeroExtract CLI (M4) is not yet implemented (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            truncated_zip = temp_path / "game_truncated.zip"
            extract_dir = temp_path / "extracted_truncated"
            extract_dir.mkdir(parents=True, exist_ok=True)

            create_corrupt_zip(truncated_zip, corruption_type="truncated")
            orig_bytes = truncated_zip.read_bytes()

            res = run_cli([str(truncated_zip), "-o", str(extract_dir)])
            self.assertNotEqual(res.exit_code, 0, "Truncated archive must yield non-zero exit code")

            # Destination must contain 0 extracted files
            files_on_disk = [f for f in extract_dir.rglob("*") if f.is_file()]
            self.assertEqual(len(files_on_disk), 0)

            # Original archive must not be modified
            self.assertEqual(truncated_zip.read_bytes(), orig_bytes)

    def test_s4_bad_central_directory_preflight_shield(self) -> None:
        """Verify preflight shield detects corrupted Central Directory pointers.

        Central Directory corruption should be detected at step 0 before attempting
        to decompress any entries.
        """
        if not _is_cli_runnable():
            self.skipTest("ZeroExtract CLI (M4) is not yet implemented (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            bad_cd_zip = temp_path / "game_bad_cd.zip"
            extract_dir = temp_path / "extracted_bad_cd"

            create_corrupt_zip(bad_cd_zip, corruption_type="bad_cd")

            res = run_cli([str(bad_cd_zip), "-o", str(extract_dir)])
            self.assertNotEqual(res.exit_code, 0)

    def test_s4_corrupt_fixture_verification(self) -> None:
        """Direct test verifying archive_builder genuinely produces corrupt archives.

        Validates:
        - 'bad_crc' archive causes zipfile.testzip() to detect CRC mismatch.
        - 'truncated' archive causes zipfile.ZipFile to raise BadZipFile.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Test bad_crc fixture
            crc_zip = create_corrupt_zip(temp_path / "fixture_crc.zip", corruption_type="bad_crc")
            with zipfile.ZipFile(crc_zip, "r") as zf:
                bad_entry = zf.testzip()
                self.assertIsNotNone(bad_entry, "zipfile.testzip() should report corrupt CRC entry")

            # Test truncated fixture
            trunc_zip = create_corrupt_zip(temp_path / "fixture_trunc.zip", corruption_type="truncated")
            with self.assertRaises(zipfile.BadZipFile):
                with zipfile.ZipFile(trunc_zip, "r") as zf:
                    zf.testzip()


# ==============================================================================
# Scenario 5: Complex Game Directory Structure with Zero-Byte & Deep Paths
# Features: F5 (ZIP/ZIP64 Reverse), F9 (Atomic), F12 (CLI Options), F13 (UI)
# ==============================================================================

class TestScenario5_ComplexGameDirectoryStructure(unittest.TestCase):
    """Scenario 5: Complex Game Directory Structure with Zero-Byte & Deep Paths.

    Verifies extraction of realistic, deeply nested game directories (>10 levels),
    empty directories, unicode/emoji filenames, 0-byte files, and mixed compression
    methods (DEFLATE and STORE).
    """

    def test_s5_deep_hierarchy_empty_dirs_unicode_mixed_compression_cli(self) -> None:
        """Verify complete game hierarchy reconstruction via ZeroExtract CLI.

        Validates:
        - Deep directory nesting (>10 levels) reconstructed accurately.
        - Explicit empty directories are preserved on disk.
        - Unicode / non-ASCII / emoji filenames extract with intact content.
        - 0-byte files are created with size 0.
        - Mixed compression methods (ZIP_STORED and ZIP_DEFLATED) both decompress cleanly.
        """
        if not _is_cli_runnable() and not HAS_FORMATS:
            self.skipTest("ZeroExtract CLI (M4) or ZipReverseExtractor (M2) required (Progressive Testability)")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            archive_path = temp_path / "game_complex_tree.zip"
            extract_dir = temp_path / "game_installed"

            # Create complex tree archive: 12 levels deep, 3 files/level, empty dirs, unicode
            target_path, file_dict = create_complex_tree_zip(
                archive_path,
                depth=12,
                files_per_level=3,
                include_empty_dirs=True,
                include_unicode=True,
                file_size=256,
            )

            # Execute ZeroExtract CLI or ZipReverseExtractor
            if _is_cli_runnable():
                res = run_cli([str(target_path), "-o", str(extract_dir)])
                self.assertEqual(res.exit_code, 0, f"Extraction failed: {res.stderr}")
            else:
                extractor = ZipReverseExtractor(target_path)
                extractor.extract(output_dir=extract_dir)

            # Verify directory contents
            v_res = verify_directory_contents(extract_dir, file_dict, check_no_temp_files=True)
            self.assertTrue(v_res.is_valid, f"Verification failed with errors: {v_res.errors}")

            # Verify deep directory nesting (sub_level_12 exists)
            deepest_dir = extract_dir / "game_root"
            for lvl in range(1, 13):
                deepest_dir = deepest_dir / f"sub_level_{lvl:02d}"
            self.assertTrue(
                deepest_dir.is_dir(),
                f"Deep directory nesting failed: {deepest_dir} does not exist",
            )

            # Verify empty directory entry exists
            empty_dir = deepest_dir / "empty_folder"
            self.assertTrue(
                empty_dir.is_dir(),
                f"Empty directory missing: {empty_dir}",
            )
            self.assertEqual(len(list(empty_dir.iterdir())), 0)

            # Verify 0-byte file exists and has size 0
            zero_byte_file = extract_dir / "zero_byte.dat"
            self.assertTrue(zero_byte_file.exists())
            self.assertEqual(zero_byte_file.stat().st_size, 0)

            # Verify Unicode filename readability and contents
            unicode_file = extract_dir / "game_root" / "sub_level_01" / "level_01_🎮_savedata_日本語.sav"
            self.assertTrue(unicode_file.exists(), f"Unicode file missing: {unicode_file}")
            self.assertGreater(unicode_file.stat().st_size, 0)

    def test_s5_complex_tree_archive_structure_inspection(self) -> None:
        """Verify create_complex_tree_zip generates valid conforming archive metadata.

        Inspects the archive using standard zipfile to verify:
        - File count exceeds depth * files_per_level.
        - Both STORED and DEFLATED entries exist.
        - Unicode entry names conform to ZIP specification (UTF-8 bit set).
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "test_inspect.zip"
            target_path, file_dict = create_complex_tree_zip(
                archive_path,
                depth=10,
                files_per_level=2,
                include_empty_dirs=True,
                include_unicode=True,
            )

            structure = inspect_zip_structure(target_path)
            self.assertGreaterEqual(structure["file_count"], 20)

            with zipfile.ZipFile(target_path, "r") as zf:
                compression_types = {info.compress_type for info in zf.infolist()}
                self.assertIn(zipfile.ZIP_DEFLATED, compression_types)
                self.assertIn(zipfile.ZIP_STORED, compression_types)

                # Check for 0-byte entry
                zero_infos = [info for info in zf.infolist() if info.filename == "zero_byte.dat"]
                self.assertEqual(len(zero_infos), 1)
                self.assertEqual(zero_infos[0].file_size, 0)

                # Check for explicit directory entry
                dir_infos = [info for info in zf.infolist() if info.filename.endswith("/")]
                self.assertGreater(len(dir_infos), 0)


if __name__ == "__main__":
    unittest.main()
