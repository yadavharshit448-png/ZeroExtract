"""Comprehensive unit tests for ZeroExtract archive formats subsystem.

Tests:
1. ZipReverseExtractor: Central Directory parsing, reverse extraction sequence,
   real physical tail truncation, empty files/dirs, CRC32 mismatch detection.
2. MultiVolumeStreamer: Volume discovery, virtual cross-boundary stream reads,
   progressive volume unlinking, sequence gap detection.
3. ChunkedSparseExtractor: Forward chunked decompression, 64KB cluster-aligned
   sparse hole-punching, headroom monitoring, fallback modes.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import struct
import sys
import tempfile
from unittest.mock import MagicMock, patch
import zipfile
import zlib

import pytest

from tests.fixtures.archive_builder import (
    calculate_expected_hashes,
    create_corrupt_zip,
    create_multi_part_zip,
    create_simple_zip,
    create_sparse_payload_zip,
    create_zip64,
    inspect_zip_structure,
)
from tests.fixtures.harness import get_allocated_file_size, is_sparse_supported, verify_directory_contents
from zeroextract.fs import (
    HeadroomMonitor,
    LowHeadroomError,
    ReverseTruncator,
    SparseError,
    SparsePuncher,
    VolumeCleaner,
    VolumeCleanError,
)
from zeroextract.formats.chunked_sparse import ChunkedSparseExtractor
from zeroextract.formats.multi_volume import MultiVolumeStreamer, MultiVolumeStreamReader, VolumeInfo
from zeroextract.formats.zip_reverse import (
    ChecksumError,
    PathTraversalError,
    UnsupportedCompressionError,
    ZipEntry,
    ZipReverseExtractor,
)


# ===========================================================================
# 1. ZipReverseExtractor Unit Tests
# ===========================================================================


class TestZipReverseExtractor:
    """Unit tests for Central Directory parsing, reverse extraction, and tail truncation."""

    def test_scan_central_directory_sorted_descending(self, tmp_path: Path) -> None:
        """Verifies Central Directory entries are returned sorted descending by local_header_offset."""
        zip_file = tmp_path / "order_test.zip"
        files = {
            "first.txt": b"First entry",
            "second.txt": b"Second entry with longer text",
            "third.txt": b"Third entry at the tail",
        }
        create_simple_zip(zip_file, files)

        extractor = ZipReverseExtractor(zip_file)
        entries = extractor.scan_central_directory()

        assert len(entries) == 3
        # Offsets must be strictly descending
        offsets = [e.local_header_offset for e in entries]
        assert offsets == sorted(offsets, reverse=True)
        assert entries[0].filename == "third.txt"
        assert entries[-1].filename == "first.txt"

    def test_reverse_extraction_stored_entries(self, tmp_path: Path) -> None:
        """Verifies reverse extraction of uncompressed (STORE) files with lockstep truncation."""
        zip_file = tmp_path / "stored.zip"
        out_dir = tmp_path / "out_stored"
        files = {
            "data1.bin": b"STORED_DATA_AAAA" * 500,
            "data2.bin": b"STORED_DATA_BBBB" * 800,
        }
        create_simple_zip(zip_file, files, compression=zipfile.ZIP_STORED)

        extractor = ZipReverseExtractor(zip_file)
        extracted = extractor.extract_all(out_dir)

        assert len(extracted) == 2
        verif = verify_directory_contents(out_dir, files)
        assert verif.is_valid

        # Physical archive file must have been truncated to 0 bytes
        assert zip_file.stat().st_size == 0

    def test_reverse_extraction_deflated_entries(self, tmp_path: Path) -> None:
        """Verifies reverse extraction of compressed (DEFLATE) files with lockstep truncation."""
        zip_file = tmp_path / "deflated.zip"
        out_dir = tmp_path / "out_deflate"
        files = {
            "doc1.txt": b"Deflated document content one " * 200,
            "doc2.txt": b"Deflated document content two " * 300,
            "doc3.txt": b"Deflated document content three " * 400,
        }
        create_simple_zip(zip_file, files, compression=zipfile.ZIP_DEFLATED)

        extractor = ZipReverseExtractor(zip_file)
        extracted = extractor.extract_all(out_dir)

        assert len(extracted) == 3
        verif = verify_directory_contents(out_dir, files)
        assert verif.is_valid
        assert zip_file.stat().st_size == 0

    def test_zip64_central_directory_and_extraction(self, tmp_path: Path) -> None:
        """Verifies parsing of ZIP64 EOCD Locator and Record with 64-bit offsets."""
        zip_file = tmp_path / "zip64.zip"
        out_dir = tmp_path / "out_zip64"
        files = {f"file_{i:02d}.dat": f"ZIP64 payload {i}".encode("utf-8") * 100 for i in range(5)}
        create_zip64(zip_file, files)

        info = inspect_zip_structure(zip_file)
        assert info["is_zip64"] is True

        extractor = ZipReverseExtractor(zip_file)
        entries = extractor.scan_central_directory()
        assert len(entries) == 5

        extracted = extractor.extract_all(out_dir)
        assert len(extracted) == 5
        verif = verify_directory_contents(out_dir, files)
        assert verif.is_valid

    def test_empty_files_and_directories(self, tmp_path: Path) -> None:
        """Verifies reverse extraction correctly creates 0-byte files and empty subdirectories."""
        zip_file = tmp_path / "empty_entries.zip"
        out_dir = tmp_path / "out_empty"

        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("zero.txt", b"")
            zinfo = zipfile.ZipInfo("empty_dir/", date_time=(2026, 1, 1, 12, 0, 0))
            zinfo.external_attr = 0o755 << 16 | 0x10
            zf.writestr(zinfo, b"")

        extractor = ZipReverseExtractor(zip_file)
        extractor.extract_all(out_dir)

        assert (out_dir / "zero.txt").exists()
        assert (out_dir / "zero.txt").stat().st_size == 0
        assert (out_dir / "empty_dir").is_dir()

    def test_crc32_mismatch_aborts_without_truncating(self, tmp_path: Path) -> None:
        """Verifies that an entry with bad CRC32 raises an exception and leaves archive intact."""
        zip_file = tmp_path / "corrupt_crc.zip"
        out_dir = tmp_path / "out_crc"
        create_corrupt_zip(zip_file, corruption_type="bad_crc", file_dict={"bad_entry.bin": b"PAYLOAD_" * 100})
        original_size = zip_file.stat().st_size

        extractor = ZipReverseExtractor(zip_file)
        with pytest.raises((ValueError, OSError), match="CRC32"):
            extractor.extract_all(out_dir)

        # Archive must NOT have been truncated when corruption detected
        assert zip_file.stat().st_size == original_size

    def test_path_traversal_prevention(self, tmp_path: Path) -> None:
        """Verifies that entries with path traversal sequences raise PathTraversalError."""
        zip_file = tmp_path / "traversal.zip"
        out_dir = tmp_path / "out_sec"

        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("../evil.txt", b"hacked")

        extractor = ZipReverseExtractor(zip_file)
        with pytest.raises(PathTraversalError):
            extractor.extract_all(out_dir)

    def test_unsupported_compression_method(self, tmp_path: Path) -> None:
        """Verifies that compression methods other than STORE and DEFLATE raise UnsupportedCompressionError."""
        zip_file = tmp_path / "bzip2.zip"
        out_dir = tmp_path / "out_bzip2"

        with zipfile.ZipFile(zip_file, "w", compression=zipfile.ZIP_BZIP2) as zf:
            zf.writestr("bzip_entry.txt", b"Bzip2 compressed data")

        extractor = ZipReverseExtractor(zip_file)
        with pytest.raises(UnsupportedCompressionError):
            extractor.extract_all(out_dir)


# ===========================================================================
# 2. MultiVolumeStreamer Unit Tests
# ===========================================================================


class TestMultiVolumeStreamer:
    """Unit tests for split volume discovery, virtual stream reading, and progressive unlinking."""

    def test_discover_volumes_pkware(self, tmp_path: Path) -> None:
        """Verifies sequence discovery for PKWARE format (.z01, .z02, ... .zip)."""
        base_zip = tmp_path / "split_pkware.zip"
        files = {"large.bin": b"CHUNK" * 15000}
        vols = create_multi_part_zip(
            base_zip, files, max_volume_size=16384, split_format="pkware", compression=zipfile.ZIP_STORED
        )
        assert len(vols) >= 3

        streamer = MultiVolumeStreamer(vols[0])
        discovered = streamer.discover_volumes()

        assert len(discovered) == len(vols)
        assert [str(p) for p in discovered] == [str(p) for p in vols]

    def test_discover_volumes_numbered(self, tmp_path: Path) -> None:
        """Verifies sequence discovery for numbered format (.part01.rar or .001)."""
        base = tmp_path / "numbered.zip"
        files = {"data.bin": b"PAYLOAD" * 10000}
        vols = create_multi_part_zip(
            base, files, max_volume_size=16384, split_format="numbered", compression=zipfile.ZIP_STORED
        )
        assert len(vols) >= 3

        streamer = MultiVolumeStreamer(vols[0])
        discovered = streamer.discover_volumes()

        assert len(discovered) == len(vols)
        assert [str(p) for p in discovered] == [str(p) for p in vols]

    def test_discover_volumes_gap_error(self, tmp_path: Path) -> None:
        """Verifies that a gap in the volume sequence raises FileNotFoundError."""
        base_zip = tmp_path / "gap.zip"
        files = {"test.bin": b"DATA" * 15000}
        vols = create_multi_part_zip(base_zip, files, max_volume_size=16384, compression=zipfile.ZIP_STORED)
        assert len(vols) >= 3

        # Delete intermediate volume (.z02)
        vols[1].unlink()

        streamer = MultiVolumeStreamer(vols[0])
        with pytest.raises(FileNotFoundError):
            streamer.discover_volumes()

    def test_validate_volume_sequence_out_of_order(self) -> None:
        """Verifies validate_volume_sequence detects scrambled volume order."""
        streamer = MultiVolumeStreamer()
        scrambled = ["archive.z02", "archive.z01", "archive.zip"]
        with pytest.raises((ValueError, OSError)):
            streamer.validate_volume_sequence(scrambled)

    def test_virtual_stream_boundary_crossing(self, tmp_path: Path) -> None:
        """Verifies reading data buffers that straddle volume boundaries."""
        vol1 = tmp_path / "span.001"
        vol2 = tmp_path / "span.002"
        data1 = b"AAAAABBBBB"  # 10 bytes
        data2 = b"CCCCCDDDDD"  # 10 bytes
        vol1.write_bytes(data1)
        vol2.write_bytes(data2)

        vols = [
            VolumeInfo(0, str(vol1), 10, 0),
            VolumeInfo(1, str(vol2), 10, 10),
        ]
        with MultiVolumeStreamReader(vols) as stream:
            # Read across boundary (from byte 5 to 15)
            stream.seek(5)
            read_data = stream.read(10)
            assert read_data == b"BBBBBCCCCC"

            # Seek and tell
            assert stream.tell() == 15
            assert stream.read(5) == b"DDDDD"
            assert stream.read(5) == b""  # EOF

    def test_progressive_volume_unlinking(self, tmp_path: Path) -> None:
        """Verifies that volume files are deleted once the stream completely consumes them."""
        base_zip = tmp_path / "prog.zip"
        out_dir = tmp_path / "out_prog"
        files = {f"file_{i}.bin": b"VOLUME_TEST_CHUNK_" * 1000 for i in range(6)}
        vols = create_multi_part_zip(base_zip, files, max_volume_size=16384, compression=zipfile.ZIP_STORED)
        assert len(vols) >= 3

        deleted_volumes = []
        cleaner = VolumeCleaner()
        mock_unlink = MagicMock(side_effect=lambda p: (deleted_volumes.append(str(p)), True)[1])

        with patch.object(cleaner, "unlink_volume", mock_unlink):
            streamer = MultiVolumeStreamer(vols[0], cleaner=cleaner)
            streamer.extract_and_clean(out_dir)

        assert len(deleted_volumes) >= len(vols) - 1

    def test_read_after_unlinked_volume_raises_error(self, tmp_path: Path) -> None:
        """Verifies that attempting to read an already-unlinked volume raises VolumeCleanError."""
        vol1 = tmp_path / "v1.001"; vol1.write_bytes(b"DATA1")
        vol2 = tmp_path / "v2.002"; vol2.write_bytes(b"DATA2")
        vols = [VolumeInfo(0, str(vol1), 5, 0), VolumeInfo(1, str(vol2), 5, 5)]

        reader = MultiVolumeStreamReader(vols)
        reader.close_volume(0)

        with pytest.raises(VolumeCleanError):
            reader.seek(0)
            reader.read(3)


# ===========================================================================
# 3. ChunkedSparseExtractor Unit Tests
# ===========================================================================


class TestChunkedSparseExtractor:
    """Unit tests for forward chunked streaming and 64KB-aligned sparse hole-punching."""

    def test_cluster_aligned_chunk_size_properties(self) -> None:
        """Verifies cluster_aligned_chunk_size is always a non-zero multiple of 64KB."""
        extractor = ChunkedSparseExtractor(chunk_size=100000)
        assert extractor.cluster_aligned_chunk_size % 65536 == 0
        assert extractor.cluster_aligned_chunk_size >= 65536

        extractor_small = ChunkedSparseExtractor(chunk_size=1024)
        assert extractor_small.cluster_aligned_chunk_size == 65536
        assert extractor_small.buffer_capacity <= 2 * 65536

    def test_extract_stream_chunked_stored(self, tmp_path: Path) -> None:
        """Verifies chunked extraction of STORED (uncompressed) stream."""
        arch_file = tmp_path / "test_arch.bin"
        dest_file = tmp_path / "dest.bin"

        payload = b"CHUNKED_STORED_PAYLOAD_TEST_" * 5000  # ~145 KB
        prefix = b"ARCHIVE_HEADER_PREFIX_PADDING" * 100  # ~3 KB
        arch_file.write_bytes(prefix + payload)

        mock_puncher = MagicMock(spec=SparsePuncher)
        mock_puncher.is_sparse_supported.return_value = False

        extractor = ChunkedSparseExtractor(archive_path=arch_file, puncher=mock_puncher, chunk_size=65536)
        written = extractor.extract_stream_chunked(
            member_offset=len(prefix),
            compressed_size=len(payload),
            dest_path=dest_file,
            expected_crc32=zlib.crc32(payload) & 0xFFFFFFFF,
            compression_method=0,
            uncompressed_size=len(payload),
        )

        assert written == len(payload)
        assert dest_file.read_bytes() == payload

    def test_extract_stream_chunked_deflated(self, tmp_path: Path) -> None:
        """Verifies chunked extraction and decompression of DEFLATE stream."""
        raw_data = b"REPEATING_DEFLATE_TEST_DATA_BLOCK_" * 10000  # ~340 KB
        compressor = zlib.compressobj(level=6, wbits=-15)
        deflated_stream = compressor.compress(raw_data) + compressor.flush()

        arch_file = tmp_path / "deflated_arch.bin"
        dest_file = tmp_path / "decompressed.bin"
        prefix = b"PREFIX_METADATA_" * 50
        arch_file.write_bytes(prefix + deflated_stream)

        mock_puncher = MagicMock(spec=SparsePuncher)
        mock_puncher.is_sparse_supported.return_value = False

        extractor = ChunkedSparseExtractor(archive_path=arch_file, puncher=mock_puncher, chunk_size=65536)
        written = extractor.extract_stream_chunked(
            member_offset=len(prefix),
            compressed_size=len(deflated_stream),
            dest_path=dest_file,
            expected_crc32=zlib.crc32(raw_data) & 0xFFFFFFFF,
            compression_method=8,
            uncompressed_size=len(raw_data),
        )

        assert written == len(raw_data)
        assert dest_file.read_bytes() == raw_data

    def test_lockstep_hole_punching_mocked(self, tmp_path: Path) -> None:
        """Verifies punch_hole is called with monotonically advancing 64KB-aligned ranges."""
        payload = b"X" * (300 * 1024)  # 300 KB
        arch_file = tmp_path / "sparse_test.bin"
        dest_file = tmp_path / "out_sparse.bin"
        arch_file.write_bytes(payload)

        mock_puncher = MagicMock(spec=SparsePuncher)
        mock_puncher.is_sparse_supported.return_value = True

        punched_ranges = []

        def fake_punch(handle, offset, length, cluster_size=65536):
            punched_ranges.append((offset, length))
            return length

        mock_puncher.punch_hole.side_effect = fake_punch

        extractor = ChunkedSparseExtractor(archive_path=arch_file, puncher=mock_puncher, chunk_size=65536)
        extractor.extract_stream_chunked(
            member_offset=0,
            compressed_size=len(payload),
            dest_path=dest_file,
            compression_method=0,
        )

        assert len(punched_ranges) >= 1
        for off, length in punched_ranges:
            assert off % 65536 == 0
            assert length % 65536 == 0

    def test_headroom_monitoring_abort_on_low_space(self, tmp_path: Path) -> None:
        """Verifies that LowHeadroomError aborts decompression when free space cushion is breached."""
        arch_file = tmp_path / "headroom_arch.bin"
        dest_file = tmp_path / "dest_fail.bin"
        arch_file.write_bytes(b"Z" * (200 * 1024))

        mock_monitor = MagicMock(spec=HeadroomMonitor)
        mock_monitor.ensure_headroom.side_effect = LowHeadroomError("Insufficient disk headroom")

        extractor = ChunkedSparseExtractor(
            archive_path=arch_file,
            headroom_monitor=mock_monitor,
            chunk_size=65536,
        )

        with pytest.raises(LowHeadroomError, match="Insufficient disk headroom"):
            extractor.extract_stream_chunked(
                member_offset=0,
                compressed_size=200 * 1024,
                dest_path=dest_file,
                compression_method=0,
            )

    def test_fallback_when_sparse_unsupported(self, tmp_path: Path) -> None:
        """Verifies allow_fallback=True extracts successfully when sparse is unsupported, while allow_fallback=False raises SparseError."""
        arch_file = tmp_path / "arch_fallback.bin"
        dest_file = tmp_path / "dest_fallback.bin"
        data = b"FALLBACK_DATA_CHUNK_" * 500
        arch_file.write_bytes(data)

        mock_puncher = MagicMock(spec=SparsePuncher)
        mock_puncher.is_sparse_supported.return_value = False

        # allow_fallback = True: succeeds
        extractor_allow = ChunkedSparseExtractor(
            archive_path=arch_file,
            puncher=mock_puncher,
            allow_fallback=True,
        )
        written = extractor_allow.extract_stream_chunked(
            member_offset=0,
            compressed_size=len(data),
            dest_path=dest_file,
            compression_method=0,
        )
        assert written == len(data)
        assert dest_file.read_bytes() == data

        # allow_fallback = False: raises SparseError
        extractor_strict = ChunkedSparseExtractor(
            archive_path=arch_file,
            puncher=mock_puncher,
            allow_fallback=False,
        )
        with pytest.raises(SparseError, match="does not support sparse files"):
            extractor_strict.extract_stream_chunked(
                member_offset=0,
                compressed_size=len(data),
                dest_path=tmp_path / "strict_fail.bin",
                compression_method=0,
            )

    @pytest.mark.skipif(sys.platform != "win32", reason="Requires Windows NTFS")
    def test_real_ntfs_sparse_extraction(self, tmp_path: Path) -> None:
        """Performs real sparse hole punching during extraction on a Windows NTFS volume."""
        puncher = SparsePuncher()
        if not puncher.is_sparse_supported(tmp_path):
            pytest.skip("Volume does not support sparse files.")

        zip_file = tmp_path / "real_sparse.zip"
        out_dir = tmp_path / "out_real_sparse"
        virtual_size = 4 * 1024 * 1024  # 4 MB
        create_sparse_payload_zip(zip_file, target_virtual_size_bytes=virtual_size, filename="sparse_payload.bin")

        extractor = ChunkedSparseExtractor(chunk_size=1048576)
        extractor.extract(str(zip_file), str(out_dir))

        result_file = out_dir / "sparse_payload.bin"
        assert result_file.exists()
        assert result_file.stat().st_size == virtual_size


class TestRarSupport:
    """Unit tests for RAR format detection and sparse parsing."""

    def test_is_rar_file_detection(self, tmp_path: Path) -> None:
        from zeroextract.formats.rar_sparse import is_rar_file

        fake_rar5 = tmp_path / "fake5.rar"
        fake_rar5.write_bytes(b"Rar!\x1a\x07\x01\x00\x00\x00extra_payload")
        assert is_rar_file(fake_rar5) is True

        fake_rar4 = tmp_path / "fake4.rar"
        fake_rar4.write_bytes(b"Rar!\x1a\x07\x00\x00\x00\x00extra_payload")
        assert is_rar_file(fake_rar4) is True

        fake_zip = tmp_path / "fake.zip"
        fake_zip.write_bytes(b"PK\x03\x04\x00\x00\x00\x00")
        assert is_rar_file(fake_zip) is False

        non_existent = tmp_path / "missing.rar"
        assert is_rar_file(non_existent) is False

    def test_rar_preflight_shield_integration(self, tmp_path: Path) -> None:
        from zeroextract.safety.preverify import PreflightShield

        shield = PreflightShield()
        # Invalid tiny RAR
        corrupt_rar = tmp_path / "corrupt.rar"
        corrupt_rar.write_bytes(b"Rar!\x1a\x07\x01\x00\xff\xff")
        valid, errors = shield.verify_archive(corrupt_rar)
        assert valid is False or len(errors) > 0
