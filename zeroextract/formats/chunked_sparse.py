"""Forward streaming extractor with lockstep 64KB-aligned NTFS sparse hole punching.

Enables extracting massive archive members (larger than available disk headroom)
by deallocating consumed compressed archive ranges in real-time via SparsePuncher.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import struct
import sys
from typing import Any, Callable, Optional
import zipfile
import zlib

from zeroextract.formats.zip_reverse import PathTraversalError, _sanitize_path
from zeroextract.fs.headroom import HeadroomMonitor, LowHeadroomError
from zeroextract.fs.sparse import SparseError, SparsePuncher

logger = logging.getLogger(__name__)


class ChunkedSparseExtractor:
    """Forward streaming extractor with lockstep 64KB-aligned NTFS sparse hole punching."""

    DEFAULT_CHUNK_SIZE: int = 1024 * 1024  # 1 MB read chunk
    CLUSTER_SIZE: int = 65536  # 64 KB NTFS sparse boundary

    def __init__(
        self,
        archive_path: str | os.PathLike | None = None,
        puncher: SparsePuncher | None = None,
        headroom_monitor: HeadroomMonitor | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        min_headroom: int = HeadroomMonitor.DEFAULT_MIN_CUSHION,
        allow_fallback: bool = True,
        on_chunk_processed: Optional[Callable[[int], None]] = None,
    ) -> None:
        self.archive_path = os.fspath(archive_path) if archive_path is not None else None
        self.puncher = puncher or SparsePuncher()
        self.headroom = headroom_monitor or HeadroomMonitor()
        self.chunk_size = max(self.CLUSTER_SIZE, chunk_size)
        self.min_headroom = min_headroom
        self.allow_fallback = allow_fallback
        self.on_chunk_processed = on_chunk_processed

    @property
    def cluster_aligned_chunk_size(self) -> int:
        """Returns chunk size aligned upwards to 64KB cluster boundary."""
        return ((self.chunk_size + self.CLUSTER_SIZE - 1) // self.CLUSTER_SIZE) * self.CLUSTER_SIZE

    @property
    def buffer_capacity(self) -> int:
        """Returns the internal buffer capacity."""
        return self.chunk_size

    def extract_stream_chunked(
        self,
        member_offset: int,
        compressed_size: int,
        dest_path: str | os.PathLike,
        expected_crc32: int | None = None,
        compression_method: int = 8,
        uncompressed_size: int | None = None,
        archive_path: str | os.PathLike | None = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> int:
        """Decompresses a stream in chunks, writing to dest and punching holes in archive in 64KB-aligned blocks.

        Args:
            member_offset: Byte offset where compressed data begins in archive.
            compressed_size: Byte length of compressed stream.
            dest_path: Output file path.
            expected_crc32: Optional CRC32 integer for verification.
            compression_method: 0 for STORE, 8 for DEFLATE.
            uncompressed_size: Optional expected uncompressed byte size.
            archive_path: Override archive path (or uses self.archive_path).
            on_progress: Optional callback receiving (bytes_extracted, total_expected).

        Returns:
            Total uncompressed bytes written to dest_path.

        Raises:
            LowHeadroomError: If disk free space breaches safety cushion.
            SparseError: If sparse punching fails and fallback is disabled.
            ValueError: On CRC32 or size mismatch.
            EOFError: On truncated stream.
        """
        arch_path = archive_path or self.archive_path
        if arch_path is None:
            raise ValueError("archive_path must be specified in __init__ or extract_stream_chunked")

        dest = Path(dest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        sparse_supported = self.puncher.is_sparse_supported(arch_path)
        if not sparse_supported and not self.allow_fallback:
            raise SparseError(f"Filesystem for '{arch_path}' does not support sparse files.")

        # Initialize decompressor
        if compression_method == 0:
            decompressor = None
        elif compression_method == 8:
            decompressor = zlib.decompressobj(-15)
        else:
            raise ValueError(f"Unsupported compression method: {compression_method}")

        total_uncompressed = 0
        running_crc32 = 0
        read_chunk_size = self.cluster_aligned_chunk_size
        remaining_compressed = compressed_size
        last_punched_end = member_offset

        tmp_target = dest.with_name(dest.name + ".unpack_part")

        try:
            with open(arch_path, "r+b") as arch_file, open(tmp_target, "wb") as dest_file:
                if sparse_supported:
                    try:
                        self.puncher.mark_as_sparse(arch_file)
                    except SparseError as exc:
                        if not self.allow_fallback:
                            raise
                        logger.warning("Failed to mark archive as sparse: %s; falling back to non-sparse", exc)
                        sparse_supported = False

                arch_file.seek(member_offset)

                while remaining_compressed > 0:
                    to_read = min(read_chunk_size, remaining_compressed)
                    chunk = arch_file.read(to_read)
                    if len(chunk) < to_read:
                        raise EOFError(
                            f"Unexpected EOF reading archive at offset {arch_file.tell()}; "
                            f"read {len(chunk)} bytes, expected {to_read}"
                        )

                    remaining_compressed -= len(chunk)

                    # Decompress
                    if decompressor is None:
                        unpacked = chunk
                    else:
                        try:
                            unpacked = decompressor.decompress(chunk)
                        except zlib.error as exc:
                            raise ValueError(
                                f"Corrupt DEFLATE compressed stream for '{dest}': {exc}"
                            ) from exc

                    if unpacked:
                        self.headroom.ensure_headroom(
                            tmp_target,
                            required_bytes=len(unpacked),
                            min_headroom_cushion=self.min_headroom,
                        )
                        dest_file.write(unpacked)
                        dest_file.flush()
                        running_crc32 = zlib.crc32(unpacked, running_crc32) & 0xFFFFFFFF
                        total_uncompressed += len(unpacked)

                    # Lockstep hole punch
                    current_consumed_offset = arch_file.tell()
                    if sparse_supported:
                        aligned_start = ((last_punched_end + self.CLUSTER_SIZE - 1) // self.CLUSTER_SIZE) * self.CLUSTER_SIZE
                        aligned_end = (current_consumed_offset // self.CLUSTER_SIZE) * self.CLUSTER_SIZE
                        if aligned_end > aligned_start:
                            punch_len = aligned_end - aligned_start
                            self.puncher.punch_hole(arch_file, aligned_start, punch_len, cluster_size=self.CLUSTER_SIZE)
                            last_punched_end = aligned_end

                    if self.on_chunk_processed is not None:
                        free_bytes = self.headroom.get_free_space(tmp_target)
                        self.on_chunk_processed(free_bytes)

                    if on_progress is not None:
                        on_progress(total_uncompressed, uncompressed_size or total_uncompressed)

                # Flush decompressor tail
                if decompressor is not None:
                    try:
                        trailing = decompressor.flush()
                    except zlib.error as exc:
                        raise ValueError(
                            f"Corrupt DEFLATE compressed stream for '{dest}': {exc}"
                        ) from exc
                    if trailing:
                        self.headroom.ensure_headroom(
                            tmp_target,
                            required_bytes=len(trailing),
                            min_headroom_cushion=self.min_headroom,
                        )
                        dest_file.write(trailing)
                        dest_file.flush()
                        running_crc32 = zlib.crc32(trailing, running_crc32) & 0xFFFFFFFF
                        total_uncompressed += len(trailing)

                # Final hole punch for any remaining full clusters
                if sparse_supported:
                    aligned_start = ((last_punched_end + self.CLUSTER_SIZE - 1) // self.CLUSTER_SIZE) * self.CLUSTER_SIZE
                    aligned_end = ((member_offset + compressed_size) // self.CLUSTER_SIZE) * self.CLUSTER_SIZE
                    if aligned_end > aligned_start:
                        punch_len = aligned_end - aligned_start
                        self.puncher.punch_hole(arch_file, aligned_start, punch_len, cluster_size=self.CLUSTER_SIZE)
                        last_punched_end = aligned_end

                dest_file.flush()
                os.fsync(dest_file.fileno())

            # Integrity checks
            if expected_crc32 is not None and running_crc32 != expected_crc32:
                raise ValueError(
                    f"CRC32 mismatch for '{dest}': expected {expected_crc32:#010x}, got {running_crc32:#010x}"
                )
            if uncompressed_size is not None and total_uncompressed != uncompressed_size:
                raise ValueError(
                    f"Uncompressed size mismatch for '{dest}': expected {uncompressed_size}, got {total_uncompressed}"
                )

            os.replace(tmp_target, dest)

        except Exception:
            if tmp_target.exists():
                try:
                    tmp_target.unlink()
                except OSError:
                    pass
            raise

        return total_uncompressed

    def extract(
        self,
        archive_path: str | os.PathLike | None = None,
        output_dir: str | os.PathLike | None = None,
    ) -> list[str]:
        """Extracts all entries of an archive using chunked forward extraction."""
        arch_path = archive_path or self.archive_path
        if arch_path is None or output_dir is None:
            raise ValueError("archive_path and output_dir must be provided")

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        extracted: list[str] = []

        with zipfile.ZipFile(arch_path, "r") as zf:
            infolist = zf.infolist()

        for info in infolist:
            target_file = _sanitize_path(info.filename, out_path)
            if info.is_dir():
                target_file.mkdir(parents=True, exist_ok=True)
                continue

            with open(arch_path, "rb") as f:
                f.seek(info.header_offset)
                sig = f.read(4)
                if sig != b"PK\x03\x04":
                    raise ValueError(f"Corrupt local header at offset {info.header_offset}")
                f.seek(info.header_offset + 26)
                name_len, extra_len = struct.unpack("<HH", f.read(4))
                data_offset = info.header_offset + 30 + name_len + extra_len

            self.extract_stream_chunked(
                member_offset=data_offset,
                compressed_size=info.compress_size,
                dest_path=target_file,
                expected_crc32=info.CRC,
                compression_method=info.compress_type,
                uncompressed_size=info.file_size,
                archive_path=arch_path,
            )
            extracted.append(str(target_file))

        return extracted
