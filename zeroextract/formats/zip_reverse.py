"""ZIP and ZIP64 reverse extractor with lockstep tail truncation.

Extracts archive entries strictly in descending order of physical header offsets
(tail to head), freeing disk space incrementally via ReverseTruncator.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
import io
import logging
import os
from pathlib import Path
import struct
import sys
from typing import Any, BinaryIO, Callable, Optional
import zlib

from zeroextract.fs.sparse import SparseError, SparsePuncher
from zeroextract.fs.truncator import ReverseTruncator, TruncateError

logger = logging.getLogger(__name__)

# ZIP Signatures
SIG_EOCD = b"PK\x05\x06"  # 0x06054b50
SIG_ZIP64_LOCATOR = b"PK\x06\x07"  # 0x07064b50
SIG_ZIP64_EOCD = b"PK\x06\x06"  # 0x06064b50
SIG_CDFH = b"PK\x01\x02"  # 0x02014b50
SIG_LFH = b"PK\x03\x04"  # 0x04034b50

# Binary Struct Formats (little-endian)
STRUCT_EOCD = "<4s4H2IH"  # 22 bytes
STRUCT_ZIP64_LOCATOR = "<4sIQI"  # 20 bytes
STRUCT_ZIP64_EOCD = "<4sQ2H2I4Q"  # 56 bytes
STRUCT_CDFH = "<4s6H3I5H2I"  # 46 bytes
STRUCT_LFH = "<4s5H3I2H"  # 30 bytes


class ZipFormatError(Exception):
    """Base exception for ZIP parsing and reverse extraction errors."""


class BadZipSignatureError(ZipFormatError):
    """Raised when EOCD, LFH, or CDFH signatures are missing or invalid."""


class CorruptArchiveError(ZipFormatError, ValueError):
    """Raised when archive data is truncated or header structures are corrupted."""


class ChecksumError(ZipFormatError, ValueError):
    """Raised when decompressed CRC32 does not match Central Directory CRC32."""


class UnsupportedCompressionError(ZipFormatError):
    """Raised when an entry uses a compression method other than 0 (STORE) or 8 (DEFLATE)."""


class PathTraversalError(ZipFormatError):
    """Raised when an entry attempts directory traversal outside output_dir."""


@dataclass(slots=True)
class ZipEntry:
    """Metadata representing a single member within a ZIP Central Directory."""

    filename: str
    compression_method: int
    compressed_size: int
    uncompressed_size: int
    crc32: int
    local_header_offset: int
    is_dir: bool = False
    flag_bits: int = 0
    mod_time: int = 0
    mod_date: int = 0
    external_attr: int = 0


def _dos_to_timestamp(dos_date: int, dos_time: int) -> float:
    """Converts MS-DOS date and time integers to a Unix timestamp."""
    year = ((dos_date >> 9) & 0x7F) + 1980
    month = max(1, min(12, (dos_date >> 5) & 0x0F))
    day = max(1, min(31, dos_date & 0x1F))
    hour = min(23, (dos_time >> 11) & 0x1F)
    minute = min(59, (dos_time >> 5) & 0x3F)
    second = min(59, (dos_time & 0x1F) * 2)
    try:
        dt = datetime.datetime(year, month, day, hour, minute, second)
        return dt.timestamp()
    except Exception:
        return 0.0


def _sanitize_path(filename: str, output_dir: Path) -> Path:
    """Sanitizes filename against Zip Slip directory traversal vulnerabilities."""
    cleaned = filename.replace("\\", "/").lstrip("/")
    parts = [p for p in cleaned.split("/") if p and p != "."]
    if any(p == ".." or ":" in p for p in parts):
        raise PathTraversalError(f"Directory traversal detected in ZIP entry: '{filename}'")

    target = output_dir
    for part in parts:
        target = target / part

    target_resolved = target.resolve()
    out_resolved = output_dir.resolve()
    try:
        target_resolved.relative_to(out_resolved)
    except ValueError:
        raise PathTraversalError(f"Target path '{target_resolved}' escapes output root '{out_resolved}'")

    return target


def _read_exact(f: BinaryIO, length: int) -> bytes:
    """Reads up to length bytes cleanly across buffered or unbuffered FileIO streams."""
    buf = f.read(length)
    if len(buf) == length or len(buf) == 0:
        return buf
    parts = [buf]
    rem = length - len(buf)
    while rem > 0:
        more = f.read(rem)
        if not more:
            break
        parts.append(more)
        rem -= len(more)
    return b"".join(parts)


class ZipReverseExtractor:
    """Central Directory caching and tail-to-head reverse extractor with lockstep truncation."""

    DEFAULT_CHUNK_SIZE: int = 1024 * 1024  # 1 MB
    SPARSE_CLUSTER_SIZE: int = 65536  # 64 KB NTFS sparse cluster boundary
    DEFAULT_SPARSE_THRESHOLD: int = 2 * 1024 * 1024  # 2 MB minimum compressed stream for intra-entry punching

    def __init__(
        self,
        archive_path: str | os.PathLike | None = None,
        reclaimer: Any = None,
        truncator: ReverseTruncator | None = None,
        puncher: SparsePuncher | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        entries: list[ZipEntry] | None = None,
        enable_intra_entry_sparse: bool = True,
        sparse_punch_threshold: int = DEFAULT_SPARSE_THRESHOLD,
    ) -> None:
        self.archive_path = os.fspath(archive_path) if archive_path is not None else None
        if truncator is not None:
            self.truncator = truncator
        elif reclaimer is not None and hasattr(reclaimer, "truncator"):
            self.truncator = reclaimer.truncator
        else:
            self.truncator = ReverseTruncator()
        if puncher is not None:
            self.puncher = puncher
        elif reclaimer is not None and hasattr(reclaimer, "sparse"):
            self.puncher = reclaimer.sparse
        else:
            self.puncher = SparsePuncher()
        self.chunk_size = max(65536, chunk_size)
        self._entries: list[ZipEntry] | None = entries
        self.enable_intra_entry_sparse = enable_intra_entry_sparse
        self.sparse_punch_threshold = sparse_punch_threshold

    def scan_central_directory(self, archive_path: str | os.PathLike | None = None) -> list[ZipEntry]:
        """Parses EOCD / Zip64 EOCD and returns entries sorted descending by local_header_offset."""
        path = archive_path or self.archive_path
        if path is None:
            raise ValueError("archive_path must be specified")

        path = os.fspath(path)
        file_size = os.path.getsize(path)
        if file_size < 22:
            raise CorruptArchiveError(f"File too small to be a valid ZIP archive ({file_size} bytes)")

        with open(path, "rb") as f:
            eocd_pos, eocd_tuple = self._find_eocd(f, file_size)
            (
                _,
                disk_num,
                cd_disk_num,
                disk_entries,
                total_entries,
                cd_size,
                cd_offset,
                comment_len,
            ) = eocd_tuple

            is_zip64, zip64_tuple = self._check_zip64(f, eocd_pos)
            if is_zip64 and zip64_tuple is not None:
                (
                    _,
                    z64_rec_size,
                    z64_ver_made,
                    z64_ver_need,
                    z64_disk_num,
                    z64_cd_disk,
                    z64_disk_entries,
                    z64_total_entries,
                    z64_cd_size,
                    z64_cd_offset,
                ) = zip64_tuple
                total_entries = z64_total_entries
                cd_size = z64_cd_size
                cd_offset = z64_cd_offset

            # SFX stub offset detection
            # Standard ZIP layout: Central Directory starts at eocd_pos - cd_size
            # (or before zip64 locator/eocd if zip64)
            if is_zip64:
                expected_cd_end = eocd_pos - 20 - (56 + (z64_rec_size - 44))
            else:
                expected_cd_end = eocd_pos

            sfx_offset = expected_cd_end - (cd_offset + cd_size)
            if sfx_offset < 0:
                sfx_offset = 0

            actual_cd_offset = cd_offset + sfx_offset
            self._entries = self._parse_central_directory(f, actual_cd_offset, cd_size, total_entries, sfx_offset)

        # Sort entries strictly descending by physical local_header_offset (tail to head)
        self._entries.sort(key=lambda e: e.local_header_offset, reverse=True)
        return self._entries

    def _find_eocd(self, f: BinaryIO, file_size: int) -> tuple[int, tuple]:
        """Scans backwards to locate and unpack the End of Central Directory record."""
        read_len = min(file_size, 65535 + 22)
        f.seek(file_size - read_len)
        buffer = f.read(read_len)

        # Scan backwards for EOCD signature PK\x05\x06
        candidate_pos = -1
        idx = len(buffer) - 22
        while idx >= 0:
            found = buffer.rfind(SIG_EOCD, 0, idx + 4)
            if found == -1:
                break
            if found + 22 <= len(buffer):
                comment_len = struct.unpack_from("<H", buffer, found + 20)[0]
                if found + 22 + comment_len == len(buffer):
                    # Exact comment length match
                    candidate_pos = found
                    break
                if candidate_pos == -1 and found + 22 + comment_len <= len(buffer):
                    candidate_pos = found
            idx = found - 1

        if candidate_pos == -1:
            raise CorruptArchiveError("End of Central Directory (EOCD) signature not found")

        abs_eocd_pos = file_size - read_len + candidate_pos
        eocd_tuple = struct.unpack_from(STRUCT_EOCD, buffer, candidate_pos)
        return abs_eocd_pos, eocd_tuple

    def _check_zip64(self, f: BinaryIO, eocd_pos: int) -> tuple[bool, Optional[tuple]]:
        """Checks for ZIP64 EOCD Locator and Record preceding the standard EOCD."""
        if eocd_pos < 20:
            return False, None

        f.seek(eocd_pos - 20)
        loc_buf = f.read(20)
        if len(loc_buf) < 20 or not loc_buf.startswith(SIG_ZIP64_LOCATOR):
            return False, None

        _, disk_with_z64_eocd, z64_eocd_offset, total_disks = struct.unpack(STRUCT_ZIP64_LOCATOR, loc_buf)
        f.seek(z64_eocd_offset)
        rec_hdr = f.read(56)
        if len(rec_hdr) < 56 or not rec_hdr.startswith(SIG_ZIP64_EOCD):
            return False, None

        z64_tuple = struct.unpack(STRUCT_ZIP64_EOCD, rec_hdr)
        return True, z64_tuple

    def _parse_central_directory(
        self,
        f: BinaryIO,
        cd_offset: int,
        cd_size: int,
        total_entries: int,
        sfx_offset: int,
    ) -> list[ZipEntry]:
        """Parses all CDFH records and resolves ZIP64 extra fields."""
        f.seek(cd_offset)
        cd_bytes = f.read(cd_size)
        ptr = 0
        entries: list[ZipEntry] = []

        while ptr < len(cd_bytes) and len(entries) < total_entries:
            if ptr + 46 > len(cd_bytes):
                break
            if cd_bytes[ptr : ptr + 4] != SIG_CDFH:
                break

            cdfh = struct.unpack_from(STRUCT_CDFH, cd_bytes, ptr)
            (
                _,
                ver_made,
                ver_need,
                flag_bits,
                method,
                mod_time,
                mod_date,
                crc32,
                comp_size,
                uncomp_size,
                fn_len,
                extra_len,
                comment_len,
                disk_start,
                int_attr,
                ext_attr,
                local_header_offset,
            ) = cdfh

            ptr += 46
            fn_bytes = cd_bytes[ptr : ptr + fn_len]
            ptr += fn_len

            # Filename decoding: UTF-8 if bit 11 set or valid UTF-8
            if flag_bits & 0x0800:
                filename = fn_bytes.decode("utf-8", errors="replace")
            else:
                try:
                    filename = fn_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    filename = fn_bytes.decode("cp437", errors="replace")

            extra_bytes = cd_bytes[ptr : ptr + extra_len]
            ptr += extra_len
            ptr += comment_len  # Skip comment bytes

            # Parse ZIP64 extra field (Header ID 0x0001)
            uncomp_size, comp_size, local_header_offset = self._parse_zip64_extra(
                extra_bytes, uncomp_size, comp_size, local_header_offset
            )

            # Apply SFX offset adjustment to local_header_offset
            local_header_offset += sfx_offset

            # Directory identification: trailing slash or DOS directory attribute (0x10)
            is_dir = filename.endswith("/") or bool(ext_attr & 0x10)

            entries.append(
                ZipEntry(
                    filename=filename,
                    compression_method=method,
                    compressed_size=comp_size,
                    uncompressed_size=uncomp_size,
                    crc32=crc32,
                    local_header_offset=local_header_offset,
                    is_dir=is_dir,
                    flag_bits=flag_bits,
                    mod_time=mod_time,
                    mod_date=mod_date,
                    external_attr=ext_attr,
                )
            )

        return entries

    def _parse_zip64_extra(
        self,
        extra_bytes: bytes,
        uncomp_size: int,
        comp_size: int,
        offset: int,
    ) -> tuple[int, int, int]:
        """Resolves 64-bit sizes and offsets from ZIP64 extra field (0x0001)."""
        idx = 0
        while idx + 4 <= len(extra_bytes):
            header_id, data_len = struct.unpack_from("<HH", extra_bytes, idx)
            idx += 4
            if header_id == 0x0001:
                field_ptr = idx
                end_ptr = min(idx + data_len, len(extra_bytes))
                if uncomp_size == 0xFFFFFFFF and field_ptr + 8 <= end_ptr:
                    uncomp_size = struct.unpack_from("<Q", extra_bytes, field_ptr)[0]
                    field_ptr += 8
                if comp_size == 0xFFFFFFFF and field_ptr + 8 <= end_ptr:
                    comp_size = struct.unpack_from("<Q", extra_bytes, field_ptr)[0]
                    field_ptr += 8
                if offset == 0xFFFFFFFF and field_ptr + 8 <= end_ptr:
                    offset = struct.unpack_from("<Q", extra_bytes, field_ptr)[0]
                    field_ptr += 8
                break
            idx += data_len

        return uncomp_size, comp_size, offset

    def extract_entry(
        self,
        entry: ZipEntry,
        output_dir: str | os.PathLike,
        archive_file: BinaryIO | None = None,
        enable_sparse: bool = False,
        on_bytes_progress: Optional[Callable[[int, str], None]] = None,
    ) -> str:
        """Extracts a single entry, validates CRC32, and atomically stages the file."""
        out_root = Path(output_dir).resolve()
        out_root.mkdir(parents=True, exist_ok=True)
        target = _sanitize_path(entry.filename, out_root)

        if entry.is_dir:
            target.mkdir(parents=True, exist_ok=True)
            return str(target)

        if entry.compression_method not in (0, 8):
            raise UnsupportedCompressionError(
                f"Unsupported compression method {entry.compression_method} for entry '{entry.filename}'"
            )

        target.parent.mkdir(parents=True, exist_ok=True)

        close_after = False
        if archive_file is None:
            if self.archive_path is None:
                raise ValueError("archive_path must be specified")
            f = open(self.archive_path, "rb")
            close_after = True
        else:
            f = archive_file

        temp_target = target.with_name(target.name + ".unpack_part")
        try:
            f.seek(entry.local_header_offset)
            lfh_buf = _read_exact(f, 30)
            if len(lfh_buf) < 30 or not lfh_buf.startswith(SIG_LFH):
                raise BadZipSignatureError(
                    f"Invalid Local File Header at offset {entry.local_header_offset} for '{entry.filename}'"
                )

            lfh = struct.unpack(STRUCT_LFH, lfh_buf)
            lfh_fn_len = lfh[9]
            lfh_extra_len = lfh[10]
            data_offset = entry.local_header_offset + 30 + lfh_fn_len + lfh_extra_len

            f.seek(data_offset)

            # Decompressor setup
            if entry.compression_method == 0:
                decompressor = None
            else:
                # Raw DEFLATE without zlib wrapper
                decompressor = zlib.decompressobj(-15)

            running_crc = 0
            bytes_written = 0
            remaining_comp = entry.compressed_size
            stream_pos = data_offset

            cluster_size = self.SPARSE_CLUSTER_SIZE
            last_punched_end = ((data_offset + cluster_size - 1) // cluster_size) * cluster_size
            punch_batch = ((max(self.chunk_size, 2 * 1024 * 1024) + cluster_size - 1) // cluster_size) * cluster_size
            sparse_active = enable_sparse and entry.compressed_size >= cluster_size
            if sparse_active:
                try:
                    self.puncher.mark_as_sparse(f)
                except (SparseError, OSError) as exc:
                    logger.debug("Sparse mark disabled for '%s': %s", entry.filename, exc)
                    sparse_active = False

            # Windows long path handling
            target_str = str(temp_target)
            if sys.platform == "win32" and len(target_str) >= 260 and not target_str.startswith("\\\\?\\"):
                target_str = "\\\\?\\" + os.path.abspath(target_str)

            with open(target_str, "wb") as out_f:
                while remaining_comp > 0:
                    read_len = min(self.chunk_size, remaining_comp)
                    chunk = _read_exact(f, read_len)
                    if len(chunk) < read_len:
                        raise CorruptArchiveError(
                            f"Unexpected EOF reading compressed stream for '{entry.filename}'"
                        )
                    remaining_comp -= len(chunk)
                    stream_pos += len(chunk)

                    if decompressor is None:
                        out_chunk = chunk
                    else:
                        try:
                            out_chunk = decompressor.decompress(chunk)
                        except zlib.error as exc:
                            raise CorruptArchiveError(
                                f"Corrupted DEFLATE compressed stream for '{entry.filename}': {exc}"
                            ) from exc

                    if out_chunk:
                        out_f.write(out_chunk)
                        running_crc = zlib.crc32(out_chunk, running_crc) & 0xFFFFFFFF
                        bytes_written += len(out_chunk)
                        if on_bytes_progress is not None:
                            on_bytes_progress(len(out_chunk), entry.filename)

                    if sparse_active:
                        aligned_end = (stream_pos // cluster_size) * cluster_size
                        pending_len = aligned_end - last_punched_end
                        if pending_len >= punch_batch or (remaining_comp == 0 and pending_len > 0):
                            try:
                                self.puncher.punch_hole(f, last_punched_end, pending_len, cluster_size=cluster_size)
                                last_punched_end = aligned_end
                            except (SparseError, OSError) as exc:
                                logger.warning("Intra-entry sparse punch failed for '%s': %s", entry.filename, exc)
                                sparse_active = False

                if decompressor is not None:
                    try:
                        trailing = decompressor.flush()
                    except zlib.error as exc:
                        raise CorruptArchiveError(
                            f"Corrupted DEFLATE compressed stream for '{entry.filename}': {exc}"
                        ) from exc
                    if trailing:
                        out_f.write(trailing)
                        running_crc = zlib.crc32(trailing, running_crc) & 0xFFFFFFFF
                        bytes_written += len(trailing)
                        if on_bytes_progress is not None:
                            on_bytes_progress(len(trailing), entry.filename)

                out_f.flush()
                os.fsync(out_f.fileno())

            # Verification: CRC32 check
            if entry.crc32 != 0 or bytes_written > 0:
                if running_crc != entry.crc32:
                    if temp_target.exists():
                        temp_target.unlink()
                    raise ChecksumError(
                        f"CRC32 mismatch for '{entry.filename}': expected {entry.crc32:#010x}, got {running_crc:#010x}"
                    )

            # Verification: uncompressed size check
            if bytes_written != entry.uncompressed_size:
                if temp_target.exists():
                    temp_target.unlink()
                raise CorruptArchiveError(
                    f"Size mismatch for '{entry.filename}': expected {entry.uncompressed_size}, got {bytes_written}"
                )

            # Atomic commit
            if temp_target.exists():
                os.replace(temp_target, target)

            # Preserve timestamp if available
            ts = _dos_to_timestamp(entry.mod_date, entry.mod_time)
            if ts > 0:
                try:
                    os.utime(target, (ts, ts))
                except Exception as exc:
                    logger.debug("Failed to set utime on '%s': %s", target, exc)

            return str(target)

        except Exception:
            if temp_target.exists():
                try:
                    temp_target.unlink()
                except OSError:
                    pass
            raise
        finally:
            if close_after:
                f.close()

    def extract_all(
        self,
        output_dir: str | os.PathLike,
        on_progress: Optional[Callable[[ZipEntry, int, int, int, int], None]] = None,
        on_member_extracted: Optional[Callable[[str], None]] = None,
        on_bytes_progress: Optional[Callable[[int, str], None]] = None,
    ) -> list[str]:
        """Extracts entries strictly tail-to-head and truncates archive in lockstep."""
        path = self.archive_path
        if path is None:
            raise ValueError("archive_path must be specified")

        if self._entries:
            entries = self._entries
        else:
            entries = self.scan_central_directory()
        extracted_paths: list[str] = []
        cumulative_freed = 0
        total_count = len(entries)

        sparse_supported = False
        if self.enable_intra_entry_sparse:
            try:
                sparse_supported = self.puncher.is_sparse_supported(path)
            except Exception:
                sparse_supported = False

        with open(path, "r+b", buffering=0) as arch_file:
            for idx, entry in enumerate(entries):
                target = _sanitize_path(entry.filename, Path(output_dir))
                if target.exists() and not entry.is_dir and target.stat().st_size == entry.uncompressed_size:
                    extracted_paths.append(str(target))
                    if on_bytes_progress is not None and entry.uncompressed_size > 0:
                        on_bytes_progress(entry.uncompressed_size, entry.filename)
                else:
                    use_sparse = sparse_supported and (entry.compressed_size >= self.sparse_punch_threshold)
                    dest_path = self.extract_entry(
                        entry,
                        output_dir,
                        archive_file=arch_file,
                        enable_sparse=use_sparse,
                        on_bytes_progress=on_bytes_progress,
                    )
                    extracted_paths.append(dest_path)

                if on_member_extracted is not None:
                    on_member_extracted(entry.filename)

                # Physical truncation of archive up to entry's local header offset
                # Since entries are sorted descending, this strictly shrinks the archive tail
                arch_file.seek(0, io.SEEK_END)
                curr_size = arch_file.tell()
                freed = 0
                if curr_size > entry.local_header_offset:
                    freed = self.truncator.truncate_tail(arch_file, entry.local_header_offset)
                    cumulative_freed += freed

                if on_progress is not None:
                    on_progress(entry, freed, cumulative_freed, idx + 1, total_count)

        return extracted_paths

    def extract(
        self,
        archive_path: str | os.PathLike | None = None,
        output_dir: str | os.PathLike | None = None,
        on_progress: Optional[Callable] = None,
        on_member_extracted: Optional[Callable[[str], None]] = None,
        on_bytes_progress: Optional[Callable[[int, str], None]] = None,
    ) -> list[str]:
        """Convenience method for extraction with optional archive_path override."""
        if archive_path is not None:
            self.archive_path = os.fspath(archive_path)
        if output_dir is None:
            raise ValueError("output_dir must be specified")
        return self.extract_all(
            output_dir,
            on_progress=on_progress,
            on_member_extracted=on_member_extracted,
            on_bytes_progress=on_bytes_progress,
        )
