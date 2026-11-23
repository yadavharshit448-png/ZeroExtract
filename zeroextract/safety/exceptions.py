"""Safety exceptions and CorruptionGuard for ZeroExtract."""

from __future__ import annotations

import io
import os
from pathlib import Path
import struct
import zlib
import zipfile


class SafetyError(Exception):
    """Base exception for all safety-related failures."""


class ChecksumError(SafetyError):
    """Raised when CRC32 or hash verification fails."""


class CorruptionError(SafetyError):
    """Raised when an archive or stream is detected to be corrupt or malformed."""


class PathTraversalError(SafetyError):
    """Raised when an archive member attempts directory traversal (Zip Slip)."""


class CorruptionGuard:
    """Security and corruption safeguard layer."""

    def check_path_safety(self, member_path: str, target_dir: str | os.PathLike) -> Path:
        """Validates that member_path does not escape target_dir (Zip Slip prevention).

        Args:
            member_path: Relative path declared inside archive.
            target_dir: Destination base directory.

        Returns:
            Resolved absolute Path safely within target_dir.

        Raises:
            PathTraversalError: If the resolved path lies outside target_dir.
        """
        base = Path(target_dir).resolve()
        # Strip drive letters or leading slashes
        clean_rel = os.path.normpath(member_path)
        if clean_rel.startswith(("\\", "/")) or (len(clean_rel) > 1 and clean_rel[1] == ":"):
            clean_rel = clean_rel.lstrip("\\/").split(":", 1)[-1].lstrip("\\/")

        # Check for directory traversal components
        parts = Path(clean_rel).parts
        if ".." in parts:
            raise PathTraversalError(f"Directory traversal detected in member path: {member_path}")

        resolved = (base / clean_rel).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            raise PathTraversalError(f"Path escapes destination directory: {member_path}")

        return resolved

    def validate_and_extract(self, archive_path: str | os.PathLike, output_dir: str | os.PathLike) -> None:
        """Validates archive integrity and extracts contents safely.

        Args:
            archive_path: Path to archive file.
            output_dir: Destination directory.

        Raises:
            CorruptionError: If archive has missing central directory, corrupt compression,
                             size mismatch, or zero valid members.
            PathTraversalError: If archive contains unsafe path traversal members.
        """
        arch_p = Path(archive_path)
        out_p = Path(output_dir)

        if not arch_p.exists():
            raise CorruptionError(f"Archive not found: {archive_path}")

        arch_size = arch_p.stat().st_size
        if arch_size < 22:
            raise CorruptionError("Archive too small to contain valid headers or Central Directory")

        # Check for valid zip magic or EOCD
        try:
            with open(arch_p, "rb") as f:
                header = f.read(4)
                if header not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
                    raise CorruptionError("Missing valid ZIP local header signature")

                # Scan backwards for EOCD signature PK\x05\x06
                f.seek(max(0, arch_size - 65557))
                tail = f.read()
                eocd_pos = tail.rfind(b"PK\x05\x06")
                if eocd_pos == -1:
                    raise CorruptionError("Missing ZIP End of Central Directory (EOCD)")
        except CorruptionError:
            raise
        except Exception as e:
            raise CorruptionError(f"Failed to read archive: {e}") from e

        try:
            with zipfile.ZipFile(arch_p, "r") as zf:
                infolist = zf.infolist()
                if not infolist:
                    # Empty zip file with valid EOCD
                    return

                for info in infolist:
                    self.check_path_safety(info.filename, out_p)

                    # Verify decompressed stream and size
                    try:
                        with zf.open(info) as src:
                            decompressed = src.read()
                    except Exception as e:
                        raise CorruptionError(f"Corrupted compressed stream in member '{info.filename}': {e}") from e

                    if len(decompressed) != info.file_size:
                        raise CorruptionError(
                            f"Size mismatch in '{info.filename}': declared {info.file_size}, decompressed {len(decompressed)}"
                        )

                    computed_crc = zlib.crc32(decompressed) & 0xFFFFFFFF
                    if computed_crc != info.CRC:
                        raise ChecksumError(
                            f"CRC32 mismatch in '{info.filename}': expected {info.CRC:08x}, got {computed_crc:08x}"
                        )
        except (CorruptionError, ChecksumError, PathTraversalError):
            raise
        except Exception as e:
            raise CorruptionError(f"Archive validation failure: {e}") from e

        # Now extract using reverse extractor
        from zeroextract.formats.zip_reverse import ZipReverseExtractor
        extractor = ZipReverseExtractor(str(arch_p))
        extractor.extract(str(out_p))


__all__ = [
    "SafetyError",
    "ChecksumError",
    "CorruptionError",
    "PathTraversalError",
    "CorruptionGuard",
]
