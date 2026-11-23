"""Two-phase commit atomic writer for ZeroExtract.

Stages extraction output in .unpack_part temporary files and commits
via atomic filesystem rename (os.replace) only after CRC32 verification passes.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import stat
import sys
from typing import Iterable
import zlib

from zeroextract.safety.exceptions import ChecksumError


class AtomicWriter:
    """Crash-safe two-phase commit atomic file writer."""

    STAGING_SUFFIX = ".unpack_part"

    def get_staging_path(self, dest_file: str | os.PathLike) -> Path:
        """Returns the temporary staging path for dest_file.

        Args:
            dest_file: Target destination file path.

        Returns:
            Path object ending with .unpack_part.
        """
        return Path(str(dest_file) + self.STAGING_SUFFIX)

    def write_atomic(
        self,
        dest_path: str | os.PathLike,
        chunks: Iterable[bytes],
        expected_crc32: int | None = None,
    ) -> int:
        """Atomically writes chunks to dest_path via a temporary staging file.

        Args:
            dest_path: Target destination file path.
            chunks: Iterable of byte chunks to write.
            expected_crc32: Optional expected CRC32 checksum for verification.

        Returns:
            Total number of bytes written.

        Raises:
            ChecksumError: If expected_crc32 does not match the actual computed CRC32.
            OSError / PermissionError: If disk write or directory access fails.
        """
        dest_p = Path(dest_path)
        dest_p.parent.mkdir(parents=True, exist_ok=True)
        staging_p = self.get_staging_path(dest_p)

        # Remove any leftover staging file from a previous aborted attempt
        if staging_p.exists():
            try:
                self._clear_readonly(staging_p)
                staging_p.unlink()
            except OSError:
                pass

        total_bytes = 0
        computed_crc = 0

        try:
            with open(staging_p, "wb") as f:
                for chunk in chunks:
                    if chunk:
                        f.write(chunk)
                        total_bytes += len(chunk)
                        computed_crc = zlib.crc32(chunk, computed_crc)
                f.flush()
                os.fsync(f.fileno())

            computed_crc &= 0xFFFFFFFF

            if expected_crc32 is not None:
                exp = expected_crc32 & 0xFFFFFFFF
                if computed_crc != exp:
                    raise ChecksumError(
                        f"CRC32 mismatch for '{dest_p}': expected {exp:08x}, got {computed_crc:08x}"
                    )

            # If dest_p exists and is read-only, clear read-only flag
            if dest_p.exists():
                self._clear_readonly(dest_p)

            # Atomic commit
            os.replace(staging_p, dest_p)
            return total_bytes

        except Exception:
            # Clean up staging file on failure so no corrupted partial files remain
            if staging_p.exists():
                try:
                    self._clear_readonly(staging_p)
                    staging_p.unlink()
                except OSError:
                    pass
            raise

    def clean_stale_parts(self, target_dir: str | os.PathLike) -> int:
        """Removes any orphaned .unpack_part files remaining from a crash.

        Args:
            target_dir: Directory tree to scan.

        Returns:
            Count of stale staging files removed.
        """
        target_p = Path(target_dir)
        if not target_p.exists():
            return 0

        cleaned_count = 0
        for p in target_p.rglob("*" + self.STAGING_SUFFIX):
            try:
                self._clear_readonly(p)
                p.unlink()
                cleaned_count += 1
            except OSError:
                pass

        return cleaned_count

    def _clear_readonly(self, path: Path) -> None:
        """Removes read-only attribute if present."""
        try:
            if sys.platform == "win32":
                ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)  # FILE_ATTRIBUTE_NORMAL
            else:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass


__all__ = ["AtomicWriter"]
