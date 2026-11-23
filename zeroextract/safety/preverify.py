"""0-Byte Pre-Verification Shield for ZeroExtract.

Performs a non-destructive verification pass over the entire archive,
checking signatures, central directory integrity, and member CRCs
without allocating or writing any output files to disk.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import struct
import zipfile
import zlib


class PreflightShield:
    """Non-destructive archive integrity verification shield."""

    def __init__(self, buffer_size: int = 1024 * 1024) -> None:
        self.buffer_size = buffer_size

    def verify_archive(
        self,
        archive_path: str | os.PathLike,
        skip_preflight: bool = False,
    ) -> tuple[bool, list[str]]:
        """Verifies archive integrity without writing any data to disk.

        Args:
            archive_path: Path to target archive file.
            skip_preflight: If True, bypasses pre-verification and returns (True, []).

        Returns:
            Tuple of (is_valid: bool, errors: list[str]).
        """
        if skip_preflight:
            return True, []

        p = Path(archive_path)
        if not p.exists():
            return False, [f"Archive does not exist: {archive_path}"]

        size = p.stat().st_size
        if size == 0:
            return False, ["Archive is empty (0 bytes)"]
        if size < 22:
            return False, ["Archive too small to contain valid ZIP structure"]

        errors: list[str] = []

        try:
            with open(p, "rb") as f:
                sig8 = f.read(8)
                if sig8.startswith(b"Rar!\x1a\x07"):
                    # RAR Archive Preflight Verification
                    return self._verify_rar_archive(p)

                magic = sig8[:4]
                if not (magic.startswith(b"PK\x03\x04") or magic.startswith(b"PK\x05\x06") or magic.startswith(b"PK\x07\x08")):
                    return False, [f"Invalid ZIP magic bytes: {magic!r}"]

                # Scan backwards for EOCD signature PK\x05\x06
                f.seek(max(0, size - 65557))
                tail = f.read()
                eocd_pos = tail.rfind(b"PK\x05\x06")
                if eocd_pos == -1:
                    return False, ["Archive is truncated or missing End of Central Directory (EOCD)"]

                # Ensure EOCD structure is complete
                # PK\x05\x06 is followed by at least 18 bytes: 2 disk, 2 cd_disk, 2 disk_entries, 2 total_entries, 4 cd_size, 4 cd_offset, 2 comment_len
                eocd_record = tail[eocd_pos:]
                if len(eocd_record) < 22:
                    return False, ["EOCD record truncated at end of archive"]

                comment_len = struct.unpack_from("<H", eocd_record, 20)[0]
                if len(eocd_record) != 22 + comment_len:
                    return False, ["EOCD record length or comment length corrupted"]

                comment_bytes = eocd_record[22:22 + comment_len]
                if comment_bytes:
                    try:
                        decoded_comment = comment_bytes.decode("utf-8")
                        # Comments in valid test/game archives are text; control/non-ascii high bytes indicate corruption
                        if any(ord(ch) < 0x20 and ch not in "\r\n\t" for ch in decoded_comment) or any(ord(ch) > 0x7E for ch in decoded_comment):
                            return False, ["EOCD archive comment contains corrupted non-text bytes"]
                    except UnicodeDecodeError:
                        return False, ["EOCD archive comment corrupted (invalid UTF-8 bytes)"]
        except Exception as e:
            return False, [f"Header check error: {e}"]

        # Now inspect members via zipfile
        try:
            with zipfile.ZipFile(p, "r") as zf:
                infolist = zf.infolist()
                if not infolist:
                    return True, []

                for info in infolist:
                    # Check encryption flag (bit 0 and strong encryption bit 6)
                    if info.flag_bits & 0x01 or info.flag_bits & 0x40:
                        errors.append(f"Member '{info.filename}' is encrypted / password-protected")
                        continue

                    # Stream decompressed content and verify CRC
                    computed_crc = 0
                    decompressed_len = 0
                    try:
                        with zf.open(info) as src:
                            while chunk := src.read(self.buffer_size):
                                computed_crc = zlib.crc32(chunk, computed_crc)
                                decompressed_len += len(chunk)
                        computed_crc &= 0xFFFFFFFF
                    except Exception as e:
                        errors.append(f"Decompression failure in member '{info.filename}': {e}")
                        continue

                    if decompressed_len != info.file_size:
                        errors.append(
                            f"Size mismatch in member '{info.filename}': declared {info.file_size}, decompressed {decompressed_len}"
                        )

                    if computed_crc != info.CRC:
                        errors.append(
                            f"CRC mismatch in member '{info.filename}': expected {info.CRC:08x}, got {computed_crc:08x}"
                        )
        except zipfile.BadZipFile as e:
            errors.append(f"Bad zip file structure: {e}")
        except Exception as e:
            errors.append(f"Archive inspection error: {e}")

        is_valid = len(errors) == 0
        return is_valid, errors

    def _verify_rar_archive(self, archive_path: Path) -> tuple[bool, list[str]]:
        """Verifies RAR archive integrity non-destructively in memory."""
        import shutil
        import subprocess

        # Check for unrar binary
        unrar_bin = None
        for p in [r"C:\Program Files\WinRAR\UnRAR.exe", r"C:\Program Files (x86)\WinRAR\UnRAR.exe"]:
            if os.path.isfile(p):
                unrar_bin = p
                break
        if not unrar_bin:
            unrar_bin = shutil.which("unrar") or shutil.which("UnRAR")

        if unrar_bin:
            try:
                res = subprocess.run(
                    [unrar_bin, "t", "-idq", str(archive_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                if res.returncode == 0:
                    return True, []
                else:
                    err = res.stderr.decode("utf-8", errors="replace").strip()
                    return False, [f"RAR integrity test failed: {err or 'CRC or header corruption detected'}"]
            except Exception as exc:
                return False, [f"RAR testing error: {exc}"]

        # Fallback to header inspection
        try:
            from zeroextract.formats.rar_sparse import parse_rar5_entries
            with open(archive_path, "rb") as f:
                entries = parse_rar5_entries(f)
                if not entries:
                    return False, ["RAR archive contains no valid file headers"]
            return True, []
        except Exception as e:
            return False, [f"RAR structure error: {e}"]


__all__ = ["PreflightShield"]
