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
        password: str | None = None,
    ) -> tuple[bool, list[str]]:
        """Verifies archive integrity without writing any data to disk.

        Args:
            archive_path: Path to target archive file.
            skip_preflight: If True, bypasses pre-verification and returns (True, []).
            password: Optional password for encrypted archives.

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
                    return self._verify_rar_archive(p, password=password)
                if sig8[:6] == b"7z\xbc\xaf\x27\x1c":
                    # 7z Archive Preflight Verification
                    return self._verify_7z_archive(p, password=password)

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
                    is_encrypted = bool(info.flag_bits & 0x01 or info.flag_bits & 0x40)
                    if is_encrypted and password is None:
                        errors.append(f"Member '{info.filename}' is encrypted / password-protected")
                        continue

                    # Stream decompressed content and verify CRC
                    computed_crc = 0
                    decompressed_len = 0
                    try:
                        pwd_bytes = password.encode("utf-8") if (is_encrypted and password is not None) else None
                        with zf.open(info, pwd=pwd_bytes) as src:
                            while chunk := src.read(self.buffer_size):
                                computed_crc = zlib.crc32(chunk, computed_crc)
                                decompressed_len += len(chunk)
                        computed_crc &= 0xFFFFFFFF
                    except NotImplementedError as e:
                        if info.compress_type == 99 and password is not None:
                            aes_ok, aes_errs = self._verify_aes_zip_member(p, info.filename, password)
                            if not aes_ok:
                                errors.extend(aes_errs)
                            continue
                        errors.append(f"Decompression failure in member '{info.filename}': {e}")
                        continue
                    except RuntimeError as e:
                        msg = str(e)
                        if "Bad password" in msg or "password" in msg.lower():
                            errors.append(f"Incorrect password for member '{info.filename}'")
                        else:
                            errors.append(f"Decompression failure in member '{info.filename}': {e}")
                        continue
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

    def _verify_aes_zip_member(
        self, archive_path: Path, member_name: str, password: str
    ) -> tuple[bool, list[str]]:
        """Verifies an AES-encrypted ZIP member using pyzipper or 7z if available."""
        import shutil
        import subprocess

        try:
            import pyzipper  # type: ignore

            with pyzipper.AESZipFile(archive_path, "r") as azf:
                azf.setpassword(password.encode("utf-8"))
                with azf.open(member_name) as src:
                    while src.read(self.buffer_size):
                        pass
            return True, []
        except ImportError:
            pass
        except Exception as exc:
            return False, [f"AES-ZIP verification failed for '{member_name}': {exc}"]

        sevenz_bin = None
        for cand in [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"]:
            if os.path.isfile(cand):
                sevenz_bin = cand
                break
        if not sevenz_bin:
            sevenz_bin = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")

        if sevenz_bin:
            res = subprocess.run(
                [sevenz_bin, "t", f"-p{password}", str(archive_path), member_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if res.returncode == 0:
                return True, []
            err = res.stderr.decode("utf-8", errors="replace").strip()
            return False, [f"AES-ZIP verification failed for '{member_name}': {err or 'wrong password or corruption'}"]

        return False, [f"Member '{member_name}' uses AES encryption (install pyzipper or 7z to verify)"]

    def _verify_rar_archive(self, archive_path: Path, password: str | None = None) -> tuple[bool, list[str]]:
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
            pwd_flag = f"-p{password}" if password is not None else "-p-"
            try:
                res = subprocess.run(
                    [unrar_bin, "t", "-idq", pwd_flag, str(archive_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                if res.returncode == 0:
                    return True, []
                else:
                    err = res.stderr.decode("utf-8", errors="replace").strip()
                    return False, [f"RAR integrity test failed: {err or 'CRC, password, or header corruption detected'}"]
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

    def _verify_7z_archive(self, archive_path: Path, password: str | None = None) -> tuple[bool, list[str]]:
        """Verifies 7z archive integrity non-destructively."""
        import shutil
        import subprocess

        sevenz_bin = None
        for cand in [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"]:
            if os.path.isfile(cand):
                sevenz_bin = cand
                break
        if not sevenz_bin:
            sevenz_bin = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")

        if sevenz_bin:
            pwd_flag = f"-p{password}" if password is not None else "-p"
            try:
                res = subprocess.run(
                    [sevenz_bin, "t", pwd_flag, str(archive_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                if res.returncode == 0:
                    return True, []
                err = res.stderr.decode("utf-8", errors="replace").strip()
                return False, [f"7z integrity test failed: {err or 'wrong password or CRC/header corruption'}"]
            except Exception as exc:
                return False, [f"7z testing error: {exc}"]

        # Fallback to 32-byte signature header check
        try:
            with open(archive_path, "rb") as f:
                hdr = f.read(32)
            if len(hdr) < 32 or hdr[:6] != b"7z\xbc\xaf\x27\x1c":
                return False, ["Invalid 7z signature header"]
            return True, []
        except Exception as exc:
            return False, [f"7z structure error: {exc}"]


__all__ = ["PreflightShield"]
