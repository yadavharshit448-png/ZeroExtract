"""7z archive format parser and in-place sparse extraction engine.

Parses 7z technical listings (7z l -slt) to determine entry metadata and
solid block pack offsets, extracts members via 7z/7zz/7za, and punches
sparse holes (FSCTL_SET_ZERO_DATA on Windows / fallocate on Linux) into
completed pack blocks in real time to recycle physical disk sectors.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
from typing import Callable, Dict, List, NamedTuple, Optional

from zeroextract.fs.sparse import SparsePuncher
from zeroextract.safety.exceptions import CorruptionError

SEVENZ_SIGNATURE = b"7z\xbc\xaf\x27\x1c"
SEVENZ_HEADER_SIZE = 32


class SevenZFileEntry(NamedTuple):
    """Metadata for an entry within a 7z archive."""

    name: str
    size: int
    packed_size: int
    offset: int
    is_dir: bool
    encrypted: bool = False
    block_index: int = -1


def is_7z_file(path: str | os.PathLike) -> bool:
    """Checks whether the file starts with the 6-byte 7z magic signature."""
    try:
        with open(path, "rb") as f:
            return f.read(6) == SEVENZ_SIGNATURE
    except OSError:
        return False


def _sanitize_7z_member_name(raw_name: str) -> Optional[str]:
    """Normalizes a 7z member path and rejects path traversal attempts."""
    clean = raw_name.replace("/", os.sep).replace("\\", os.sep)
    if clean.startswith(os.sep) or (len(clean) > 1 and clean[1] == ":"):
        clean = clean.lstrip(os.sep).split(":", 1)[-1].lstrip(os.sep)
    if not clean or ".." in Path(clean).parts:
        return None
    return clean


def _parse_int(value: str, default: int = 0) -> int:
    """Parses an integer field from 7z -slt output, returning default on empty/invalid."""
    value = value.strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_7z_slt_output(output: str) -> List[SevenZFileEntry]:
    """Parses `7z l -slt` technical listing stdout into SevenZFileEntry objects."""
    entries: List[SevenZFileEntry] = []
    # Technical listing separates archive header and each member by blank lines after '----------'
    marker_idx = output.find("----------")
    body = output[marker_idx + len("----------"):] if marker_idx != -1 else output

    stanzas = [s.strip() for s in body.strip().split("\n\n") if s.strip()]
    if not stanzas and body.strip():
        stanzas = [s.strip() for s in body.strip().split("\r\n\r\n") if s.strip()]

    for stanza in stanzas:
        fields: Dict[str, str] = {}
        for line in stanza.splitlines():
            if " = " in line:
                k, v = line.split(" = ", 1)
                fields[k.strip()] = v.strip()

        raw_path = fields.get("Path")
        if not raw_path:
            continue
        clean_name = _sanitize_7z_member_name(raw_path)
        if clean_name is None:
            continue

        folder_attr = fields.get("Folder", "")
        attrs = fields.get("Attributes", "")
        is_dir = folder_attr == "+" or attrs.startswith("D")

        size = _parse_int(fields.get("Size", "0"))
        packed_size = _parse_int(fields.get("Packed Size", "0"))
        offset = _parse_int(fields.get("Offset", "0"))
        block_index = _parse_int(fields.get("Block", "-1"), default=-1)
        encrypted = fields.get("Encrypted", "-") == "+"

        entries.append(
            SevenZFileEntry(
                name=clean_name,
                size=size,
                packed_size=packed_size,
                offset=offset,
                is_dir=is_dir,
                encrypted=encrypted,
                block_index=block_index,
            )
        )

    return entries


class SevenZSparseExtractor:
    """Extracts 7z archives in-place with real-time sparse hole-punching."""

    def __init__(self, archive_path: str | os.PathLike, sevenz_bin: Optional[str] = None) -> None:
        self.archive_path = Path(archive_path).resolve()
        if not self.archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {self.archive_path}")

        self.sevenz_bin = sevenz_bin or self._find_7z()
        self.puncher = SparsePuncher()

    def _find_7z(self) -> str:
        """Finds 7z.exe, 7z, 7zz, or 7za executable."""
        standard_paths = [
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ]
        for p in standard_paths:
            if os.path.isfile(p):
                return p

        which = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
        if which:
            return which

        raise RuntimeError(
            "No 7-Zip extraction tool found. Please ensure 7-Zip (7z/7zz/7za) is installed."
        )

    def _read_pack_end_offset(self) -> int:
        """Reads the 32-byte 7z signature header to determine where packed streams end."""
        with open(self.archive_path, "rb") as f:
            hdr = f.read(SEVENZ_HEADER_SIZE)
            if len(hdr) < SEVENZ_HEADER_SIZE or hdr[:6] != SEVENZ_SIGNATURE:
                raise CorruptionError("Invalid 7z archive signature header.")
            next_header_offset = struct.unpack_from("<Q", hdr, 12)[0]
            return SEVENZ_HEADER_SIZE + next_header_offset

    def get_entries(self, password: Optional[str] = None) -> List[SevenZFileEntry]:
        """Lists all entries in the 7z archive via `7z l -slt`."""
        pwd_arg = f"-p{password}" if password is not None else "-p"
        cmd = [self.sevenz_bin, "l", "-slt", pwd_arg, str(self.archive_path)]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
        if res.returncode != 0:
            err = (res.stderr or res.stdout).strip()
            if "Wrong password" in err or "encrypted" in err.lower():
                raise PermissionError(f"Incorrect or missing password for 7z archive: {err}")
            raise CorruptionError(f"7z listing failed: {err}")
        return parse_7z_slt_output(res.stdout)

    def extract(
        self,
        output_dir: str | os.PathLike,
        progress_cb: Optional[Callable[[str, int, int, int], None]] = None,
        enable_sparse_punch: bool = True,
        password: Optional[str] = None,
        on_space_saved: Optional[Callable[[int], None]] = None,
        cancel_event: Optional[threading.Event] = None,
        on_member_extracted: Optional[Callable[[str], None]] = None,
    ) -> int:
        """Extracts all files and punches sparse holes into completed pack blocks.

        Args:
            output_dir: Destination directory.
            progress_cb: Callback (filename, bytes_extracted, total_unpacked, total_packed).
            enable_sparse_punch: Whether to punch sparse holes in the source archive.
            password: Optional archive password.
            on_space_saved: Callback invoked with delta bytes punched/freed.
            cancel_event: Optional threading.Event to safely abort extraction.
            on_member_extracted: Callback invoked with each completed member name.

        Returns:
            Number of files extracted.
        """
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        entries = self.get_entries(password=password)
        file_entries = [e for e in entries if not e.is_dir]
        total_unpacked = sum(e.size for e in file_entries)
        total_packed = sum(e.packed_size for e in file_entries)

        entry_by_norm: Dict[str, SevenZFileEntry] = {
            e.name.replace("\\", "/").lower(): e for e in file_entries
        }
        # Track remaining files per solid block so we only punch a block after all its files finish
        block_remaining: Dict[int, int] = {}
        block_ranges: Dict[int, tuple[int, int]] = {}
        for e in file_entries:
            if e.block_index >= 0:
                block_remaining[e.block_index] = block_remaining.get(e.block_index, 0) + 1
                if e.packed_size > 0 and e.block_index not in block_ranges:
                    block_ranges[e.block_index] = (SEVENZ_HEADER_SIZE + e.offset, e.packed_size)

        if enable_sparse_punch:
            try:
                self.puncher.mark_as_sparse(self.archive_path)
            except Exception:
                pass

        if sys.platform == "win32":
            try:
                subprocess.run(
                    ["compact", "/c", str(out_dir)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass

        pwd_arg = f"-p{password}" if password is not None else "-p"
        cmd = [
            self.sevenz_bin,
            "x",
            "-y",
            "-bb1",
            pwd_arg,
            f"-o{out_dir}",
            str(self.archive_path),
        ]

        bytes_done = 0
        files_extracted = 0
        completed_blocks: set[int] = set()

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )
        assert proc.stdout is not None

        def _punch_block(blk_idx: int) -> None:
            if not enable_sparse_punch or blk_idx in completed_blocks:
                return
            completed_blocks.add(blk_idx)
            if blk_idx in block_ranges:
                off, length = block_ranges[blk_idx]
                if length >= 65536:
                    try:
                        freed = self.puncher.punch_hole(
                            self.archive_path,
                            offset=off,
                            length=length,
                            cluster_size=65536,
                        )
                        if freed > 0 and on_space_saved is not None:
                            on_space_saved(freed)
                    except Exception:
                        pass

        pending_block_to_punch: Optional[int] = None
        for line in proc.stdout:
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                proc.wait()
                raise InterruptedError("Extraction cancelled by user.")

            stripped = line.strip()
            if stripped.startswith("- "):
                # Previous file finished extracting
                if pending_block_to_punch is not None:
                    _punch_block(pending_block_to_punch)
                    pending_block_to_punch = None

                member_rel = stripped[2:].strip().replace("\\", "/")
                entry = entry_by_norm.get(member_rel.lower())
                if entry is not None:
                    bytes_done += entry.size
                    files_extracted += 1
                    if progress_cb:
                        progress_cb(entry.name, bytes_done, total_unpacked, total_packed)
                    if on_member_extracted:
                        on_member_extracted(entry.name)

                    if entry.block_index >= 0 and entry.block_index in block_remaining:
                        block_remaining[entry.block_index] -= 1
                        if block_remaining[entry.block_index] <= 0:
                            pending_block_to_punch = entry.block_index

        if pending_block_to_punch is not None:
            _punch_block(pending_block_to_punch)

        rc = proc.wait()
        stderr_out = proc.stderr.read() if proc.stderr else ""
        if rc != 0:
            if "Wrong password" in stderr_out or "Data Error in encrypted file" in stderr_out:
                raise PermissionError(f"Incorrect password for 7z archive: {stderr_out.strip()}")
            raise RuntimeError(f"7z extraction failed (exit {rc}): {stderr_out.strip()}")

        # Remove or truncate source archive upon successful completion
        orig_size = 0
        try:
            orig_size = self.archive_path.stat().st_size
            self.archive_path.unlink()
            if orig_size > 0 and on_space_saved is not None:
                on_space_saved(orig_size)
        except Exception:
            try:
                with open(self.archive_path, "wb") as f:
                    f.truncate(0)
                if orig_size > 0 and on_space_saved is not None:
                    on_space_saved(orig_size)
            except Exception:
                pass

        return files_extracted


__all__ = [
    "SEVENZ_SIGNATURE",
    "SevenZFileEntry",
    "SevenZSparseExtractor",
    "is_7z_file",
    "parse_7z_slt_output",
]
