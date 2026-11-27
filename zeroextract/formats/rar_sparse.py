"""RAR archive format parser and in-place sparse extraction engine.

Supports RAR5 and RAR4 formats. Parses block headers to determine the exact
byte offset and packed size of each file's compressed payload, extracts
members via UnRAR/tar with NTFS compression, and immediately punches sparse
holes (FSCTL_SET_ZERO_DATA) into the source archive payload in real time
to recycle physical disk sectors back to NTFS as extraction progresses.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from typing import Callable, Generator, List, NamedTuple, Optional

from zeroextract.fs.sparse import SparsePuncher
from zeroextract.safety.exceptions import CorruptionError, CorruptionGuard


RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"
RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"


class RarFileEntry(NamedTuple):
    """Metadata for an entry within a RAR archive."""
    name: str
    payload_offset: int
    packed_size: int
    unpacked_size: int
    is_dir: bool


def is_rar_file(path: str | os.PathLike) -> bool:
    """Checks whether the file starts with a RAR signature (RAR5 or RAR4)."""
    try:
        with open(path, "rb") as f:
            sig = f.read(8)
            return sig.startswith(b"Rar!\x1a\x07")
    except Exception:
        return False


def _read_vint(f) -> Optional[int]:
    """Reads a variable-length integer (VINT) from a RAR5 stream."""
    res = 0
    shift = 0
    while True:
        b = f.read(1)
        if not b:
            return None
        val = b[0]
        res |= (val & 0x7F) << shift
        if not (val & 0x80):
            break
        shift += 7
        if shift > 70:
            raise CorruptionError("Malformed VINT in RAR5 header.")
    return res


def parse_rar5_entries(f) -> List[RarFileEntry]:
    """Parses all file entries and payload offsets in a RAR5 archive."""
    entries: List[RarFileEntry] = []
    f.seek(8)  # Skip 8-byte RAR5 signature
    guard = CorruptionGuard()

    while True:
        pos = f.tell()
        crc = f.read(4)
        if len(crc) < 4:
            break

        hdr_size = _read_vint(f)
        if hdr_size is None:
            break
        hdr_start = f.tell()
        hdr_end = hdr_start + hdr_size

        hdr_type = _read_vint(f)
        hdr_flags = _read_vint(f)

        if hdr_flags is None or hdr_type is None:
            break

        extra_size = _read_vint(f) if (hdr_flags & 0x0001) else 0
        data_size = _read_vint(f) if (hdr_flags & 0x0002) else 0

        if hdr_type == 2:  # File header
            file_flags = _read_vint(f)
            unp_size = _read_vint(f)
            attrs = _read_vint(f)
            if file_flags & 0x0002:  # mtime
                f.read(4)
            if file_flags & 0x0004:  # data_crc32
                f.read(4)
            comp_info = _read_vint(f)
            host_os = _read_vint(f)
            name_len = _read_vint(f)
            name_bytes = f.read(name_len)
            raw_name = name_bytes.decode("utf-8", errors="replace")
            # Strip absolute prefixes or traversal components
            clean_name = raw_name.replace("/", os.sep).replace("\\", os.sep)
            if clean_name.startswith(os.sep) or (len(clean_name) > 1 and clean_name[1] == ":"):
                clean_name = clean_name.lstrip(os.sep).split(":", 1)[-1].lstrip(os.sep)
            if ".." in Path(clean_name).parts:
                continue
            is_dir = bool(file_flags & 0x0001)

            payload_offset = hdr_end
            entries.append(
                RarFileEntry(
                    name=clean_name,
                    payload_offset=payload_offset,
                    packed_size=data_size or 0,
                    unpacked_size=unp_size or 0,
                    is_dir=is_dir,
                )
            )

        f.seek(hdr_end + (data_size or 0))

    return entries


class RarSparseExtractor:
    """Extracts RAR archives in-place with real-time NTFS sparse hole-punching."""

    def __init__(self, archive_path: str | os.PathLike) -> None:
        self.archive_path = Path(archive_path).resolve()
        if not self.archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {self.archive_path}")

        self.unrar_bin = self._find_unrar()
        self.puncher = SparsePuncher()

    def _find_unrar(self) -> str:
        """Finds UnRAR.exe or compatible extraction utility."""
        standard_paths = [
            r"C:\Program Files\WinRAR\UnRAR.exe",
            r"C:\Program Files (x86)\WinRAR\UnRAR.exe",
        ]
        for p in standard_paths:
            if os.path.isfile(p):
                return p

        # Check PATH
        which = shutil.which("unrar") or shutil.which("UnRAR") or shutil.which("tar")
        if which:
            return which

        raise RuntimeError(
            "No RAR extraction tool found. Please ensure WinRAR / UnRAR is installed."
        )

    def get_entries(self) -> List[RarFileEntry]:
        """Parses and returns all file entries with their byte offsets."""
        with open(self.archive_path, "rb") as f:
            sig = f.read(8)
            if sig.startswith(RAR5_SIGNATURE):
                return parse_rar5_entries(f)
            elif sig.startswith(RAR4_SIGNATURE):
                # Fallback to listing via unrar
                return self._list_entries_via_unrar()
            else:
                raise CorruptionError(f"Unsupported or invalid RAR signature: {sig[:8]!r}")

    def _list_entries_via_unrar(self, password: Optional[str] = None) -> List[RarFileEntry]:
        """Fall back to parsing entries via unrar vb."""
        pwd_flag = f"-p{password}" if password is not None else "-p-"
        cmd = [self.unrar_bin, "vb", pwd_flag, str(self.archive_path)]
        out = subprocess.check_output(cmd, text=True, errors="replace")
        guard = CorruptionGuard()
        entries = []
        for line in out.splitlines():
            line = line.strip()
            if line:
                clean = line.replace("/", os.sep).replace("\\", os.sep).lstrip(os.sep)
                entries.append(RarFileEntry(name=clean, payload_offset=0, packed_size=0, unpacked_size=0, is_dir=False))
        return entries

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
        """Extracts all files member-by-member and punches sparse holes in lockstep.

        Args:
            output_dir: Directory where extracted files will be placed.
            progress_cb: Callback (filename, bytes_extracted, total_unpacked, total_packed).
            enable_sparse_punch: Whether to deallocate source archive sectors.

        Returns:
            Total number of files extracted.
        """
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        entries = self.get_entries()
        total_unpacked = sum(e.unpacked_size for e in entries)
        total_packed = sum(e.packed_size for e in entries)
        bytes_done = 0
        files_extracted = 0

        # Mark source archive sparse
        if enable_sparse_punch and sys.platform == "win32":
            try:
                self.puncher.mark_as_sparse(self.archive_path)
            except Exception:
                pass

        # Enable NTFS compression on output directory if on Windows
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

        pwd_flag = f"-p{password}" if password is not None else "-p-"

        for entry in entries:
            if cancel_event is not None and cancel_event.is_set():
                raise InterruptedError("Extraction cancelled by user.")

            if entry.is_dir:
                (out_dir / entry.name).mkdir(parents=True, exist_ok=True)
                continue

            # Extract this specific member using unrar
            # -y: assume yes, -idq: quiet, -oc: set NTFS compressed attribute
            cmd = [
                self.unrar_bin,
                "x",
                "-y",
                "-idq",
                pwd_flag,
                "-oc",
                str(self.archive_path),
                entry.name,
                str(out_dir) + os.sep,
            ]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if res.returncode != 0:
                # Try without -oc if -oc is not supported
                cmd = [
                    self.unrar_bin,
                    "x",
                    "-y",
                    "-idq",
                    pwd_flag,
                    str(self.archive_path),
                    entry.name,
                    str(out_dir) + os.sep,
                ]
                res2 = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                if res2.returncode != 0:
                    err_msg = res2.stderr.decode("utf-8", errors="replace")
                    raise RuntimeError(f"UnRAR failed extracting '{entry.name}': {err_msg}")

            bytes_done += entry.unpacked_size
            files_extracted += 1

            if progress_cb:
                progress_cb(entry.name, bytes_done, total_unpacked, total_packed)
            if on_member_extracted:
                on_member_extracted(entry.name)

            # Punch hole on extracted member's compressed payload in source archive
            if enable_sparse_punch and entry.payload_offset > 0 and entry.packed_size >= 65536:
                try:
                    freed = self.puncher.punch_hole(
                        self.archive_path,
                        offset=entry.payload_offset,
                        length=entry.packed_size,
                        cluster_size=65536,
                    )
                    if freed > 0 and on_space_saved is not None:
                        on_space_saved(freed)
                except Exception:
                    pass

        # Once all files are extracted, remove or truncate source archive
        try:
            self.archive_path.unlink()
        except Exception:
            try:
                with open(self.archive_path, "wb") as f:
                    f.truncate(0)
            except Exception:
                pass

        return files_extracted
