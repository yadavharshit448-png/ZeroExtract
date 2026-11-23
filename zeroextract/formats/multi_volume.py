"""Multi-volume archive sequence discovery, transparent boundary streaming, and progressive unlinking.

Handles Split ZIP (.z01/.z02/.zip, .zip.001), RAR (.part01.rar, .r00),
7-Zip (.7z.001), and generic (.001) multi-volume archives.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
import io
import logging
import os
from pathlib import Path
import re
import struct
import sys
from typing import Any, Callable, Optional
import zipfile

from zeroextract.formats.zip_reverse import PathTraversalError, _sanitize_path
from zeroextract.fs.volume_cleaner import VolumeCleaner, VolumeCleanError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class VolumeInfo:
    """Metadata representing a single volume within a multi-volume sequence."""

    index: int
    path: str
    size: int
    start_offset: int

    @property
    def end_offset(self) -> int:
        return self.start_offset + self.size


class MultiVolumeStreamReader(io.RawIOBase):
    """Seekable/readable binary stream abstracting multiple volume files as a continuous stream.

    Transparently handles reads spanning volume boundaries while maintaining at most
    one open OS file handle to prevent Windows file locking contention (WinError 32).
    """

    def __init__(self, volumes: list[VolumeInfo]) -> None:
        super().__init__()
        if not volumes:
            raise ValueError("volumes list cannot be empty")
        self._volumes = volumes
        self._offsets: list[int] = [0]
        for v in self._volumes:
            self._offsets.append(self._offsets[-1] + v.size)
        self._total_size = self._offsets[-1]
        self._pos = 0
        self._current_handle: Optional[io.BufferedReader] = None
        self._current_vol_idx: Optional[int] = None
        self._unlinked_indices: set[int] = set()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def tell(self) -> int:
        return self._pos

    @property
    def total_size(self) -> int:
        return self._total_size

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            new_pos = offset
        elif whence == io.SEEK_CUR:
            new_pos = self._pos + offset
        elif whence == io.SEEK_END:
            new_pos = self._total_size + offset
        else:
            raise ValueError(f"Invalid whence argument: {whence}")

        if new_pos < 0:
            raise ValueError(f"Negative seek position: {new_pos}")
        self._pos = new_pos
        return self._pos

    def _locate_volume(self, pos: int) -> tuple[int, int]:
        """Maps a global byte offset to (volume_index, internal_volume_offset)."""
        if pos >= self._total_size:
            return len(self._volumes), 0
        idx = bisect.bisect_right(self._offsets, pos) - 1
        return idx, pos - self._offsets[idx]

    def _get_handle(self, vol_idx: int) -> io.BufferedReader:
        if vol_idx in self._unlinked_indices:
            raise VolumeCleanError(
                f"Volume {vol_idx} ({self._volumes[vol_idx].path}) has been unlinked "
                "to reclaim disk space and can no longer be accessed."
            )
        if self._current_vol_idx == vol_idx and self._current_handle is not None:
            return self._current_handle

        self._close_handle()
        self._current_handle = open(self._volumes[vol_idx].path, "rb")
        self._current_vol_idx = vol_idx
        return self._current_handle

    def _close_handle(self) -> None:
        if self._current_handle is not None:
            try:
                self._current_handle.close()
            finally:
                self._current_handle = None
                self._current_vol_idx = None

    def close_volume(self, vol_idx: int) -> None:
        """Explicitly closes handle for a volume and marks it unlinked."""
        if self._current_vol_idx == vol_idx:
            self._close_handle()
        self._unlinked_indices.add(vol_idx)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._total_size - self._pos
        if self._pos >= self._total_size or size <= 0:
            return b""

        bytes_to_read = min(size, self._total_size - self._pos)
        chunks: list[bytes] = []

        while bytes_to_read > 0 and self._pos < self._total_size:
            vol_idx, internal_offset = self._locate_volume(self._pos)
            if vol_idx >= len(self._volumes):
                break
            vol_size = self._volumes[vol_idx].size
            chunk_len = min(bytes_to_read, vol_size - internal_offset)

            handle = self._get_handle(vol_idx)
            handle.seek(internal_offset)
            data = handle.read(chunk_len)
            if not data:
                break
            chunks.append(data)
            self._pos += len(data)
            bytes_to_read -= len(data)

        return b"".join(chunks)

    def close(self) -> None:
        self._close_handle()
        super().close()


class MultiVolumeStreamer:
    """Multi-volume archive sequence coordinator and progressive cleaner."""

    def __init__(
        self,
        first_volume_path: str | os.PathLike | None = None,
        cleaner: VolumeCleaner | None = None,
    ) -> None:
        self.first_volume_path = os.fspath(first_volume_path) if first_volume_path is not None else None
        self.cleaner = cleaner or VolumeCleaner()
        self.volumes: list[VolumeInfo] = []
        self._reader: Optional[MultiVolumeStreamReader] = None

    def _parse_part_index(self, path_str: str) -> tuple[str, int]:
        """Parses base name and volume index for any supported split volume filename."""
        name = os.path.basename(path_str)

        m_rar = re.match(r"^(.*?)\.part(\d+)\.rar$", name, re.IGNORECASE)
        if m_rar:
            return m_rar.group(1), int(m_rar.group(2))

        m_7z = re.match(r"^(.*?)\.7z\.(\d+)$", name, re.IGNORECASE)
        if m_7z:
            return m_7z.group(1), int(m_7z.group(2))

        m_zip_num = re.match(r"^(.*?)\.zip\.(\d+)$", name, re.IGNORECASE)
        if m_zip_num:
            return m_zip_num.group(1), int(m_zip_num.group(2))

        m_z = re.match(r"^(.*?)\.z(\d{2,})$", name, re.IGNORECASE)
        if m_z:
            return m_z.group(1), int(m_z.group(2))

        m_zip = re.match(r"^(.*?)\.zip$", name, re.IGNORECASE)
        if m_zip:
            # Final PKWARE volume
            return m_zip.group(1), 999999999

        m_r = re.match(r"^(.*?)\.r(\d{2,})$", name, re.IGNORECASE)
        if m_r:
            return m_r.group(1), int(m_r.group(2)) + 1

        m_old_rar = re.match(r"^(.*?)\.rar$", name, re.IGNORECASE)
        if m_old_rar:
            return m_old_rar.group(1), 0

        m_gen = re.match(r"^(.*?)\.(\d{3,})$", name)
        if m_gen:
            return m_gen.group(1), int(m_gen.group(2))

        return name, 1

    def validate_volume_sequence(self, volume_paths: list[str]) -> bool:
        """Validates that a list of volume paths is strictly ordered and contiguous.

        Raises:
            ValueError: If volume paths are scrambled, out of order, or have gaps.
        """
        if not volume_paths:
            raise ValueError("volume_paths cannot be empty")

        parsed = []
        for p in volume_paths:
            base, idx = self._parse_part_index(p)
            parsed.append((base, idx, p))

        # Check all share base
        bases = {b.lower() for b, _, _ in parsed}
        if len(bases) > 1:
            raise ValueError(f"Mismatched volume bases in sequence: {bases}")

        # Check order
        for i in range(len(parsed) - 1):
            curr_idx = parsed[i][1]
            next_idx = parsed[i + 1][1]
            if curr_idx >= next_idx:
                raise ValueError(
                    f"Out-of-order volumes detected: '{parsed[i][2]}' (index {curr_idx}) "
                    f"precedes '{parsed[i + 1][2]}' (index {next_idx})"
                )

        # Check contiguity (except for 999999999 final marker in pkware)
        for i in range(len(parsed) - 1):
            curr_idx = parsed[i][1]
            next_idx = parsed[i + 1][1]
            if next_idx != 999999999 and next_idx != curr_idx + 1:
                raise ValueError(
                    f"Gap detected in volume sequence between '{parsed[i][2]}' and '{parsed[i + 1][2]}'"
                )

        return True

    def discover_volumes(self, path: str | os.PathLike | None = None) -> list[str]:
        """Discovers all volumes in sequence given any member of the split archive set."""
        target = path or self.first_volume_path
        if target is None:
            raise ValueError("Archive volume path must be provided")

        vol_path = Path(target).resolve()
        if not vol_path.exists():
            raise FileNotFoundError(f"Archive volume not found: '{vol_path}'")

        parent = vol_path.parent
        name = vol_path.name

        m_rar = re.match(r"^(.*?)\.part(\d+)\.rar$", name, re.IGNORECASE)
        m_7z = re.match(r"^(.*?)\.7z\.(\d+)$", name, re.IGNORECASE)
        m_zip_num = re.match(r"^(.*?)\.zip\.(\d+)$", name, re.IGNORECASE)
        m_z = re.match(r"^(.*?)\.z(\d{2,})$", name, re.IGNORECASE)
        m_zip = re.match(r"^(.*?)\.zip$", name, re.IGNORECASE)
        m_r = re.match(r"^(.*?)\.r(\d{2,})$", name, re.IGNORECASE)
        m_old_rar = re.match(r"^(.*?)\.rar$", name, re.IGNORECASE)
        m_gen = re.match(r"^(.*?)\.(\d{3,})$", name)

        if m_rar:
            base = m_rar.group(1)
            pat = re.compile(rf"^{re.escape(base)}\.part(\d+)\.rar$", re.IGNORECASE)
            return self._collect_numbered_volumes(parent, pat, base)

        if m_7z:
            base = m_7z.group(1)
            pat = re.compile(rf"^{re.escape(base)}\.7z\.(\d+)$", re.IGNORECASE)
            return self._collect_numbered_volumes(parent, pat, base)

        if m_zip_num:
            base = m_zip_num.group(1)
            pat = re.compile(rf"^{re.escape(base)}\.zip\.(\d+)$", re.IGNORECASE)
            return self._collect_numbered_volumes(parent, pat, base)

        if m_z or m_zip:
            base = m_z.group(1) if m_z else m_zip.group(1)
            z01 = parent / f"{base}.z01"
            if z01.exists() or m_z:
                pat_z = re.compile(rf"^{re.escape(base)}\.z(\d{{2,}})$", re.IGNORECASE)
                z_items: list[tuple[int, str]] = []
                for f in parent.iterdir():
                    fm = pat_z.match(f.name)
                    if fm:
                        z_items.append((int(fm.group(1)), str(f)))
                z_items.sort(key=lambda x: x[0])
                self._validate_contiguous(z_items, base, start_idx=1)
                result = [f for _, f in z_items]
                zip_file = parent / f"{base}.zip"
                if not zip_file.exists():
                    raise FileNotFoundError(f"Missing final split volume: {zip_file}")
                result.append(str(zip_file))
                return result

        if m_r or m_old_rar:
            base = m_r.group(1) if m_r else m_old_rar.group(1)
            r00 = parent / f"{base}.r00"
            if r00.exists() or m_r:
                result = []
                rar_file = parent / f"{base}.rar"
                if rar_file.exists():
                    result.append(str(rar_file))
                pat_r = re.compile(rf"^{re.escape(base)}\.r(\d{{2,}})$", re.IGNORECASE)
                r_items: list[tuple[int, str]] = []
                for f in parent.iterdir():
                    fm = pat_r.match(f.name)
                    if fm:
                        r_items.append((int(fm.group(1)), str(f)))
                r_items.sort(key=lambda x: x[0])
                self._validate_contiguous(r_items, base, start_idx=0)
                result.extend([f for _, f in r_items])
                return result

        if m_gen:
            base = m_gen.group(1)
            pat = re.compile(rf"^{re.escape(base)}\.(\d{{3,}})$")
            return self._collect_numbered_volumes(parent, pat, base)

        # Single volume fallback
        return [str(vol_path)]

    def _collect_numbered_volumes(
        self, parent: Path, pattern: re.Pattern, base_name: str
    ) -> list[str]:
        items: list[tuple[int, str]] = []
        for f in parent.iterdir():
            m = pattern.match(f.name)
            if m:
                items.append((int(m.group(1)), str(f)))
        items.sort(key=lambda x: x[0])
        self._validate_contiguous(items, base_name, start_idx=1)
        return [f for _, f in items]

    def _validate_contiguous(
        self, items: list[tuple[int, str]], base_name: str, start_idx: int = 1
    ) -> None:
        if not items:
            return
        if items[0][0] != start_idx:
            raise FileNotFoundError(
                f"Missing initial volume for sequence '{base_name}': expected index {start_idx}, found {items[0][0]}"
            )
        for i in range(len(items) - 1):
            curr_idx = items[i][0]
            next_idx = items[i + 1][0]
            if next_idx != curr_idx + 1:
                raise FileNotFoundError(
                    f"Gap detected in split volumes for '{base_name}': missing volume {curr_idx + 1} between {curr_idx} and {next_idx}"
                )

    def open_stream(self, path: str | os.PathLike | None = None) -> MultiVolumeStreamReader:
        """Initializes and returns a seekable/readable stream over the concatenated volumes."""
        target = path or self.first_volume_path
        paths = self.discover_volumes(target)
        self.volumes = []
        cumulative_offset = 0
        for idx, p in enumerate(paths):
            sz = os.path.getsize(p)
            v_info = VolumeInfo(index=idx, path=p, size=sz, start_offset=cumulative_offset)
            self.volumes.append(v_info)
            cumulative_offset += sz

        self._reader = MultiVolumeStreamReader(self.volumes)
        return self._reader

    def extract_and_clean(
        self,
        output_dir: str | os.PathLike,
        on_volume_done: Optional[Callable[[str, int], None]] = None,
    ) -> list[str]:
        """Streams through volumes, extracts members, and unlinks each volume as soon as fully consumed."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        reader = self.open_stream()
        extracted_files: list[str] = []
        unlinked_volumes: set[int] = set()

        try:
            with zipfile.ZipFile(reader) as zf:
                infolist = zf.infolist()
                infolist.sort(key=lambda info: info.header_offset)
                entry_vols = []
                for info in infolist:
                    start_off = info.header_offset
                    # Total span of member in virtual stream: LFH + filename + extra + compressed payload
                    try:
                        reader.seek(start_off)
                        lfh_buf = reader.read(30)
                        if len(lfh_buf) == 30 and lfh_buf.startswith(b"PK\x03\x04"):
                            lfh_fn_len, lfh_extra_len = struct.unpack("<2H", lfh_buf[26:30])
                            end_off = start_off + 30 + lfh_fn_len + lfh_extra_len + info.compress_size
                        else:
                            end_off = start_off + 30 + len(info.filename.encode("utf-8")) + len(info.extra) + info.compress_size
                    except Exception:
                        end_off = start_off + 30 + len(info.filename.encode("utf-8")) + len(info.extra) + info.compress_size

                    first_v = max(0, min(len(self.volumes) - 1, bisect.bisect_right(reader._offsets, max(0, start_off)) - 1))
                    last_v = max(first_v, min(len(self.volumes) - 1, bisect.bisect_right(reader._offsets, max(0, end_off - 1)) - 1))
                    entry_vols.append((info, first_v, last_v))

                pending_per_vol = {i: set() for i in range(len(self.volumes))}
                for e_idx, (info, fv, lv) in enumerate(entry_vols):
                    for v in range(max(0, fv), min(lv + 1, len(self.volumes))):
                        pending_per_vol[v].add(e_idx)

                for e_idx, (info, fv, lv) in enumerate(entry_vols):
                    target_file = _sanitize_path(info.filename, out_path)
                    if info.is_dir():
                        target_file.mkdir(parents=True, exist_ok=True)
                    else:
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        tmp_target = target_file.with_name(target_file.name + ".unpack_part")

                        try:
                            with zf.open(info.filename) as src, open(tmp_target, "wb") as f_out:
                                while chunk := src.read(1024 * 1024):
                                    f_out.write(chunk)
                                f_out.flush()
                                os.fsync(f_out.fileno())

                            os.replace(tmp_target, target_file)
                        except Exception:
                            if tmp_target.exists():
                                try:
                                    tmp_target.unlink()
                                except OSError:
                                    pass
                            raise

                        extracted_files.append(str(target_file))

                    for v in range(fv, min(lv + 1, len(self.volumes))):
                        pending_per_vol[v].discard(e_idx)

                    # Progressive unlinking of completed leading volumes
                    for v in range(len(self.volumes) - 1):
                        if v not in unlinked_volumes and len(pending_per_vol[v]) == 0:
                            reader.close_volume(v)
                            self.cleaner.unlink_volume(self.volumes[v].path)
                            unlinked_volumes.add(v)
                            if on_volume_done is not None:
                                on_volume_done(self.volumes[v].path, v)

        finally:
            reader.close()

        # Unlink final remaining volume(s)
        for v in range(len(self.volumes)):
            if v not in unlinked_volumes:
                self.cleaner.unlink_volume(self.volumes[v].path)
                unlinked_volumes.add(v)
                if on_volume_done is not None:
                    on_volume_done(self.volumes[v].path, v)

        return extracted_files

    def extract(
        self,
        first_volume_path: str | os.PathLike | None = None,
        output_dir: str | os.PathLike | None = None,
        on_volume_done: Optional[Callable[[str, int], None]] = None,
    ) -> list[str]:
        """Convenience method for extraction with optional volume path override."""
        if first_volume_path is not None:
            self.first_volume_path = os.fspath(first_volume_path)
        if output_dir is None:
            raise ValueError("output_dir must be specified")
        return self.extract_and_clean(output_dir, on_volume_done=on_volume_done)
