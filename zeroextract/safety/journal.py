"""Crash-Safe Transaction Journal for ZeroExtract.

Maintains an atomic on-disk journal tracking completed members and unlinked
archive volumes, enabling seamless crash recovery and resumption.
"""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any


class JournalState(dict):
    """Journal state dictionary with helper methods for progress queries."""

    def get_chunk_offset(self, member_name: str) -> int:
        """Returns the recorded chunk byte offset for an in-flight member."""
        chunk_prog = self.get("chunk_progress", {})
        return chunk_prog.get(member_name, 0)


class _LoadOrCreateDescriptor:
    """Supports TransactionJournal.load_or_create(path) and journal.load_or_create()."""

    def __get__(self, obj: Any, objtype: Any = None) -> Any:
        if obj is None:
            def _cls_loader(path: str | os.PathLike) -> TransactionJournal:
                instance = objtype(path)
                instance._load_or_create_internal()
                return instance
            return _cls_loader
        else:
            def _inst_loader() -> JournalState:
                return obj._load_or_create_internal()
            return _inst_loader


class TransactionJournal:
    """Crash-safe journal logging extraction progress with atomic commits."""

    CURRENT_SCHEMA_VERSION = 1
    DEFAULT_JOURNAL_FILENAME = ".unpack_journal.json"
    load_or_create = _LoadOrCreateDescriptor()

    def __init__(
        self,
        archive_or_journal_path: str | os.PathLike,
        journal_path: str | os.PathLike | None = None,
    ) -> None:
        raw_p = Path(archive_or_journal_path)

        if journal_path is not None:
            self._journal_p = Path(journal_path)
            self._archive_p = raw_p
        elif raw_p.name.endswith(".json") or raw_p.name == self.DEFAULT_JOURNAL_FILENAME:
            self._journal_p = raw_p
            self._archive_p = raw_p.parent
        else:
            self._archive_p = raw_p
            self._journal_p = raw_p.parent / self.DEFAULT_JOURNAL_FILENAME

        self._completed_members: dict[str, dict[str, Any]] = {}
        self._unlinked_volumes: set[str] = set()
        self._chunk_progress: dict[str, int] = {}
        self._planned_entries: list[dict[str, Any]] = []
        self._is_open = True
        self._ops_count = 0
        self._last_flush_time = 0.0

    @property
    def journal_path(self) -> str:
        """String path to the journal file on disk."""
        return str(self._journal_p)

    def _load_or_create_internal(self) -> dict[str, Any]:
        """Loads state from disk if present, or initializes a new journal."""
        if self._journal_p.exists():
            self._clear_readonly(self._journal_p)
            try:
                raw_text = self._journal_p.read_text(encoding="utf-8")
                data = json.loads(raw_text)

                schema_ver = data.get("schema_version", 1)
                if schema_ver > self.CURRENT_SCHEMA_VERSION:
                    raise ValueError(
                        f"Unsupported journal schema version: {schema_ver} "
                        f"(max supported: {self.CURRENT_SCHEMA_VERSION})"
                    )

                raw_completed = data.get("completed_members", {})
                if isinstance(raw_completed, dict):
                    self._completed_members = raw_completed
                elif isinstance(raw_completed, list):
                    # List format fallback
                    self._completed_members = {name: {} for name in raw_completed}
                else:
                    self._completed_members = {}

                self._unlinked_volumes = set(data.get("unlinked_volumes", []))
                self._chunk_progress = data.get("chunk_progress", {})
                self._planned_entries = data.get("planned_entries", [])
                return JournalState(data)

            except json.JSONDecodeError:
                # Corrupted or truncated journal recovered cleanly
                self._completed_members = {}
                self._unlinked_volumes = set()
                self._chunk_progress = {}
                self._planned_entries = []
                self._flush()
                return JournalState(self._build_state_dict())

        # New journal file initialization
        state = self._build_state_dict()
        self._flush()
        return JournalState(state)

    def set_planned_entries(self, entries: list[dict[str, Any]]) -> None:
        """Stores planned archive entries in journal for crash resilience."""
        self._planned_entries = entries
        self._flush()

    def get_planned_entries(self) -> list[dict[str, Any]]:
        """Returns planned archive entries from journal."""
        return self._planned_entries

    def record_chunk_progress(self, member_name: str, chunk_offset: int) -> None:
        """Records byte progress for an in-flight sparse chunked extraction.

        Args:
            member_name: Archive member filename.
            chunk_offset: Byte offset successfully written.
        """
        self._chunk_progress[member_name] = chunk_offset
        self._ops_count += 1
        self._flush()
        self._last_flush_time = time.monotonic()

    def get_chunk_offset(self, member_name: str) -> int:
        """Returns the recorded chunk byte offset for an in-flight member."""
        return self._chunk_progress.get(member_name, 0)

    def mark_completed(
        self,
        member_name: str,
        uncompressed_size: int = 0,
        crc32: int = 0,
        flush: bool = False,
    ) -> None:
        """Records a successfully extracted and verified archive member.

        Args:
            member_name: Archive member filename.
            uncompressed_size: Size in bytes of uncompressed file.
            crc32: 32-bit CRC checksum.
            flush: If True, forces an immediate on-disk flush.
        """
        self._completed_members[member_name] = {
            "uncompressed_size": uncompressed_size,
            "crc32": crc32,
        }
        self._ops_count += 1
        now = time.monotonic()
        if flush or self._ops_count <= 5 or (now - self._last_flush_time >= 0.05):
            self._flush()
            self._last_flush_time = now

    def is_completed(self, member_name: str) -> bool:
        """Checks if a member was already verified and written to disk."""
        return member_name in self._completed_members

    def mark_volume_unlinked(self, volume_name: str, flush: bool = True) -> None:
        """Records that an archive volume has been safely deleted.

        Args:
            volume_name: Filename of the deleted volume.
            flush: If True, forces an immediate on-disk flush.
        """
        self._unlinked_volumes.add(volume_name)
        self._ops_count += 1
        self._flush()
        self._last_flush_time = time.monotonic()

    def flush(self) -> None:
        """Explicitly flushes pending journal state to disk."""
        self._flush()

    def close(self, success: bool = False) -> None:
        """Closes the journal, deleting it on 100% successful extraction."""
        if not success:
            self._flush()
        self._is_open = False
        if success and self._journal_p.exists():
            self._clear_readonly(self._journal_p)
            try:
                self._journal_p.unlink()
            except OSError:
                pass

    def __del__(self) -> None:
        try:
            if getattr(self, "_is_open", False):
                self._flush()
        except Exception:
            pass

    def _build_state_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.CURRENT_SCHEMA_VERSION,
            "archive_path": str(self._archive_p),
            "completed_members": self._completed_members,
            "unlinked_volumes": sorted(self._unlinked_volumes),
            "chunk_progress": self._chunk_progress,
            "planned_entries": getattr(self, "_planned_entries", []),
        }

    def _flush(self) -> None:
        """Atomically commits current state to disk."""
        if not self._is_open:
            return

        self._journal_p.parent.mkdir(parents=True, exist_ok=True)
        if self._journal_p.exists():
            self._clear_readonly(self._journal_p)

        tmp_p = self._journal_p.with_name(self._journal_p.name + ".tmp")
        state = self._build_state_dict()
        raw_json = json.dumps(state)

        try:
            with open(tmp_p, "w", encoding="utf-8") as f:
                f.write(raw_json)
                f.flush()

            os.replace(tmp_p, self._journal_p)
        except Exception:
            if tmp_p.exists():
                try:
                    tmp_p.unlink()
                except OSError:
                    pass
            raise

    def _clear_readonly(self, path: Path) -> None:
        """Clears read-only attribute if set."""
        try:
            if sys.platform == "win32":
                ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)
            else:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass


__all__ = ["TransactionJournal"]
