"""Unit tests for ZeroExtract Safety and Transaction subsystem (Milestone 3)."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile
import zlib

from zeroextract.safety.atomic import AtomicWriter
from zeroextract.safety.exceptions import (
    ChecksumError,
    CorruptionError,
    CorruptionGuard,
    PathTraversalError,
    SafetyError,
)
from zeroextract.safety.journal import TransactionJournal
from zeroextract.safety.preverify import PreflightShield


class TestPreflightShield(unittest.TestCase):
    """Unit tests for PreflightShield."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_verify_valid_archive(self) -> None:
        zip_p = self.dir / "valid.zip"
        with zipfile.ZipFile(zip_p, "w") as zf:
            zf.writestr("test.txt", b"Hello, world!")
            zf.writestr("data/sub.bin", b"Sub binary content" * 50)

        shield = PreflightShield()
        valid, errors = shield.verify_archive(zip_p)
        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_verify_empty_zip(self) -> None:
        zip_p = self.dir / "empty.zip"
        with zipfile.ZipFile(zip_p, "w"):
            pass

        shield = PreflightShield()
        valid, errors = shield.verify_archive(zip_p)
        self.assertTrue(valid)
        self.assertEqual(errors, [])

    def test_verify_corrupted_magic(self) -> None:
        zip_p = self.dir / "bad_magic.zip"
        zip_p.write_bytes(b"NOT_A_ZIP_HEADER_DATA_1234567890")

        shield = PreflightShield()
        valid, errors = shield.verify_archive(zip_p)
        self.assertFalse(valid)
        self.assertTrue(len(errors) > 0)

    def test_verify_corrupted_crc(self) -> None:
        zip_p = self.dir / "bad_crc.zip"
        with zipfile.ZipFile(zip_p, "w") as zf:
            zf.writestr("corrupt.txt", b"Original content that will have bad CRC")

        # Corrupt central directory CRC
        raw = bytearray(zip_p.read_bytes())
        cd_pos = raw.find(b"PK\x01\x02")
        self.assertNotEqual(cd_pos, -1)
        # Flip bytes in CRC
        raw[cd_pos + 16] ^= 0xFF
        zip_p.write_bytes(raw)

        shield = PreflightShield()
        valid, errors = shield.verify_archive(zip_p)
        self.assertFalse(valid)
        self.assertTrue(any("crc" in e.lower() for e in errors))

    def test_skip_preflight(self) -> None:
        shield = PreflightShield()
        valid, errors = shield.verify_archive("non_existent_file.zip", skip_preflight=True)
        self.assertTrue(valid)
        self.assertEqual(errors, [])


class TestAtomicWriter(unittest.TestCase):
    """Unit tests for AtomicWriter."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_write_atomic_success(self) -> None:
        writer = AtomicWriter()
        dest = self.dir / "output" / "atomic.txt"
        payload = b"Atomic test content line 1\nLine 2\n"
        crc = zlib.crc32(payload) & 0xFFFFFFFF

        written = writer.write_atomic(dest, [payload], expected_crc32=crc)
        self.assertEqual(written, len(payload))
        self.assertTrue(dest.exists())
        self.assertEqual(dest.read_bytes(), payload)
        self.assertFalse(dest.with_name(dest.name + ".unpack_part").exists())

    def test_write_atomic_crc_mismatch_cleans_staging(self) -> None:
        writer = AtomicWriter()
        dest = self.dir / "fail_crc.bin"
        payload = b"Actual content payload"

        with self.assertRaises(ChecksumError):
            writer.write_atomic(dest, [payload], expected_crc32=0xBAD00000)

        self.assertFalse(dest.exists())
        self.assertFalse(dest.with_name(dest.name + ".unpack_part").exists())

    def test_clean_stale_parts(self) -> None:
        writer = AtomicWriter()
        sub = self.dir / "deep" / "folder"
        sub.mkdir(parents=True)
        stale1 = sub / "file1.bin.unpack_part"
        stale2 = sub / "file2.bin.unpack_part"
        stale1.write_bytes(b"stale 1")
        stale2.write_bytes(b"stale 2")

        cleaned = writer.clean_stale_parts(self.dir)
        self.assertEqual(cleaned, 2)
        self.assertFalse(stale1.exists())
        self.assertFalse(stale2.exists())


class TestTransactionJournal(unittest.TestCase):
    """Unit tests for TransactionJournal."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_create_and_mark_completed(self) -> None:
        archive_p = self.dir / "game.zip"
        archive_p.write_bytes(b"dummy")

        journal = TransactionJournal(str(archive_p))
        journal.load_or_create()

        self.assertFalse(journal.is_completed("file1.txt"))
        journal.mark_completed("file1.txt", 1234, 0x12345678)
        self.assertTrue(journal.is_completed("file1.txt"))

        # Re-read
        resumed = TransactionJournal.load_or_create(journal.journal_path)
        self.assertTrue(resumed.is_completed("file1.txt"))
        self.assertFalse(resumed.is_completed("file2.txt"))

    def test_corrupted_json_recovery(self) -> None:
        j_path = self.dir / ".unpack_journal.json"
        j_path.write_text("{broken json syntax ...", encoding="utf-8")

        journal = TransactionJournal(j_path)
        state = journal.load_or_create()
        self.assertIsNotNone(state)
        self.assertFalse(journal.is_completed("anything"))

    def test_unsupported_future_version(self) -> None:
        j_path = self.dir / ".unpack_journal.json"
        j_path.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")

        journal = TransactionJournal(j_path)
        with self.assertRaises(ValueError):
            journal.load_or_create()

    def test_close_success_deletes_journal(self) -> None:
        j_path = self.dir / ".unpack_journal.json"
        journal = TransactionJournal(j_path)
        journal.load_or_create()
        self.assertTrue(j_path.exists())

        journal.close(success=True)
        self.assertFalse(j_path.exists())


class TestCorruptionGuard(unittest.TestCase):
    """Unit tests for CorruptionGuard."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_check_path_safety_valid(self) -> None:
        guard = CorruptionGuard()
        safe_p = guard.check_path_safety("sub/folder/file.txt", self.dir)
        self.assertTrue(str(safe_p).startswith(str(self.dir.resolve())))

    def test_check_path_safety_traversal_rejected(self) -> None:
        guard = CorruptionGuard()
        with self.assertRaises(PathTraversalError):
            guard.check_path_safety("../../Windows/System32/evil.dll", self.dir)


if __name__ == "__main__":
    unittest.main()
