"""Unit tests for v0.1.1+ features: 7z sparse extraction, passwords, Linux fallocate, GUI/CLI polish."""

from __future__ import annotations

import ctypes
import io
import os
from pathlib import Path
import struct
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch
import zipfile
import zlib

import pytest

from zeroextract.cli.gui import _format_bytes_human, _parse_drop_paths
from zeroextract.cli.main import create_parser, extract_single_archive, main
from zeroextract.cli.ui import TerminalUI
from zeroextract.formats.sevenz_sparse import (
    SEVENZ_SIGNATURE,
    SevenZSparseExtractor,
    is_7z_file,
    parse_7z_slt_output,
)
from zeroextract.formats.zip_reverse import ZipFormatError, ZipReverseExtractor
from zeroextract.fs.sparse import FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, SparseError, SparsePuncher
from zeroextract.fs.truncator import ReverseTruncator
from zeroextract.safety.preverify import PreflightShield


def _build_zipcrypto_zip(path: Path, filename: str, data: bytes, password: str) -> None:
    """Builds a valid ZipCrypto-encrypted ZIP file in pure Python."""
    crc = zlib.crc32(data) & 0xFFFFFFFF
    comp_data = zlib.compress(data)[2:-4]  # raw DEFLATE

    # PKWARE ZipCrypto key schedule
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

    def update(c: int) -> None:
        nonlocal k0, k1, k2
        k0 = (~zlib.crc32(bytes([c]), ~k0)) & 0xFFFFFFFF
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = (~zlib.crc32(bytes([(k1 >> 24) & 0xFF]), ~k2)) & 0xFFFFFFFF

    def encrypt_byte(b: int) -> int:
        temp = (k2 | 2) & 0xFFFF
        key = ((temp * (temp ^ 1)) >> 8) & 0xFF
        update(b)
        return b ^ key

    for ch in password.encode("utf-8"):
        update(ch)

    # 12-byte encryption header ending with high byte of CRC32
    hdr_plain = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, (crc >> 24) & 0xFF])
    enc_stream = bytes(encrypt_byte(b) for b in hdr_plain) + bytes(encrypt_byte(b) for b in comp_data)

    fn_bytes = filename.encode("utf-8")
    lfh = struct.pack(
        "<4s5H3I2H",
        b"PK\x03\x04",
        20,  # version needed
        0x0001,  # flag bit 0: encrypted
        8,  # DEFLATE
        0,  # mod_time
        0,  # mod_date
        crc,
        len(enc_stream),
        len(data),
        len(fn_bytes),
        0,
    ) + fn_bytes

    cd_offset = len(lfh) + len(enc_stream)
    cdfh = struct.pack(
        "<4s6H3I5H2I",
        b"PK\x01\x02",
        20,
        20,
        0x0001,
        8,
        0,
        0,
        crc,
        len(enc_stream),
        len(data),
        len(fn_bytes),
        0,
        0,
        0,
        0,
        0,
        0,
    ) + fn_bytes

    eocd = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        1,
        1,
        len(cdfh),
        cd_offset,
        0,
    )
    path.write_bytes(lfh + enc_stream + cdfh + eocd)


class TestLinuxSparseAndTruncate:
    """Tests for Linux fallocate hole punching and ftruncate support."""

    def test_linux_fallocate_punch_hole_mocked(self, tmp_path: Path) -> None:
        target = tmp_path / "linux_sparse.bin"
        target.write_bytes(b"\xAA" * (256 * 1024))

        mock_libc = MagicMock()
        mock_libc.fallocate.return_value = 0

        puncher = SparsePuncher(kernel32_dll=None, libc_cdll=mock_libc)
        # Force _k32 to None even when running on Windows
        puncher._k32 = None

        assert puncher.is_sparse_supported(target) is True
        assert puncher.mark_as_sparse(target) is True

        freed = puncher.punch_hole(target, offset=0, length=131072, cluster_size=65536)
        assert freed == 131072
        mock_libc.fallocate.assert_called_once()
        args = mock_libc.fallocate.call_args[0]
        assert args[1] == (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)
        assert args[2].value == 0
        assert args[3].value == 131072

    def test_linux_fallocate_error_raises_sparse_error(self, tmp_path: Path) -> None:
        target = tmp_path / "linux_err.bin"
        target.write_bytes(b"\xAA" * (128 * 1024))

        mock_libc = MagicMock()
        mock_libc.fallocate.return_value = -1

        puncher = SparsePuncher(kernel32_dll=None, libc_cdll=mock_libc)
        puncher._k32 = None

        with pytest.raises(SparseError, match="fallocate"):
            puncher.punch_hole(target, offset=0, length=65536, cluster_size=65536)

    def test_truncator_fallback_raw_fd(self, tmp_path: Path) -> None:
        target = tmp_path / "fd_trunc.bin"
        target.write_bytes(b"X" * 1024)

        trunc = ReverseTruncator(kernel32_dll=None)
        trunc._k32 = None

        fd = os.open(target, os.O_RDWR)
        try:
            freed = trunc.truncate_tail(fd, 256)
            assert freed == 768
            assert os.fstat(fd).st_size == 256
        finally:
            os.close(fd)


class TestSevenZSparse:
    """Tests for 7z detection, -slt parsing, and sparse extraction."""

    def test_is_7z_file(self, tmp_path: Path) -> None:
        valid = tmp_path / "game.7z"
        valid.write_bytes(SEVENZ_SIGNATURE + b"\x00" * 26)
        invalid = tmp_path / "not7z.zip"
        invalid.write_bytes(b"PK\x03\x04" + b"\x00" * 20)

        assert is_7z_file(valid) is True
        assert is_7z_file(invalid) is False
        assert is_7z_file(tmp_path / "missing.7z") is False

    def test_parse_7z_slt_output_and_traversal_filter(self) -> None:
        sample = (
            "Listing archive: game.7z\n"
            "----------\n"
            "Path = data/level1.pak\n"
            "Size = 1048576\n"
            "Packed Size = 524288\n"
            "Attributes = A\n"
            "Encrypted = -\n"
            "Block = 0\n"
            "Offset = 0\n\n"
            "Path = ../evil.dll\n"
            "Size = 100\n"
            "Packed Size = 50\n"
            "Block = 1\n\n"
            "Path = data\n"
            "Folder = +\n"
            "Size = 0\n"
        )
        entries = parse_7z_slt_output(sample)
        assert len(entries) == 2
        assert entries[0].name == os.path.join("data", "level1.pak")
        assert entries[0].size == 1048576
        assert entries[0].packed_size == 524288
        assert entries[0].block_index == 0
        assert entries[0].is_dir is False
        assert entries[1].is_dir is True

    def test_sevenz_extract_with_mocked_7z_and_punch(self, tmp_path: Path) -> None:
        arch = tmp_path / "repack.7z"
        arch.write_bytes(SEVENZ_SIGNATURE + b"\x00" * (256 * 1024))
        out_dir = tmp_path / "out"

        slt_out = (
            "----------\n"
            "Path = bin/game.exe\n"
            "Size = 1024\n"
            "Packed Size = 131072\n"
            "Attributes = A\n"
            "Encrypted = -\n"
            "Block = 0\n"
            "Offset = 0\n\n"
        )

        ext = SevenZSparseExtractor(arch, sevenz_bin="7z")
        ext.puncher = MagicMock()
        ext.puncher.punch_hole.return_value = 131072

        saved_events: list[int] = []

        mock_proc = MagicMock()
        mock_proc.stdout = iter(["- bin/game.exe\n"])
        mock_proc.stderr = io.StringIO("")
        mock_proc.wait.return_value = 0

        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=slt_out, stderr="")), \
             patch("subprocess.Popen", return_value=mock_proc):
            count = ext.extract(
                out_dir,
                password="secret",
                on_space_saved=saved_events.append,
            )

        assert count == 1
        ext.puncher.punch_hole.assert_called_once()
        assert sum(saved_events) >= 131072
        assert not arch.exists()


class TestPasswordSupport:
    """Tests for password-protected archive preflight and extraction."""

    def test_preflight_zipcrypto_password_check(self, tmp_path: Path) -> None:
        zp = tmp_path / "secret.zip"
        _build_zipcrypto_zip(zp, "readme.txt", b"Secret game key = 12345" * 10, "hunter2")

        shield = PreflightShield()
        ok_none, errs_none = shield.verify_archive(zp)
        assert ok_none is False
        assert any("encrypted" in e.lower() for e in errs_none)

        ok_bad, errs_bad = shield.verify_archive(zp, password="wrong")
        assert ok_bad is False
        assert any("password" in e.lower() for e in errs_bad)

        ok_good, errs_good = shield.verify_archive(zp, password="hunter2")
        assert ok_good is True
        assert errs_good == []

    def test_zip_reverse_extract_zipcrypto(self, tmp_path: Path) -> None:
        zp = tmp_path / "encrypted.zip"
        payload = b"Hello encrypted zeroextract payload!\n" * 20
        _build_zipcrypto_zip(zp, "data/config.ini", payload, "pw123")
        out_dir = tmp_path / "extracted"

        bad_ext = ZipReverseExtractor(zp, password="badpw")
        with pytest.raises(ZipFormatError, match="Incorrect password"):
            bad_ext.extract(output_dir=out_dir)
        assert zp.stat().st_size > 0  # Archive untouched on bad password

        good_ext = ZipReverseExtractor(zp, password="pw123")
        saved: list[int] = []
        paths = good_ext.extract(output_dir=out_dir, on_space_saved=saved.append)
        assert len(paths) == 1
        assert (out_dir / "data" / "config.ini").read_bytes() == payload
        assert zp.stat().st_size == 0
        assert sum(saved) > 0


class TestCliAndGuiPolish:
    """Tests for CLI help string, --password, cancel/resume, and GUI helpers."""

    def test_parser_help_mentions_rar_and_7z_and_password(self) -> None:
        parser = create_parser()
        help_text = parser.format_help()
        assert ".rar" in help_text
        assert ".7z" in help_text
        assert "--password" in help_text

    def test_cancel_preserves_journal_for_resume(self, tmp_path: Path) -> None:
        zp = tmp_path / "multi.zip"
        out_dir = tmp_path / "out"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("a.txt", b"A" * 100)
            zf.writestr("b.txt", b"B" * 100)

        cancel_ev = threading.Event()
        cancel_ev.set()  # Cancel immediately before extracting first member

        ui = TerminalUI(stream=io.StringIO(), quiet=True)
        code = extract_single_archive(
            archive_path_str=str(zp),
            output_dir_str=str(out_dir),
            dry_run=False,
            no_verify=True,
            chunk_size=65536,
            min_headroom=0,
            ui=ui,
            cancel_event=cancel_ev,
        )
        assert code == 130
        assert (out_dir / ".unpack_journal.json").exists()

        # Resume without cancel_event completes cleanly
        code2 = main([str(zp), "-o", str(out_dir), "-q"])
        assert code2 == 0
        assert (out_dir / "a.txt").read_bytes() == b"A" * 100
        assert (out_dir / "b.txt").read_bytes() == b"B" * 100
        assert not (out_dir / ".unpack_journal.json").exists()

    def test_gui_helpers(self) -> None:
        assert _format_bytes_human(0) == "0 B"
        assert _format_bytes_human(1536) == "1.50 KB"
        assert _format_bytes_human(5 * 1024 * 1024) == "5.00 MB"
        assert _parse_drop_paths("{C:\\My Games\\repack.7z} D:\\other.zip") == [
            "C:\\My Games\\repack.7z",
            "D:\\other.zip",
        ]
