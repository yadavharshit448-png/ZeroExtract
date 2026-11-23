"""Unit tests for ZeroExtract CLI and Windows integration subsystem (Milestone 4)."""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from zeroextract.cli.main import create_parser, main
from zeroextract.cli.ui import TerminalUI
from zeroextract.cli.windows_setup import create_batch_launcher, normalize_windows_path


class TestWindowsSetup(unittest.TestCase):
    """Unit tests for Windows setup and path normalization."""

    def test_normalize_windows_path_quotes(self) -> None:
        raw = '"D:\\Games\\My Game.zip"'
        self.assertEqual(normalize_windows_path(raw), "D:\\Games\\My Game.zip")

    def test_normalize_windows_path_forward_slashes(self) -> None:
        raw = "D:/Games/Subfolder/game.zip"
        norm = normalize_windows_path(raw)
        self.assertNotIn("/", norm)
        self.assertIn("\\", norm)

    def test_normalize_windows_path_trailing_spaces(self) -> None:
        raw = "D:\\Games\\archive.zip   "
        self.assertEqual(normalize_windows_path(raw), "D:\\Games\\archive.zip")

    def test_normalize_windows_path_unc(self) -> None:
        raw = "\\\\nas_server\\share\\game.zip"
        self.assertTrue(normalize_windows_path(raw).startswith("\\\\"))

    def test_create_batch_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            bat_path = Path(tmp_dir) / "zeroextract.bat"
            create_batch_launcher(bat_path)
            self.assertTrue(bat_path.exists())
            text = bat_path.read_text(encoding="utf-8")
            self.assertIn("python", text.lower())
            self.assertIn("zeroextract", text.lower())


class TestTerminalUI(unittest.TestCase):
    """Unit tests for TerminalUI."""

    def test_format_throughput(self) -> None:
        ui = TerminalUI()
        self.assertIn("MB/s", ui.format_throughput(10 * 1024 * 1024))
        self.assertIn("KB/s", ui.format_throughput(500 * 1024))
        self.assertIn("GB/s", ui.format_throughput(2 * 1024 * 1024 * 1024))

    def test_format_eta(self) -> None:
        ui = TerminalUI()
        self.assertIn("01:00", ui.format_eta(60.0))
        self.assertIn("--:--", ui.format_eta(float("inf")))
        self.assertIn("--:--", ui.format_eta(-5.0))

    def test_render_error(self) -> None:
        buf = io.StringIO()
        ui = TerminalUI(stream=buf)
        ui.render_error("Critical error message")
        self.assertIn("Critical error message", buf.getvalue())


class TestCLIMain(unittest.TestCase):
    """Unit tests for CLI main."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_main_no_arguments_returns_2(self) -> None:
        code = main([])
        self.assertEqual(code, 2)

    def test_main_negative_headroom_returns_2(self) -> None:
        code = main(["game.zip", "--min-headroom", "-100"])
        self.assertEqual(code, 2)

    def test_main_non_existent_archive_returns_1(self) -> None:
        code = main([str(self.dir / "does_not_exist_404.zip")])
        self.assertEqual(code, 1)

    def test_main_dry_run_success(self) -> None:
        zip_p = self.dir / "test_dry.zip"
        with zipfile.ZipFile(zip_p, "w") as zf:
            zf.writestr("test.txt", b"Hello dry run")

        code = main([str(zip_p), "--dry-run"])
        self.assertEqual(code, 0)

    def test_main_full_extract_success(self) -> None:
        zip_p = self.dir / "test_extract.zip"
        out_p = self.dir / "output"
        with zipfile.ZipFile(zip_p, "w") as zf:
            zf.writestr("game.cfg", b"volume=100\n")

        code = main([str(zip_p), "-o", str(out_p)])
        self.assertEqual(code, 0)
        self.assertTrue((out_p / "game.cfg").exists())


if __name__ == "__main__":
    unittest.main()
