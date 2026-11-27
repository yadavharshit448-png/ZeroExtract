"""Command-Line Interface entry point for ZeroExtract."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import threading
import time
from typing import Callable, Sequence
import zipfile

from zeroextract import __version__
from zeroextract.cli.ui import TerminalUI
from zeroextract.cli.windows_setup import normalize_windows_path
from zeroextract.formats.multi_volume import MultiVolumeStreamer
from zeroextract.formats.rar_sparse import RarSparseExtractor, is_rar_file
from zeroextract.formats.sevenz_sparse import SevenZSparseExtractor, is_7z_file
from zeroextract.formats.zip_reverse import ZipReverseExtractor
from zeroextract.fs.headroom import HeadroomMonitor
from zeroextract.safety.atomic import AtomicWriter
from zeroextract.safety.journal import TransactionJournal
from zeroextract.safety.preverify import PreflightShield


def create_parser() -> argparse.ArgumentParser:
    """Creates the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="zeroextract",
        description="ZeroExtract: In-place zero-extra-space archive extractor.",
    )
    parser.add_argument(
        "archive",
        nargs="*",
        help="Path to archive file(s) to extract (supports .zip, .zip64, .rar, .7z, and multi-part splits).",
    )
    parser.add_argument(
        "-p",
        "--password",
        dest="password",
        default=None,
        help="Password for encrypted archives (ZIP, RAR, or 7z).",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        default=None,
        help="Target output directory for extracted files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate extraction without writing files or modifying archive.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip 0-byte preflight archive verification pass.",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1048576,
        help="Buffer and sparse deallocation chunk size in bytes (default: 1048576).",
    )
    parser.add_argument(
        "--min-headroom",
        type=int,
        default=10 * 1024 * 1024,
        help="Minimum free disk space cushion in bytes (default: 10485760).",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch interactive desktop graphical user interface.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress interactive terminal output.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed diagnostic messages.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def extract_single_archive(
    archive_path_str: str,
    output_dir_str: str | None,
    dry_run: bool,
    no_verify: bool,
    chunk_size: int,
    min_headroom: int,
    ui: TerminalUI,
    password: str | None = None,
    cancel_event: threading.Event | None = None,
    on_space_saved: Callable[[int], None] | None = None,
) -> int:
    """Executes the zero-extra-space extraction pipeline on a single archive."""
    normalized_path = normalize_windows_path(archive_path_str)
    archive_path = Path(normalized_path)

    if not archive_path.exists():
        ui.render_error(f"Archive not found: '{archive_path}'")
        return 1

    # Resolve destination directory
    if output_dir_str is not None:
        out_dir = Path(normalize_windows_path(output_dir_str)).resolve()
    else:
        out_dir = (archive_path.parent / archive_path.stem).resolve()

    # If archive was already completely extracted in-place and truncated to 0 bytes
    if archive_path.stat().st_size == 0 and out_dir.exists() and any(out_dir.iterdir()):
        ui.render_info(f"Archive '{archive_path.name}' has already been completely extracted into '{out_dir}'.")
        return 0

    # Detect multi-volume split archive or existing journal resumption
    journal_file = out_dir / ".unpack_journal.json"
    is_resumption = journal_file.exists()

    streamer = MultiVolumeStreamer(first_volume_path=str(archive_path))
    is_multi = False
    try:
        discovered = streamer.discover_volumes(str(archive_path))
        if len(discovered) > 1:
            is_multi = True
    except Exception:
        is_multi = False

    # Preflight integrity check (for full standalone archives that are not mid-resumption or multi-part)
    if not no_verify and not is_multi and not is_resumption:
        ui.render_info(f"Running 0-byte preflight verification on {archive_path.name}...")
        shield = PreflightShield(buffer_size=chunk_size)
        is_valid, errors = shield.verify_archive(archive_path, password=password)
        if not is_valid:
            err_details = "; ".join(errors)
            ui.render_error(f"Archive corruption detected in '{archive_path.name}': {err_details}")
            return 1

    is_rar = is_rar_file(archive_path)
    is_7z = is_7z_file(archive_path)

    # Dry-run simulation mode
    if dry_run:
        if is_rar:
            try:
                rar_ext = RarSparseExtractor(archive_path)
                entries = rar_ext.get_entries()
                total_uncomp = sum(e.unpacked_size for e in entries)
                member_count = len(entries)
            except Exception:
                member_count = 0
                total_uncomp = archive_path.stat().st_size
        elif is_7z:
            try:
                sevenz_ext = SevenZSparseExtractor(archive_path)
                entries = sevenz_ext.get_entries(password=password)
                total_uncomp = sum(e.size for e in entries)
                member_count = len(entries)
            except Exception:
                member_count = 0
                total_uncomp = archive_path.stat().st_size
        else:
            try:
                with zipfile.ZipFile(archive_path, "r") as zf:
                    infolist = zf.infolist()
                    total_uncomp = sum(i.file_size for i in infolist)
                    member_count = len(infolist)
            except Exception:
                member_count = 0
                total_uncomp = archive_path.stat().st_size

        ui.render_info(
            f"[Dry-Run] Archive '{archive_path.name}' verified intact. "
            f"Members: {member_count}, uncompressed payload: {total_uncomp} bytes. "
            "Zero files written, archive untouched."
        )
        return 0

    # Disk headroom verification
    monitor = HeadroomMonitor()
    target_check_dir = out_dir if out_dir.exists() else out_dir.parent
    try:
        free_space = monitor.get_free_space(target_check_dir)
        if free_space < min_headroom:
            ui.render_error(
                f"Insufficient disk headroom: free space ({free_space} bytes) "
                f"is below the required safety threshold of {min_headroom} bytes."
            )
            return 1
    except InterruptedError:
        try:
            journal.close(success=False)
        except Exception:
            pass
        ui.render_info("Extraction paused/cancelled by user. Progress saved to .unpack_journal.json for resume.")
        return 130
    except Exception as exc:
        ui.render_error(f"Headroom check failure: {exc}")
        return 1

    # Initialize destination directory
    out_dir.mkdir(parents=True, exist_ok=True)

    # Initialize Transaction Journal
    journal = TransactionJournal(archive_path, journal_path=str(journal_file))
    journal_state = journal.load_or_create()

    # Clean orphaned staging files from prior interrupted runs
    writer = AtomicWriter()
    writer.clean_stale_parts(out_dir)

    try:
        if is_rar:
            ui.render_info(f"Extracting RAR archive in-place with sparse hole-punching: {archive_path.name}...")
            rar_ext = RarSparseExtractor(archive_path)
            def rar_progress(name: str, done: int, total_unp: int, total_pk: int):
                ui.render_progress(
                    current_bytes=done,
                    total_bytes=max(1, total_unp),
                    current_member=name,
                )
            extracted_count = rar_ext.extract(
                out_dir,
                progress_cb=rar_progress,
                password=password,
                on_space_saved=on_space_saved,
                cancel_event=cancel_event,
                on_member_extracted=lambda member: journal.mark_completed(member, 0, 0),
            )
            ui.render_info(f"Successfully extracted {extracted_count} files from '{archive_path.name}' into '{out_dir}'.")
            journal.close(success=True)
            return 0
        elif is_7z:
            ui.render_info(f"Extracting 7z archive in-place with sparse hole-punching: {archive_path.name}...")
            sevenz_ext = SevenZSparseExtractor(archive_path)
            def sevenz_progress(name: str, done: int, total_unp: int, total_pk: int):
                ui.render_progress(
                    current_bytes=done,
                    total_bytes=max(1, total_unp),
                    current_member=name,
                )
            extracted_count = sevenz_ext.extract(
                out_dir,
                progress_cb=sevenz_progress,
                password=password,
                on_space_saved=on_space_saved,
                cancel_event=cancel_event,
                on_member_extracted=lambda member: journal.mark_completed(member, 0, 0),
            )
            ui.render_info(f"Successfully extracted {extracted_count} files from '{archive_path.name}' into '{out_dir}'.")
            journal.close(success=True)
            return 0
        elif is_multi:
            ui.render_info(f"Extracting multi-volume sequence ({len(streamer.volumes)} volumes)...")
            streamer.extract(
                output_dir=str(out_dir),
                on_volume_done=lambda path, idx: journal.mark_volume_unlinked(Path(path).name),
            )
        else:
            from zeroextract.formats.zip_reverse import ZipEntry
            saved_entries = journal_state.get("planned_entries", [])
            if saved_entries:
                planned_zip_entries = [
                    ZipEntry(
                        filename=d["filename"],
                        compression_method=d["compression_method"],
                        compressed_size=d["compressed_size"],
                        uncompressed_size=d["uncompressed_size"],
                        crc32=d["crc32"],
                        local_header_offset=d["local_header_offset"],
                        is_dir=d.get("is_dir", False),
                        flag_bits=d.get("flag_bits", 0),
                        mod_time=d.get("mod_time", 0),
                        mod_date=d.get("mod_date", 0),
                        external_attr=d.get("external_attr", 0),
                    )
                    for d in saved_entries
                ]
                extractor = ZipReverseExtractor(
                    str(archive_path),
                    chunk_size=chunk_size,
                    entries=planned_zip_entries,
                    password=password,
                )
                scanned = planned_zip_entries
            else:
                extractor = ZipReverseExtractor(
                    str(archive_path),
                    chunk_size=chunk_size,
                    password=password,
                )
                scanned = extractor.scan_central_directory()
                journal.set_planned_entries([
                    {
                        "filename": e.filename,
                        "compression_method": e.compression_method,
                        "compressed_size": e.compressed_size,
                        "uncompressed_size": e.uncompressed_size,
                        "crc32": e.crc32,
                        "local_header_offset": e.local_header_offset,
                        "is_dir": e.is_dir,
                        "flag_bits": e.flag_bits,
                        "mod_time": e.mod_time,
                        "mod_date": e.mod_date,
                        "external_attr": e.external_attr,
                    }
                    for e in scanned
                ])

            ui.render_info(f"Extracting '{archive_path.name}' via reverse tail-truncation + sparse hole-punching...")
            total_uncomp = sum(e.uncompressed_size for e in scanned)
            start_time = time.monotonic()
            completed_bytes = 0

            def zip_bytes_progress(chunk_delta: int, member_name: str) -> None:
                nonlocal completed_bytes
                completed_bytes += chunk_delta
                elapsed = max(0.001, time.monotonic() - start_time)
                speed = completed_bytes / elapsed
                rem = max(0, total_uncomp - completed_bytes)
                eta = (rem / speed) if speed > 0 else float("inf")
                ui.render_progress(
                    current_bytes=min(completed_bytes, max(0, total_uncomp - 1)),
                    total_bytes=max(1, total_uncomp),
                    current_member=member_name,
                    speed=speed,
                    eta=eta,
                )

            extractor.extract(
                output_dir=str(out_dir),
                on_member_extracted=lambda member: journal.mark_completed(member, 0, 0),
                on_bytes_progress=zip_bytes_progress,
                cancel_event=cancel_event,
                on_space_saved=on_space_saved,
            )
            if total_uncomp > 0:
                elapsed = max(0.001, time.monotonic() - start_time)
                ui.render_progress(
                    current_bytes=total_uncomp,
                    total_bytes=total_uncomp,
                    current_member="",
                    speed=total_uncomp / elapsed,
                    eta=0.0,
                    force=True,
                )

        # Successful completion - remove journal
        journal.close(success=True)
        ui.render_info(f"Extraction complete for '{archive_path.name}'.")
        return 0

    except InterruptedError:
        try:
            journal.close(success=False)
        except Exception:
            pass
        ui.render_info("Extraction paused/cancelled by user. Progress saved to .unpack_journal.json for resume.")
        return 130
    except Exception as exc:
        try:
            journal.close(success=False)
        except Exception:
            pass
        ui.render_error(f"Extraction failed: {exc}")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point function."""
    if argv is None:
        argv = sys.argv[1:]

    parser = create_parser()

    # Special case: no arguments provided
    if not argv:
        parser.print_usage(sys.stderr)
        sys.stderr.write("zeroextract: error: the following arguments are required: archive\n")
        return 2

    # Parse arguments
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    if getattr(args, "gui", False):
        from zeroextract.cli.gui import launch_gui
        initial_arch = args.archive[0] if args.archive else None
        return launch_gui(initial_archive=initial_arch)

    if not args.archive:
        parser.print_usage(sys.stderr)
        sys.stderr.write("zeroextract: error: the following arguments are required: archive\n")
        return 2

    if args.min_headroom < 0:
        sys.stderr.write(f"zeroextract: error: --min-headroom cannot be negative: {args.min_headroom}\n")
        return 2

    if args.chunk_size <= 0:
        sys.stderr.write(f"zeroextract: error: --chunk-size must be positive: {args.chunk_size}\n")
        return 2

    ui = TerminalUI(stream=sys.stdout, quiet=args.quiet, verbose=args.verbose)

    # Process archives in sequence
    exit_code = 0
    for arch_str in args.archive:
        code = extract_single_archive(
            archive_path_str=arch_str,
            output_dir_str=args.output_dir,
            dry_run=args.dry_run,
            no_verify=args.no_verify,
            chunk_size=args.chunk_size,
            min_headroom=args.min_headroom,
            ui=ui,
            password=args.password,
        )
        if code != 0:
            exit_code = code

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
