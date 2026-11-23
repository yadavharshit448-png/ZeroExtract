"""Command-Line Interface entry point for ZeroExtract."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Sequence
import zipfile

from zeroextract import __version__
from zeroextract.cli.ui import TerminalUI
from zeroextract.cli.windows_setup import normalize_windows_path
from zeroextract.formats.multi_volume import MultiVolumeStreamer
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
        help="Path to archive file(s) to extract (supports .zip, .zip64, multi-part splits).",
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
        default=50 * 1024 * 1024,
        help="Minimum free disk space cushion in bytes (default: 52428800).",
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
        is_valid, errors = shield.verify_archive(archive_path)
        if not is_valid:
            err_details = "; ".join(errors)
            ui.render_error(f"Archive corruption detected in '{archive_path.name}': {err_details}")
            return 1

    # Dry-run simulation mode
    if dry_run:
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
        if is_multi:
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
                extractor = ZipReverseExtractor(str(archive_path), chunk_size=chunk_size, entries=planned_zip_entries)
            else:
                extractor = ZipReverseExtractor(str(archive_path), chunk_size=chunk_size)
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

            ui.render_info(f"Extracting '{archive_path.name}' via reverse tail-truncation...")
            extractor.extract(
                output_dir=str(out_dir),
                on_member_extracted=lambda member: journal.mark_completed(member, 0, 0),
            )

        # Successful completion - remove journal
        journal.close(success=True)
        ui.render_info(f"Extraction complete for '{archive_path.name}'.")
        return 0

    except Exception as exc:
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
        )
        if code != 0:
            exit_code = code

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
