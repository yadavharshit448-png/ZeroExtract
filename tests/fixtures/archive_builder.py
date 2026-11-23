"""Synthetic Archive Builder Fixtures for ZeroExtract Testing.

Generates genuine, standards-compliant archive variations:
- Simple ZIP (DEFLATE / STORE)
- ZIP64 archives with 64-bit headers
- Multi-part split volume ZIP archives (.z01, .z02, ... .zip and .zip.001, ...)
- Corrupted archives (bad CRC, truncated, corrupted Central Directory, bad headers)
- Sparse payload archives (virtual gigabyte payloads in minimal disk space)
- Complex tree archives (deep nesting, unicode filenames, empty dirs, mixed compression)
"""

from __future__ import annotations

import hashlib
import io
import math
import os
from pathlib import Path
import struct
from typing import Any, Mapping, Sequence
import zipfile
import zlib


def _normalize_entry_content(content: Any) -> bytes:
    """Normalize input content to bytes."""
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, int):
        # Generate dummy content of the specified byte length
        if content <= 0:
            return b""
        pattern = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        repeats = (content // len(pattern)) + 1
        return (pattern * repeats)[:content]
    raise TypeError(f"Unsupported content type: {type(content).__name__}")


def calculate_expected_hashes(file_dict: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Calculate expected size, SHA256 hex digest, and CRC32 integer for entries.

    Args:
        file_dict: Mapping of relative path to bytes, str, or int length.

    Returns:
        Dict mapping relative path to {"size": int, "sha256": str, "crc32": int}.
    """
    hashes: dict[str, dict[str, Any]] = {}
    for name, content in file_dict.items():
        data = _normalize_entry_content(content)
        sha256 = hashlib.sha256(data).hexdigest()
        crc32 = zlib.crc32(data) & 0xFFFFFFFF
        hashes[name] = {
            "size": len(data),
            "sha256": sha256,
            "crc32": crc32,
        }
    return hashes


def create_simple_zip(
    target_path: str | Path,
    file_dict: Mapping[str, Any],
    compression: int = zipfile.ZIP_DEFLATED,
    comment: bytes = b"ZeroExtract Test Simple Archive",
) -> Path:
    """Create a standard valid ZIP archive containing specified entries.

    Args:
        target_path: Destination zip file path.
        file_dict: Mapping of relative file path in archive to content (bytes/str/int).
        compression: zipfile compression algorithm (default ZIP_DEFLATED).
        comment: Archive-level comment bytes.

    Returns:
        Path to the created ZIP file.
    """
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(target, "w", compression=compression) as zf:
        zf.comment = comment
        for rel_path, content in file_dict.items():
            data = _normalize_entry_content(content)
            # Use forward slashes per ZIP specification
            zip_entry_name = rel_path.replace("\\", "/")
            zinfo = zipfile.ZipInfo(zip_entry_name, date_time=(2026, 1, 1, 12, 0, 0))
            zinfo.compress_type = compression
            zinfo.external_attr = 0o644 << 16
            zf.writestr(zinfo, data)

    return target


def create_zip64(
    target_path: str | Path,
    file_dict: Mapping[str, Any],
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    """Create a genuine ZIP64 archive with 64-bit headers and locator records.

    Ensures that ZIP64 End of Central Directory (PK\x06\x06) and ZIP64 End of Central
    Directory Locator (PK\x06\x07) records are present, complying with ZIP64 specification.

    Args:
        target_path: Destination zip file path.
        file_dict: Mapping of relative file path in archive to content.
        compression: Compression algorithm.

    Returns:
        Path to the created ZIP64 file.
    """
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    # Step 1: Write initial ZIP with force_zip64 on individual entry streams
    with zipfile.ZipFile(target, "w", compression=compression) as zf:
        zf.comment = b"ZeroExtract ZIP64 Test Archive"
        for rel_path, content in file_dict.items():
            data = _normalize_entry_content(content)
            zip_entry_name = rel_path.replace("\\", "/")
            zinfo = zipfile.ZipInfo(zip_entry_name, date_time=(2026, 1, 1, 12, 0, 0))
            zinfo.compress_type = compression
            zinfo.external_attr = 0o644 << 16
            with zf.open(zinfo, "w", force_zip64=True) as entry_stream:
                entry_stream.write(data)

    # Step 2: Inject ZIP64 End of Central Directory Record and Locator if not already written
    raw = bytearray(target.read_bytes())
    if b"PK\x06\x06" not in raw:
        eocd_pos = raw.rfind(b"PK\x05\x06")
        if eocd_pos != -1:
            cent_dir_data = raw[:eocd_pos]
            eocd = raw[eocd_pos:]
            (
                _,
                disk_no,
                cd_disk,
                cd_entries_disk,
                cd_entries_tot,
                cd_size,
                cd_offset,
                comment_len,
            ) = struct.unpack("<4s4H2LH", eocd[:22])

            zip64_end = struct.pack(
                zipfile.structEndArchive64,
                zipfile.stringEndArchive64,
                44,  # size of remaining record
                45,  # version made by
                45,  # version needed
                0,   # disk no
                0,   # disk with start of CD
                cd_entries_tot,
                cd_entries_tot,
                cd_size,
                cd_offset,
            )
            zip64_loc = struct.pack(
                zipfile.structEndArchive64Locator,
                zipfile.stringEndArchive64Locator,
                0,         # disk with zip64 EOCD
                eocd_pos,  # offset of zip64 EOCD
                1,         # total disks
            )
            new_eocd = (
                struct.pack(
                    "<4s4H2LH",
                    b"PK\x05\x06",
                    0xFFFF,
                    0xFFFF,
                    0xFFFF,
                    0xFFFF,
                    0xFFFFFFFF,
                    0xFFFFFFFF,
                    comment_len,
                )
                + eocd[22:]
            )
            target.write_bytes(cent_dir_data + zip64_end + zip64_loc + new_eocd)

    return target


def create_multi_part_zip(
    base_path: str | Path,
    file_dict: Mapping[str, Any],
    max_volume_size: int = 65536,
    split_format: str = "pkware",
    compression: int = zipfile.ZIP_DEFLATED,
) -> list[Path]:
    """Create a multi-part split volume ZIP archive.

    Supported split formats:
    - 'pkware' (default): .z01, .z02, ... .zip (where the final volume has .zip extension)
    - 'numbered': .zip.001, .zip.002, ... .zip.NNN

    Args:
        base_path: Destination base path (e.g. 'archive.zip').
        file_dict: Mapping of relative paths to entry contents.
        max_volume_size: Maximum volume slice size in bytes (default 64KB).
        split_format: Split volume naming scheme ('pkware' or 'numbered').
        compression: Compression type.

    Returns:
        List of Path objects for all created volume parts in sequential order.
    """
    base = Path(base_path)
    base.parent.mkdir(parents=True, exist_ok=True)

    # 1. Build the complete single-stream ZIP in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for rel_path, content in file_dict.items():
            data = _normalize_entry_content(content)
            zip_entry_name = rel_path.replace("\\", "/")
            zinfo = zipfile.ZipInfo(zip_entry_name, date_time=(2026, 1, 1, 12, 0, 0))
            zinfo.compress_type = compression
            zf.writestr(zinfo, data)

    full_payload = buf.getvalue()
    total_len = len(full_payload)

    # If payload fits in single volume, write single file
    if total_len <= max_volume_size:
        base.write_bytes(full_payload)
        return [base]

    num_parts = math.ceil(total_len / max_volume_size)
    volumes: list[Path] = []
    base_stem = base.stem if base.suffix.lower() == ".zip" else base.name

    for idx in range(num_parts):
        start_offset = idx * max_volume_size
        end_offset = min(start_offset + max_volume_size, total_len)
        slice_data = full_payload[start_offset:end_offset]

        if split_format.lower() == "pkware":
            # For PKWARE spanned archives:
            # Parts 0 to N-2: .z01, .z02, ...
            # Final part N-1: .zip
            if idx == num_parts - 1:
                vol_path = base.parent / f"{base_stem}.zip"
            else:
                vol_path = base.parent / f"{base_stem}.z{idx + 1:02d}"
        elif split_format.lower() == "numbered":
            vol_path = base.parent / f"{base.name}.{idx + 1:03d}"
        else:
            raise ValueError(f"Unsupported split_format: {split_format}")

        vol_path.write_bytes(slice_data)
        volumes.append(vol_path)

    return volumes


def create_corrupt_zip(
    target_path: str | Path,
    corruption_type: str = "bad_crc",
    file_dict: Mapping[str, Any] | None = None,
) -> Path:
    """Create an archive with intentional corruption to test safety shields.

    Supported corruption_type:
    - 'bad_crc': Modifies compressed payload so decompression CRC32 validation fails.
    - 'truncated': Truncates archive midway, leaving incomplete file or missing Central Directory.
    - 'bad_cd': Corrupts Central Directory signature (PK\x01\x02) and EOCD pointers.
    - 'bad_local_header': Overwrites local file header signature (PK\x03\x04).
    - 'missing_eocd': Removes the End of Central Directory record completely.

    Args:
        target_path: Destination zip file path.
        corruption_type: Type of corruption to inject.
        file_dict: Optional file mapping (defaults to multi-file test payload).

    Returns:
        Path to the corrupted archive.
    """
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    if file_dict is None:
        file_dict = {
            "game_main.exe": b"BINARY_EXECUTABLE_HEADER_PADDING_" * 50,
            "data/textures.pak": b"COMPRESSED_TEXTURE_DATA_BLOCK_" * 100,
            "config.json": b'{"version": "1.0", "title": "ZeroExtract Corrupt Test"}\n',
        }

    # Step 1: Create a valid ZIP
    create_simple_zip(target, file_dict)
    data = bytearray(target.read_bytes())

    corruption = corruption_type.lower()

    if corruption == "bad_crc":
        # Modify the CRC32 field in both Local File Header (offset +14)
        # and Central Directory Header (offset +16) for the target entry
        loc_hdr = data.find(b"PK\x03\x04")
        if loc_hdr != -1:
            orig_crc = struct.unpack_from("<I", data, loc_hdr + 14)[0]
            bad_crc = orig_crc ^ 0xFFFFFFFF
            struct.pack_into("<I", data, loc_hdr + 14, bad_crc)

        cd_hdr = data.find(b"PK\x01\x02")
        if cd_hdr != -1:
            orig_crc = struct.unpack_from("<I", data, cd_hdr + 16)[0]
            bad_crc = orig_crc ^ 0xFFFFFFFF
            struct.pack_into("<I", data, cd_hdr + 16, bad_crc)

    elif corruption == "truncated":
        # Cut off archive at 40% length, ensuring incomplete stream
        cut_len = max(len(data) // 2, 20)
        data = data[:cut_len]

    elif corruption == "bad_cd":
        # Corrupt Central Directory signature (PK\x01\x02 -> XX\x01\x02)
        cd_pos = data.find(b"PK\x01\x02")
        while cd_pos != -1:
            data[cd_pos : cd_pos + 2] = b"XX"
            cd_pos = data.find(b"PK\x01\x02", cd_pos + 4)

        # Also corrupt EOCD pointer if present
        eocd_pos = data.rfind(b"PK\x05\x06")
        if eocd_pos != -1 and eocd_pos + 20 <= len(data):
            # Overwrite offset of start of central directory with bogus offset
            struct.pack_into("<I", data, eocd_pos + 16, 0x7FFFFFFF)

    elif corruption == "bad_local_header":
        # Overwrite PK\x03\x04 signature
        loc_hdr = data.find(b"PK\x03\x04")
        if loc_hdr != -1:
            data[loc_hdr : loc_hdr + 4] = b"BAD!"

    elif corruption == "missing_eocd":
        # Find EOCD (PK\x05\x06) and cut file right before it
        eocd_pos = data.rfind(b"PK\x05\x06")
        if eocd_pos != -1:
            data = data[:eocd_pos]
        else:
            data = data[:-22]

    else:
        raise ValueError(f"Unknown corruption_type: {corruption_type}")

    target.write_bytes(data)
    return target


def create_sparse_payload_zip(
    target_path: str | Path,
    target_virtual_size_bytes: int,
    chunk_size: int = 1048576,
    filename: str = "sparse_game_data.bin",
    sparse_marker_interval: int = 10485760,  # 10MB
) -> Path:
    """Create an archive containing a large virtual file that compresses to minimal disk space.

    Simulates multi-gigabyte sparse game data (e.g. 1GB, 10GB, 50GB) using highly compressible
    sparse patterns (header, repeating null blocks, periodic markers, footer).

    Args:
        target_path: Destination zip file path.
        target_virtual_size_bytes: Total uncompressed virtual size in bytes.
        chunk_size: Block size for compression streaming (default 1MB).
        filename: Name of the virtual sparse file inside the archive.
        sparse_marker_interval: Interval between non-zero markers to verify offset integrity.

    Returns:
        Path to the created ZIP file.
    """
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    header_magic = f"ZEROEXTRACT_SPARSE_V1:SIZE={target_virtual_size_bytes}\n".encode("utf-8")
    header_block = header_magic + b"\x00" * max(0, 4096 - len(header_magic))

    footer_magic = b"\nZEROEXTRACT_SPARSE_V1:EOF\n"
    footer_block = b"\x00" * max(0, 4096 - len(footer_magic)) + footer_magic

    # Use ZIP_DEFLATED with fast compression level
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
        zinfo = zipfile.ZipInfo(filename, date_time=(2026, 1, 1, 12, 0, 0))
        zinfo.compress_type = zipfile.ZIP_DEFLATED
        zinfo.external_attr = 0o644 << 16

        with zf.open(zinfo, "w", force_zip64=True) as entry_stream:
            bytes_written = 0

            # Write header block if space permits
            if target_virtual_size_bytes <= len(header_block) + len(footer_block):
                # Small edge case: write exact length
                entry_stream.write(b"\x00" * target_virtual_size_bytes)
                bytes_written = target_virtual_size_bytes
            else:
                entry_stream.write(header_block)
                bytes_written += len(header_block)

                middle_bytes = target_virtual_size_bytes - len(header_block) - len(footer_block)
                null_chunk = b"\x00" * chunk_size

                while middle_bytes > 0:
                    current_chunk_size = min(middle_bytes, chunk_size)
                    # Periodic marker to test integrity without losing high compressibility
                    if bytes_written % sparse_marker_interval < current_chunk_size:
                        marker = f"[MK@{bytes_written:012d}]".encode("ascii")
                        chunk = marker + b"\x00" * (current_chunk_size - len(marker))
                    else:
                        chunk = null_chunk[:current_chunk_size]

                    entry_stream.write(chunk)
                    bytes_written += current_chunk_size
                    middle_bytes -= current_chunk_size

                entry_stream.write(footer_block)
                bytes_written += len(footer_block)

    return target


def create_complex_tree_zip(
    target_path: str | Path,
    depth: int = 10,
    files_per_level: int = 3,
    include_empty_dirs: bool = True,
    include_unicode: bool = True,
    file_size: int = 128,
) -> tuple[Path, dict[str, bytes]]:
    """Create an archive with a deep nested directory structure and varied entry types.

    Features:
    - Deep directory nesting up to `depth` levels
    - Multiple files per level
    - Optional empty directories
    - Unicode characters, spaces, and special symbols in filenames
    - Mixed compression methods (ZIP_STORED and ZIP_DEFLATED)
    - 0-byte files and binary data files

    Args:
        target_path: Destination zip file path.
        depth: Hierarchy depth level (e.g. 10).
        files_per_level: Number of files per directory level (e.g. 3).
        include_empty_dirs: Whether to generate explicit directory entries.
        include_unicode: Whether to include emojis, non-ASCII, and special chars.
        file_size: Base size for generated content files.

    Returns:
        Tuple of (target_path, file_dict) where file_dict maps archive relative path to bytes.
    """
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    file_dict: dict[str, bytes] = {}
    current_dir_parts: list[str] = ["game_root"]

    unicode_names = [
        "🎮_savedata_日本語.sav",
        "текст_локализации.cfg",
        "audio_é_à_music [ambient].ogg",
        "shader_fx (v2.0) #1.bin",
        "level_dünya_küre.dat",
    ]

    with zipfile.ZipFile(target, "w") as zf:
        # Root level files
        file_dict["game.exe"] = b"MZ_GAME_BINARY_ROOT_EXECUTABLE_MAGIC_PADDING_" * 4
        file_dict["license.txt"] = b"ZeroExtract Test Game License Agreement.\nAll rights reserved.\n"
        file_dict["zero_byte.dat"] = b""

        # Write root files
        for name, data in file_dict.items():
            zinfo = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 12, 0, 0))
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zinfo, data)

        # Generate nested levels
        for level in range(1, depth + 1):
            level_dir_name = f"sub_level_{level:02d}"
            current_dir_parts.append(level_dir_name)
            current_prefix = "/".join(current_dir_parts) + "/"

            if include_empty_dirs:
                # Add an explicit empty directory entry
                empty_dir_path = f"{current_prefix}empty_folder/"
                zinfo = zipfile.ZipInfo(empty_dir_path, date_time=(2026, 1, 1, 12, 0, 0))
                zinfo.external_attr = 0o755 << 16 | 0x10  # Directory attribute
                zf.writestr(zinfo, b"")

            for f_idx in range(files_per_level):
                if include_unicode and f_idx < len(unicode_names):
                    fname = f"level_{level:02d}_{unicode_names[f_idx]}"
                else:
                    fname = f"level_{level:02d}_resource_{f_idx:02d}.bin"

                rel_path = f"{current_prefix}{fname}"
                content = f"Payload at level {level}, file {f_idx}: ".encode("utf-8") + (
                    b"X" * max(0, file_size - 30)
                )

                file_dict[rel_path] = content

                zinfo = zipfile.ZipInfo(rel_path, date_time=(2026, 1, 1, 12, 0, 0))
                # Alternate compression algorithms between STORED and DEFLATED
                if (level + f_idx) % 2 == 0:
                    zinfo.compress_type = zipfile.ZIP_DEFLATED
                else:
                    zinfo.compress_type = zipfile.ZIP_STORED

                zf.writestr(zinfo, content)

    return target, file_dict


def inspect_zip_structure(zip_path: str | Path) -> dict[str, Any]:
    """Inspect and report structural properties of a ZIP archive.

    Returns:
        Dict with keys: 'file_count', 'total_uncompressed_size',
        'total_compressed_size', 'is_zip64', 'comment', 'entry_names'.
    """
    path = Path(zip_path)
    if not path.exists():
        raise FileNotFoundError(f"Archive not found: {path}")

    with zipfile.ZipFile(path, "r") as zf:
        infolist = zf.infolist()
        total_uncompressed = sum(info.file_size for info in infolist)
        total_compressed = sum(info.compress_size for info in infolist)

        # Check for ZIP64 signatures in file bytes
        raw_bytes = path.read_bytes()
        is_zip64 = (b"PK\x06\x06" in raw_bytes) or (b"PK\x06\x07" in raw_bytes)

        return {
            "file_count": len(infolist),
            "total_uncompressed_size": total_uncompressed,
            "total_compressed_size": total_compressed,
            "is_zip64": is_zip64,
            "comment": zf.comment,
            "entry_names": [info.filename for info in infolist],
        }
