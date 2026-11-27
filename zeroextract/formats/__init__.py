"""Archive formats and in-place extraction engine subsystem for ZeroExtract.

Provides:
- ZipReverseExtractor: Central Directory parsing and tail-to-head reverse extraction.
- MultiVolumeStreamer & MultiVolumeStreamReader: Multi-part archive sequence streaming.
- ChunkedSparseExtractor: 64KB-aligned NTFS sparse hole-punching for massive stream entries.
"""

from __future__ import annotations

from zeroextract.formats.chunked_sparse import ChunkedSparseExtractor
from zeroextract.formats.multi_volume import (
    MultiVolumeStreamer,
    MultiVolumeStreamReader,
    VolumeInfo,
)
from zeroextract.formats.rar_sparse import (
    RarFileEntry,
    RarSparseExtractor,
    is_rar_file,
)
from zeroextract.formats.sevenz_sparse import (
    SevenZFileEntry,
    SevenZSparseExtractor,
    is_7z_file,
)
from zeroextract.formats.zip_reverse import (
    BadZipSignatureError,
    ChecksumError,
    CorruptArchiveError,
    PathTraversalError,
    UnsupportedCompressionError,
    ZipEntry,
    ZipFormatError,
    ZipReverseExtractor,
)

__all__ = [
    "ZipReverseExtractor",
    "ZipEntry",
    "ZipFormatError",
    "BadZipSignatureError",
    "CorruptArchiveError",
    "ChecksumError",
    "UnsupportedCompressionError",
    "PathTraversalError",
    "MultiVolumeStreamer",
    "MultiVolumeStreamReader",
    "VolumeInfo",
    "ChunkedSparseExtractor",
    "RarSparseExtractor",
    "is_rar_file",
    "RarFileEntry",
    "SevenZSparseExtractor",
    "is_7z_file",
    "SevenZFileEntry",
]
