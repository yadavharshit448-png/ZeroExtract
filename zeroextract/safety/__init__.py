"""Safety and transaction subsystem for ZeroExtract.

Provides:
- ChecksumError, CorruptionError, CorruptionGuard: Archive integrity and security validation.
- PreflightShield: Zero-byte pre-verification pass ensuring archive integrity before extraction.
- AtomicWriter: Two-phase commit atomic file writing with .unpack_part staging.
- TransactionJournal: Crash-safe transaction journal tracking extraction progress and volume unlinking.
"""

from __future__ import annotations

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

__all__ = [
    "SafetyError",
    "ChecksumError",
    "CorruptionError",
    "PathTraversalError",
    "CorruptionGuard",
    "PreflightShield",
    "AtomicWriter",
    "TransactionJournal",
]
