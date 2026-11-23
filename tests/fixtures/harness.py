"""Test Execution and Verification Harness for ZeroExtract.

Provides opaque-box CLI execution, Windows filesystem inspection (sparse support,
allocated disk size, sparse attributes), crash simulation (power-cut testing),
and comprehensive extracted content verification.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence
import zlib

if sys.platform == "win32":
    from ctypes import wintypes
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
else:
    _kernel32 = None  # type: ignore

# Windows constants
FILE_SUPPORTS_SPARSE_FILES = 0x00000040
FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
INVALID_FILE_SIZE = 0xFFFFFFFF
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class CLIResult:
    """Outcome of a CLI execution invocation."""
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    cmd: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """True if process exited with code 0."""
        return self.exit_code == 0

    def __iter__(self):
        """Allows unpacking: exit_code, stdout, stderr = result."""
        return iter((self.exit_code, self.stdout, self.stderr))

    def __repr__(self) -> str:
        return (
            f"CLIResult(exit_code={self.exit_code}, duration={self.duration:.2f}s, "
            f"stdout_len={len(self.stdout)}, stderr_len={len(self.stderr)})"
        )


@dataclass
class VerificationResult:
    """Outcome of verifying an extracted directory against expected files."""
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    verified_files: list[str] = field(default_factory=list)
    missing_files: list[str] = field(default_factory=list)
    corrupted_files: list[str] = field(default_factory=list)
    leftover_temp_files: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        """Truthy if verification passed with no errors."""
        return self.is_valid

    def __iter__(self):
        """Allows unpacking: is_valid, errors = result."""
        return iter((self.is_valid, self.errors))

    def __repr__(self) -> str:
        status = "PASSED" if self.is_valid else f"FAILED({len(self.errors)} errors)"
        return (
            f"VerificationResult({status}, verified={len(self.verified_files)}, "
            f"missing={len(self.missing_files)}, corrupt={len(self.corrupted_files)}, "
            f"temp_leftover={len(self.leftover_temp_files)})"
        )


def _resolve_cli_command(args: Sequence[str] | str) -> list[str]:
    """Resolve CLI arguments into an executable command line list."""
    if isinstance(args, str):
        parsed_args = shlex.split(args, posix=(sys.platform != "win32"))
    else:
        parsed_args = list(args)

    # If already fully specified python command, return as is
    if parsed_args and (parsed_args[0] == sys.executable or parsed_args[0].lower().endswith("python.exe")):
        return parsed_args

    run_script = WORKSPACE_ROOT / "run_zeroextract.py"
    if run_script.exists():
        return [sys.executable, str(run_script)] + parsed_args

    # Fallback to module execution: python -m zeroextract
    return [sys.executable, "-m", "zeroextract"] + parsed_args


def run_cli(
    args: Sequence[str] | str,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 60.0,
) -> CLIResult:
    """Execute the ZeroExtract CLI in a subprocess and capture results.

    Args:
        args: Command-line arguments to pass to ZeroExtract.
        cwd: Working directory (defaults to WORKSPACE_ROOT).
        env: Environment variables (merged with current environment).
        timeout: Subprocess timeout in seconds (default 60s).

    Returns:
        CLIResult containing exit_code, stdout, stderr, and duration.
    """
    cmd = _resolve_cli_command(args)
    working_dir = Path(cwd) if cwd is not None else WORKSPACE_ROOT

    exec_env = os.environ.copy()
    exec_env["PYTHONUNBUFFERED"] = "1"
    # Ensure WORKSPACE_ROOT is on PYTHONPATH for child process
    existing_pythonpath = exec_env.get("PYTHONPATH", "")
    exec_env["PYTHONPATH"] = (
        f"{WORKSPACE_ROOT}{os.pathsep}{existing_pythonpath}"
        if existing_pythonpath
        else str(WORKSPACE_ROOT)
    )
    if env is not None:
        exec_env.update(env)

    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(working_dir),
            env=exec_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        duration = time.time() - start_time
        return CLIResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration=duration,
            cmd=cmd,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.time() - start_time
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CLIResult(
            exit_code=-9,
            stdout=stdout,
            stderr=stderr + f"\n[Harness] Execution timed out after {timeout}s",
            duration=duration,
            cmd=cmd,
        )


def is_sparse_supported(volume_path: str | Path = "D:\\") -> bool:
    """Check if the filesystem volume hosting volume_path supports sparse files.

    Uses Windows GetVolumeInformationW and checks for FILE_SUPPORTS_SPARSE_FILES (0x40).
    On non-Windows systems, returns False.

    Args:
        volume_path: Path to volume root or any file/dir on the volume.

    Returns:
        True if sparse files are supported by the filesystem, False otherwise.
    """
    if sys.platform != "win32" or _kernel32 is None:
        return False

    abs_path = os.path.abspath(str(volume_path))
    drive, _ = os.path.splitdrive(abs_path)
    root_path = f"{drive}\\" if drive else abs_path

    vol_name = ctypes.create_unicode_buffer(260)
    fs_name = ctypes.create_unicode_buffer(260)
    serial_number = wintypes.DWORD()
    max_component_len = wintypes.DWORD()
    fs_flags = wintypes.DWORD()

    ret = _kernel32.GetVolumeInformationW(
        root_path,
        vol_name,
        ctypes.sizeof(vol_name),
        ctypes.byref(serial_number),
        ctypes.byref(max_component_len),
        ctypes.byref(fs_flags),
        fs_name,
        ctypes.sizeof(fs_name),
    )

    if not ret:
        return False

    return bool(fs_flags.value & FILE_SUPPORTS_SPARSE_FILES)


def get_allocated_file_size(file_path: str | Path) -> int:
    """Get the physical on-disk allocated byte size of a file.

    On Windows, calls GetCompressedFileSizeW (which returns cluster-allocated size,
    taking into account sparse holes and NTFS compression).
    On POSIX systems, uses stat.st_blocks * 512.

    Args:
        file_path: Path to file.

    Returns:
        Number of physical bytes allocated on disk.
    """
    resolved = Path(file_path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")

    if sys.platform == "win32" and _kernel32 is not None:
        high_order = wintypes.DWORD(0)
        low_order = _kernel32.GetCompressedFileSizeW(str(resolved), ctypes.byref(high_order))
        if low_order == INVALID_FILE_SIZE:
            err = ctypes.get_last_error()
            if err != 0:
                raise ctypes.WinError(err)
        return (high_order.value << 32) | low_order

    # Non-Windows POSIX fallback
    stat_info = resolved.stat()
    if hasattr(stat_info, "st_blocks"):
        return stat_info.st_blocks * 512
    return stat_info.st_size


def is_file_sparse(file_path: str | Path) -> bool:
    """Check whether a file has the FILE_ATTRIBUTE_SPARSE_FILE (0x200) attribute.

    Args:
        file_path: Path to file.

    Returns:
        True if the file is marked as sparse, False otherwise.
    """
    resolved = Path(file_path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")

    if sys.platform == "win32" and _kernel32 is not None:
        attrs = _kernel32.GetFileAttributesW(str(resolved))
        if attrs == INVALID_FILE_ATTRIBUTES:
            err = ctypes.get_last_error()
            raise ctypes.WinError(err)
        return bool(attrs & FILE_ATTRIBUTE_SPARSE_FILE)

    # Non-Windows heuristic: allocated size is strictly less than logical size
    try:
        return get_allocated_file_size(resolved) < resolved.stat().st_size
    except Exception:
        return False


def simulate_power_cut_extraction(
    args: Sequence[str] | str,
    cut_after_seconds: float = 0.5,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CLIResult:
    """Launch an extraction process and forcibly kill it midway to simulate a crash/power cut.

    Used to test transaction journal integrity and crash-recovery resumption.

    Args:
        args: Extraction command arguments.
        cut_after_seconds: Seconds to allow extraction to run before process termination.
        cwd: Working directory.
        env: Environment mapping.

    Returns:
        CLIResult representing the terminated process state.
    """
    cmd = _resolve_cli_command(args)
    working_dir = Path(cwd) if cwd is not None else WORKSPACE_ROOT

    exec_env = os.environ.copy()
    exec_env["PYTHONUNBUFFERED"] = "1"
    existing_pythonpath = exec_env.get("PYTHONPATH", "")
    exec_env["PYTHONPATH"] = (
        f"{WORKSPACE_ROOT}{os.pathsep}{existing_pythonpath}"
        if existing_pythonpath
        else str(WORKSPACE_ROOT)
    )
    if env is not None:
        exec_env.update(env)

    start_time = time.time()
    proc = subprocess.Popen(
        cmd,
        cwd=str(working_dir),
        env=exec_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Let extraction execute up to cut_after_seconds
    time.sleep(cut_after_seconds)

    # Hard kill process and any child processes
    if sys.platform == "win32":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except Exception:
            pass

    proc.kill()
    stdout, stderr = proc.communicate()
    duration = time.time() - start_time

    return CLIResult(
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        duration=duration,
        cmd=cmd,
    )


def verify_directory_contents(
    extracted_dir: str | Path,
    expected_files_dict: Mapping[str, Any],
    check_no_temp_files: bool = True,
) -> VerificationResult:
    """Verify that an extracted directory contains all expected files with matching checksums.

    Args:
        extracted_dir: Directory containing extracted files.
        expected_files_dict: Mapping of relative paths to expected content (bytes/str)
                             or metadata dict containing 'size', 'sha256', and/or 'crc32'.
        check_no_temp_files: If True, checks that no temporary files (.unpack_part, .tmp) remain.

    Returns:
        VerificationResult with is_valid=True if all files match perfectly, False otherwise.
    """
    target_dir = Path(extracted_dir).resolve()
    errors: list[str] = []
    verified_files: list[str] = []
    missing_files: list[str] = []
    corrupted_files: list[str] = []
    leftover_temp_files: list[str] = []

    if not target_dir.exists() or not target_dir.is_dir():
        errors.append(f"Extracted directory does not exist or is not a directory: {target_dir}")
        return VerificationResult(
            is_valid=False,
            errors=errors,
            missing_files=list(expected_files_dict.keys()),
        )

    for rel_path, expected_val in expected_files_dict.items():
        # Normalize relative path for current OS
        normalized_rel = rel_path.replace("/", os.sep).replace("\\", os.sep)
        full_path = target_dir / normalized_rel

        # Directory entries (ending with slash or empty directories)
        if rel_path.endswith("/") or rel_path.endswith("\\"):
            if not full_path.exists() or not full_path.is_dir():
                errors.append(f"Expected directory missing: {rel_path}")
                missing_files.append(rel_path)
            else:
                verified_files.append(rel_path)
            continue

        if not full_path.exists():
            errors.append(f"Expected file missing: {rel_path} (looked at {full_path})")
            missing_files.append(rel_path)
            continue

        # Check content / checksum
        try:
            actual_data = full_path.read_bytes()
            actual_size = len(actual_data)
            actual_sha256 = hashlib.sha256(actual_data).hexdigest()
            actual_crc32 = zlib.crc32(actual_data) & 0xFFFFFFFF

            if isinstance(expected_val, (bytes, str)):
                expected_bytes = (
                    expected_val if isinstance(expected_val, bytes) else expected_val.encode("utf-8")
                )
                expected_size = len(expected_bytes)
                if actual_size != expected_size:
                    errors.append(
                        f"Size mismatch in {rel_path}: expected {expected_size} bytes, got {actual_size}"
                    )
                    corrupted_files.append(rel_path)
                    continue

                expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()
                if actual_sha256 != expected_sha256:
                    errors.append(
                        f"SHA256 mismatch in {rel_path}: expected {expected_sha256}, got {actual_sha256}"
                    )
                    corrupted_files.append(rel_path)
                    continue

            elif isinstance(expected_val, dict):
                exp_size = expected_val.get("size")
                if exp_size is not None and actual_size != exp_size:
                    errors.append(
                        f"Size mismatch in {rel_path}: expected {exp_size} bytes, got {actual_size}"
                    )
                    corrupted_files.append(rel_path)
                    continue

                exp_sha = expected_val.get("sha256")
                if exp_sha is not None and actual_sha256.lower() != exp_sha.lower():
                    errors.append(
                        f"SHA256 mismatch in {rel_path}: expected {exp_sha}, got {actual_sha256}"
                    )
                    corrupted_files.append(rel_path)
                    continue

                exp_crc = expected_val.get("crc32")
                if exp_crc is not None and actual_crc32 != exp_crc:
                    errors.append(
                        f"CRC32 mismatch in {rel_path}: expected {exp_crc:#010x}, got {actual_crc32:#010x}"
                    )
                    corrupted_files.append(rel_path)
                    continue

            verified_files.append(rel_path)

        except Exception as exc:
            errors.append(f"Error reading {rel_path}: {exc}")
            corrupted_files.append(rel_path)

    # Check for leftover temporary staging files
    if check_no_temp_files and target_dir.exists():
        temp_suffixes = {".unpack_part", ".unpack_tmp", ".tmp", ".part"}
        for root, _, files in os.walk(target_dir):
            for f in files:
                f_path = Path(root) / f
                if f_path.suffix.lower() in temp_suffixes or f.startswith(".unpack_"):
                    rel_temp = str(f_path.relative_to(target_dir))
                    leftover_temp_files.append(rel_temp)
                    errors.append(f"Found leftover temporary file on disk: {rel_temp}")

    is_valid = len(errors) == 0
    return VerificationResult(
        is_valid=is_valid,
        errors=errors,
        verified_files=verified_files,
        missing_files=missing_files,
        corrupted_files=corrupted_files,
        leftover_temp_files=leftover_temp_files,
    )
