"""Test fixtures package for ZeroExtract E2E and integration tests."""

from tests.fixtures.archive_builder import (
    create_simple_zip,
    create_zip64,
    create_multi_part_zip,
    create_corrupt_zip,
    create_sparse_payload_zip,
    create_complex_tree_zip,
    calculate_expected_hashes,
    inspect_zip_structure,
)

from tests.fixtures.harness import (
    CLIResult,
    VerificationResult,
    run_cli,
    is_sparse_supported,
    get_allocated_file_size,
    is_file_sparse,
    simulate_power_cut_extraction,
    verify_directory_contents,
)

__all__ = [
    "create_simple_zip",
    "create_zip64",
    "create_multi_part_zip",
    "create_corrupt_zip",
    "create_sparse_payload_zip",
    "create_complex_tree_zip",
    "calculate_expected_hashes",
    "inspect_zip_structure",
    "CLIResult",
    "VerificationResult",
    "run_cli",
    "is_sparse_supported",
    "get_allocated_file_size",
    "is_file_sparse",
    "simulate_power_cut_extraction",
    "verify_directory_contents",
]
