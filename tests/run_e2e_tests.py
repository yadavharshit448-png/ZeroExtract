"""Unified E2E Test Suite Runner for ZeroExtract.

Executes tests across Tiers 1-4, tracks individual pass/fail metrics,
and outputs a formatted summary breakdown report.

Usage:
    python tests/run_e2e_tests.py
    python tests/run_e2e_tests.py --tier 1
    python tests/run_e2e_tests.py --tier 2
    python tests/run_e2e_tests.py --tier 3
    python tests/run_e2e_tests.py --tier 4
    python tests/run_e2e_tests.py --tier all --verbose
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import io
import os
from pathlib import Path
import sys
import time
import unittest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
E2E_DIR = WORKSPACE_ROOT / "tests" / "e2e"

TIER_CONFIG = {
    1: {
        "id": 1,
        "title": "Tier 1: Feature Coverage",
        "file": "test_tier1_features.py",
        "expected_min": 70,
    },
    2: {
        "id": 2,
        "title": "Tier 2: Boundary & Corner Cases",
        "file": "test_tier2_boundaries.py",
        "expected_min": 70,
    },
    3: {
        "id": 3,
        "title": "Tier 3: Combinations",
        "file": "test_tier3_combinations.py",
        "expected_min": 15,
    },
    4: {
        "id": 4,
        "title": "Tier 4: Real-World Scenarios",
        "file": "test_tier4_realworld.py",
        "expected_min": 5,
    },
}


@dataclass
class TierResult:
    """Aggregated outcome of running a single test tier."""
    tier_id: int
    title: str
    file_name: str
    exists: bool = False
    tests_run: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    duration: float = 0.0
    failure_details: list[str] = field(default_factory=list)
    error_details: list[str] = field(default_factory=list)

    @property
    def is_success(self) -> bool:
        return self.failed == 0 and self.errors == 0


class TrackingTestResult(unittest.TextTestResult):
    """Test result collector that counts passes, failures, errors, and skips."""

    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.successes: list[unittest.TestCase] = []

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self.successes.append(test)


def run_tier(
    tier_id: int,
    verbose: bool = False,
    failfast: bool = False,
    name_filter: str | None = None,
) -> TierResult:
    """Run tests for a designated tier and return a TierResult."""
    cfg = TIER_CONFIG[tier_id]
    test_file = E2E_DIR / cfg["file"]

    tier_res = TierResult(
        tier_id=tier_id,
        title=cfg["title"],
        file_name=cfg["file"],
        exists=test_file.exists(),
    )

    if not test_file.exists():
        return tier_res

    # Ensure root is on sys.path
    if str(WORKSPACE_ROOT) not in sys.path:
        sys.path.insert(0, str(WORKSPACE_ROOT))

    loader = unittest.defaultTestLoader
    # Load tests from file
    module_name = f"tests.e2e.{test_file.stem}"
    try:
        suite = loader.loadTestsFromName(module_name)
    except Exception as exc:
        tier_res.errors = 1
        tier_res.error_details.append(f"Failed to import/load {module_name}: {exc}")
        return tier_res

    # Filter suite if requested
    if name_filter:
        filtered_suite = unittest.TestSuite()
        for test in _iter_suite(suite):
            if name_filter.lower() in test.id().lower():
                filtered_suite.addTest(test)
        suite = filtered_suite

    output_stream = sys.stdout if verbose else io.StringIO()
    runner = unittest.TextTestRunner(
        stream=output_stream,
        verbosity=2 if verbose else 0,
        failfast=failfast,
        resultclass=TrackingTestResult,
    )

    start_time = time.time()
    result = runner.run(suite)
    duration = time.time() - start_time

    tier_res.tests_run = result.testsRun
    tier_res.passed = len(getattr(result, "successes", []))
    tier_res.failed = len(result.failures)
    tier_res.errors = len(result.errors)
    tier_res.skipped = len(result.skipped)
    tier_res.duration = duration

    for test, trace in result.failures:
        tier_res.failure_details.append(f"{test.id()}:\n{trace}")
    for test, trace in result.errors:
        tier_res.error_details.append(f"{test.id()}:\n{trace}")

    return tier_res


def _iter_suite(suite: unittest.TestSuite):
    """Recursively iterate over test cases in a TestSuite."""
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_suite(item)
        else:
            yield item


def print_summary_report(results: list[TierResult]) -> None:
    """Print an ASCII summary table for all tiers."""
    sep_line = "=" * 88
    dash_line = "-" * 88

    print("\n" + sep_line)
    print(f"{'ZeroExtract E2E Test Execution Summary':^88}")
    print(sep_line)
    header = (
        f"{'Tier':<34} | {'Status':<10} | {'Tests':>6} | {'Passed':>6} | "
        f"{'Failed':>6} | {'Errors':>6} | {'Skipped':>7} | {'Time':>6}"
    )
    print(header)
    print(dash_line)

    tot_run = 0
    tot_pass = 0
    tot_fail = 0
    tot_err = 0
    tot_skip = 0
    tot_time = 0.0

    for r in results:
        tot_run += r.tests_run
        tot_pass += r.passed
        tot_fail += r.failed
        tot_err += r.errors
        tot_skip += r.skipped
        tot_time += r.duration

        if not r.exists:
            status = "MISSING"
        elif r.failed > 0 or r.errors > 0:
            status = "FAILED"
        elif r.tests_run == 0:
            status = "EMPTY"
        else:
            status = "PASSED"

        time_str = f"{r.duration:.2f}s"
        line = (
            f"{r.title:<34} | {status:<10} | {r.tests_run:>6} | {r.passed:>6} | "
            f"{r.failed:>6} | {r.errors:>6} | {r.skipped:>7} | {time_str:>6}"
        )
        print(line)

    print(dash_line)
    total_time_str = f"{tot_time:.2f}s"
    tot_line = (
        f"{'TOTAL':<34} | {'':<10} | {tot_run:>6} | {tot_pass:>6} | "
        f"{tot_fail:>6} | {tot_err:>6} | {tot_skip:>7} | {total_time_str:>6}"
    )
    print(tot_line)
    print(sep_line)

    # Print error details if any
    has_issues = False
    for r in results:
        if r.failure_details or r.error_details:
            has_issues = True
            print(f"\n--- Issues in {r.title} ---")
            for fail in r.failure_details:
                print(f"[FAIL] {fail}\n")
            for err in r.error_details:
                print(f"[ERROR] {err}\n")

    if not has_issues and tot_fail == 0 and tot_err == 0:
        print("\n>>> OVERALL RESULT: PASSED <<<")
    else:
        print("\n>>> OVERALL RESULT: FAILED <<<")
    print(sep_line + "\n")


def main() -> int:
    """CLI entry point for E2E test runner."""
    parser = argparse.ArgumentParser(
        description="ZeroExtract E2E Test Suite Runner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--tier",
        choices=["1", "2", "3", "4", "all"],
        default="all",
        help="Specify which tier to execute (1, 2, 3, 4, or all)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose test execution output",
    )
    parser.add_argument(
        "-f", "--failfast",
        action="store_true",
        help="Stop on first failure or error",
    )
    parser.add_argument(
        "-k", "--filter",
        type=str,
        default=None,
        help="Filter test names matching substring",
    )

    args = parser.parse_args()

    # Determine tiers to run
    if args.tier == "all":
        tier_ids = [1, 2, 3, 4]
    else:
        tier_ids = [int(args.tier)]

    results: list[TierResult] = []
    for tid in tier_ids:
        res = run_tier(
            tier_id=tid,
            verbose=args.verbose,
            failfast=args.failfast,
            name_filter=args.filter,
        )
        results.append(res)
        if args.failfast and (res.failed > 0 or res.errors > 0):
            break

    print_summary_report(results)

    # Return 1 if any failure or error, 0 otherwise
    any_failed = any(r.failed > 0 or r.errors > 0 for r in results)
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
