#!/usr/bin/env python3
"""Fail CI when critical first-party coverage drops below minimums."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_LINE_THRESHOLDS = {
    "src/dbus.rs": 90.0,
    "src/access.rs": 90.0,
    "src/unlock.rs": 90.0,
    "src/bin/keyring_ctl/source_reader.rs": 90.0,
}
DEFAULT_TOTAL_LINE_THRESHOLD = 90.0
FIRST_PARTY_PREFIXES = ("src/", "protocol/src/")
CANONICAL_DUPLICATE_PREFIX = "src/bin/../"


def parse_thresholds(raw_values: list[str]) -> dict[str, float]:
    thresholds = dict(DEFAULT_LINE_THRESHOLDS)
    for raw in raw_values:
        if "=" not in raw:
            raise ValueError(f"invalid --threshold '{raw}', expected path=percent")
        path, value = raw.split("=", 1)
        try:
            thresholds[path] = float(value)
        except ValueError as error:
            raise ValueError(f"invalid coverage percent in '{raw}'") from error
    return thresholds


def read_summary(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"coverage summary not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"coverage summary is invalid JSON: {path}") from error


def relative_source_path(filename: str) -> str:
    marker = "/keyring-rs/"
    if marker in filename:
        return filename.rsplit(marker, 1)[1]
    return filename


def is_first_party_source(relative_path: str) -> bool:
    if relative_path.startswith(CANONICAL_DUPLICATE_PREFIX):
        return False
    return relative_path.startswith(FIRST_PARTY_PREFIXES)


def coverage_counts(summary_entry: dict, metric: str) -> tuple[int, int]:
    values = summary_entry.get("summary", {}).get(metric, {})
    covered = int(values.get("covered", 0))
    count = int(values.get("count", 0))
    return covered, count


def coverage_percent(covered: int, count: int) -> float:
    if count == 0:
        return 100.0
    return covered * 100.0 / count


def first_party_files(summary: dict) -> dict[str, dict]:
    files: dict[str, dict] = {}
    for data_entry in summary.get("data", []):
        for file_entry in data_entry.get("files", []):
            relative_path = relative_source_path(file_entry.get("filename", ""))
            if is_first_party_source(relative_path):
                files[relative_path] = file_entry
    return files


def find_line_coverage(
    files: dict[str, dict], relative_path: str
) -> tuple[int, int] | None:
    suffix = f"/{relative_path}"
    for filename, file_entry in files.items():
        if filename != relative_path and not filename.endswith(suffix):
            continue
        covered, total = coverage_counts(file_entry, "lines")
        if total == 0:
            return None
        return covered, total
    return None


def total_coverage(files: dict[str, dict], metric: str) -> tuple[int, int]:
    covered = 0
    total = 0
    for file_entry in files.values():
        file_covered, file_total = coverage_counts(file_entry, metric)
        covered += file_covered
        total += file_total
    return covered, total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        default="target/llvm-cov/coverage-summary.json",
        help="Path to cargo llvm-cov --json --summary-only report",
    )
    parser.add_argument(
        "--threshold",
        action="append",
        default=[],
        help="Override threshold as path=percent (repeatable)",
    )
    parser.add_argument(
        "--total-lines",
        type=float,
        default=DEFAULT_TOTAL_LINE_THRESHOLD,
        help="Minimum aggregate first-party line coverage percent",
    )
    parser.add_argument(
        "--total-functions",
        type=float,
        default=None,
        help="Optional minimum aggregate first-party function coverage percent",
    )
    args = parser.parse_args()

    try:
        thresholds = parse_thresholds(args.threshold)
        files = first_party_files(read_summary(Path(args.summary)))
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    failures: list[str] = []
    total_lines = total_coverage(files, "lines")
    total_functions = total_coverage(files, "functions")

    print("Aggregate first-party coverage thresholds:")
    covered, total = total_lines
    percent = coverage_percent(covered, total)
    print(
        f"  - lines: {percent:.2f}% ({covered}/{total}, required >= {args.total_lines:.2f}%)"
    )
    if percent < args.total_lines:
        failures.append(
            f"total lines: {percent:.2f}% < required {args.total_lines:.2f}% ({covered}/{total})"
        )

    covered, total = total_functions
    percent = coverage_percent(covered, total)
    if args.total_functions is None:
        print(f"  - functions: {percent:.2f}% ({covered}/{total}, informational)")
    else:
        print(
            f"  - functions: {percent:.2f}% ({covered}/{total}, required >= {args.total_functions:.2f}%)"
        )
        if percent < args.total_functions:
            failures.append(
                f"total functions: {percent:.2f}% < required {args.total_functions:.2f}% ({covered}/{total})"
            )

    print("Critical module coverage thresholds:")
    for module, minimum in thresholds.items():
        coverage = find_line_coverage(files, module)
        if coverage is None:
            failures.append(f"{module}: missing from coverage summary")
            print(f"  - {module}: missing (required >= {minimum:.2f}%)")
            continue

        covered, total = coverage
        percent = coverage_percent(covered, total)
        print(
            f"  - {module}: {percent:.2f}% ({covered}/{total} lines, required >= {minimum:.2f}%)"
        )
        if percent < minimum:
            failures.append(
                f"{module}: {percent:.2f}% < required {minimum:.2f}% ({covered}/{total})"
            )

    if failures:
        print("\nCoverage threshold check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("\nCoverage threshold check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
