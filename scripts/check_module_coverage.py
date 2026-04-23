#!/usr/bin/env python3
"""Fail CI when critical modules drop below minimum line coverage."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_THRESHOLDS = {
    "src/dbus.rs": 90.0,
    "src/access.rs": 90.0,
    "src/unlock.rs": 90.0,
    "src/bin/keyring_ctl/source_reader.rs": 90.0,
}


def parse_thresholds(raw_values: list[str]) -> dict[str, float]:
    thresholds = dict(DEFAULT_THRESHOLDS)
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


def find_line_coverage(summary: dict, relative_path: str) -> tuple[int, int] | None:
    suffix = f"/{relative_path}"
    for data_entry in summary.get("data", []):
        for file_entry in data_entry.get("files", []):
            filename = file_entry.get("filename", "")
            if filename != relative_path and not filename.endswith(suffix):
                continue
            lines = file_entry.get("summary", {}).get("lines", {})
            covered = int(lines.get("count", 0))
            missed = int(lines.get("missed", 0))
            total = covered + missed
            if total == 0:
                return None
            return covered, total
    return None


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
    args = parser.parse_args()

    try:
        thresholds = parse_thresholds(args.threshold)
        summary = read_summary(Path(args.summary))
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    failures: list[str] = []
    print("Critical module coverage thresholds:")
    for module, minimum in thresholds.items():
        coverage = find_line_coverage(summary, module)
        if coverage is None:
            failures.append(f"{module}: missing from coverage summary")
            print(f"  - {module}: missing (required >= {minimum:.2f}%)")
            continue

        covered, total = coverage
        percent = covered * 100.0 / total
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
