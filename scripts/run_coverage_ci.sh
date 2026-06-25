#!/usr/bin/env bash
set -euo pipefail

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
}

run_in_dbus_session() {
  local label="$1"
  shift

  echo
  echo "==> ${label}"
  dbus-run-session -- "$@"
}

LLVM_COV_BIN="${LLVM_COV:-llvm-cov}"
LLVM_PROFDATA_BIN="${LLVM_PROFDATA:-llvm-profdata}"
COVERAGE_DIR="target/llvm-cov"
SUMMARY_PATH="${COVERAGE_DIR}/coverage-summary.json"
LCOV_PATH="${COVERAGE_DIR}/lcov.info"

require_command cargo
require_command dbus-run-session
require_command secret-tool
require_command "${LLVM_COV_BIN}"
require_command "${LLVM_PROFDATA_BIN}"
require_command python3

mkdir -p "${COVERAGE_DIR}"

echo "==> Cleaning previous coverage artifacts"
LLVM_COV="${LLVM_COV_BIN}" LLVM_PROFDATA="${LLVM_PROFDATA_BIN}" \
  cargo llvm-cov clean --workspace

echo
echo "==> Running regular test suite with coverage instrumentation"
LLVM_COV="${LLVM_COV_BIN}" LLVM_PROFDATA="${LLVM_PROFDATA_BIN}" \
  cargo llvm-cov --workspace --all-features --no-report

run_in_dbus_session \
  "Running ignored keyring-daemon D-Bus integration tests for coverage" \
  env LLVM_COV="${LLVM_COV_BIN}" LLVM_PROFDATA="${LLVM_PROFDATA_BIN}" \
    cargo llvm-cov --workspace --all-features --no-report \
    --lib \
    -- \
    --ignored \
    --test-threads=1

run_in_dbus_session \
  "Running ignored keyring-ctl import integration test for coverage" \
  env LLVM_COV="${LLVM_COV_BIN}" LLVM_PROFDATA="${LLVM_PROFDATA_BIN}" \
    cargo llvm-cov --workspace --all-features --no-report \
    --bin keyring-ctl \
    -- \
    tests::import_round_trip_lookup_from_seeded_source_service \
    --ignored \
    --exact \
    --test-threads=1

run_in_dbus_session \
  "Running ignored keyring-ctl source-reader integration tests for coverage" \
  env LLVM_COV="${LLVM_COV_BIN}" LLVM_PROFDATA="${LLVM_PROFDATA_BIN}" \
    cargo llvm-cov --workspace --all-features --no-report \
    --bin keyring-ctl \
    -- \
    source_reader::tests::read_unlocked_snapshot_ \
    --ignored \
    --test-threads=1

echo
echo "==> Generating coverage reports"
LLVM_COV="${LLVM_COV_BIN}" LLVM_PROFDATA="${LLVM_PROFDATA_BIN}" \
  cargo llvm-cov report --json --summary-only --output-path "${SUMMARY_PATH}"
LLVM_COV="${LLVM_COV_BIN}" LLVM_PROFDATA="${LLVM_PROFDATA_BIN}" \
  cargo llvm-cov report --lcov --output-path "${LCOV_PATH}"

echo
echo "==> Enforcing per-module coverage thresholds"
python3 scripts/check_module_coverage.py --summary "${SUMMARY_PATH}"

echo
echo "Coverage artifacts:"
echo "  - ${SUMMARY_PATH}"
echo "  - ${LCOV_PATH}"
