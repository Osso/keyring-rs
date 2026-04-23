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

require_command dbus-run-session
require_command cargo
require_command secret-tool

run_in_dbus_session \
  "keyring-daemon ignored D-Bus integration tests" \
  cargo test --bin keyring-daemon -- --ignored --test-threads=1

run_in_dbus_session \
  "keyring-ctl ignored import integration test" \
  cargo test \
    --bin keyring-ctl \
    tests::import_round_trip_lookup_from_seeded_source_service \
    -- \
    --ignored \
    --exact \
    --test-threads=1
