#!/usr/bin/env bash
set -euo pipefail

runtime_dir="${RUNNER_TEMP:-$PWD/.ory-foundation-runtime}"

stop_recorded_process() {
  local name="$1"
  local expected="$2"
  local pid_file="$runtime_dir/$name.pid"
  if [[ ! -f "$pid_file" ]]; then
    return 0
  fi
  local pid command_line
  pid=$(cat "$pid_file")
  if [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]]; then
    command_line=$(tr '\0' ' ' < "/proc/$pid/cmdline")
    if [[ "$command_line" == *"$expected"* ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pid_file"
}

# Limit termination to recorded processes whose command lines match a script
# started by run.sh. This avoids terminating unrelated runner processes.
stop_recorded_process "ory-foundation-mail-sink" "tests/ory-foundation/smtp_sink.py"
stop_recorded_process "ory-foundation-relay" "tests/ory-foundation/loopback_relay.py"

export BAOBAB_ORY_HOST_GATEWAY=172.30.146.1
docker compose -p ory-foundation-ci \
  -f docker-compose.ory.yml \
  -f tests/ory-foundation/compose.isolated.yml \
  down -v --remove-orphans
