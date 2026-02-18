#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] $*"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DURATION=${DURATION:-10}
INTERVAL=${INTERVAL:-1}
PARALLEL=${PARALLEL:-0}

run_http() {
  DURATION="${HTTP_DURATION:-$DURATION}" INTERVAL="${HTTP_INTERVAL:-$INTERVAL}" "$SCRIPT_DIR/traffic_http.sh"
}

run_dns() {
  DURATION="${DNS_DURATION:-$DURATION}" INTERVAL="${DNS_INTERVAL:-$INTERVAL}" "$SCRIPT_DIR/traffic_dns.sh"
}

run_ping() {
  DURATION="${PING_DURATION:-$DURATION}" INTERVAL="${PING_INTERVAL:-$INTERVAL}" "$SCRIPT_DIR/traffic_ping.sh"
}

run_ssh() {
  if [[ -n "${SSH_HOST:-}" ]]; then
    DURATION="${SSH_DURATION:-$DURATION}" INTERVAL="${SSH_INTERVAL:-$INTERVAL}" "$SCRIPT_DIR/traffic_ssh.sh"
  else
    log "SSH: skipped (set SSH_HOST to enable)"
  fi
}

run_iperf() {
  if [[ -n "${IPERF_HOST:-}" ]]; then
    DURATION="${IPERF_DURATION:-$DURATION}" "$SCRIPT_DIR/traffic_iperf3.sh"
  else
    log "IPERF3: skipped (set IPERF_HOST to enable)"
  fi
}

log "run_all: duration=${DURATION}s interval=${INTERVAL}s parallel=${PARALLEL}"

if [[ "$PARALLEL" -eq 1 ]]; then
  run_http &
  pids=($!)
  run_dns &
  pids+=($!)
  run_ping &
  pids+=($!)
  run_ssh &
  pids+=($!)
  run_iperf &
  pids+=($!)
  wait "${pids[@]}"
else
  run_http
  run_dns
  run_ping
  run_ssh
  run_iperf
fi

log "run_all: done"
