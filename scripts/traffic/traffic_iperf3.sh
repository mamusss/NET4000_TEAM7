#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] $*"
}

require_cmd iperf3

: "${IPERF_HOST:?Set IPERF_HOST}"
IPERF_PORT=${IPERF_PORT:-5201}
DURATION=${DURATION:-10}
IPERF_REVERSE=${IPERF_REVERSE:-0}
IPERF_PARALLEL=${IPERF_PARALLEL:-1}
IPERF_BW=${IPERF_BW:-}

args=(
  -c "$IPERF_HOST"
  -p "$IPERF_PORT"
  -t "$DURATION"
  -P "$IPERF_PARALLEL"
)

if [[ "$IPERF_REVERSE" -eq 1 ]]; then
  args+=(-R)
fi

if [[ -n "$IPERF_BW" ]]; then
  args+=(-b "$IPERF_BW")
fi

log "IPERF3: host=$IPERF_HOST port=$IPERF_PORT duration=${DURATION}s parallel=$IPERF_PARALLEL reverse=$IPERF_REVERSE"

iperf3 "${args[@]}"
