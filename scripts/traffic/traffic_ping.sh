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

require_cmd ping

PING_HOST=${PING_HOST:-127.0.0.1}
DURATION=${DURATION:-10}
INTERVAL=${INTERVAL:-1}
TIMEOUT=${TIMEOUT:-1}

log "PING: host=$PING_HOST duration=${DURATION}s interval=${INTERVAL}s timeout=${TIMEOUT}s"

end=$((SECONDS + DURATION))
while [[ $SECONDS -lt $end ]]; do
  ping -c 1 -W "$TIMEOUT" "$PING_HOST" >/dev/null 2>&1 || true
  sleep "$INTERVAL"
done

log "PING: done"
