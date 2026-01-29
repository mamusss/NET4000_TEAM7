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

require_cmd curl

URL=${TARGET_HTTP_URL:-http://127.0.0.1:8000/}
DURATION=${DURATION:-10}
INTERVAL=${INTERVAL:-1}
TIMEOUT=${TIMEOUT:-2}

log "HTTP: url=$URL duration=${DURATION}s interval=${INTERVAL}s timeout=${TIMEOUT}s"

end=$((SECONDS + DURATION))
while [[ $SECONDS -lt $end ]]; do
  curl -sS --max-time "$TIMEOUT" -o /dev/null "$URL" || true
  sleep "$INTERVAL"
done

log "HTTP: done"
