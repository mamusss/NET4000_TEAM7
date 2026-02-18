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

require_cmd ssh

: "${SSH_HOST:?Set SSH_HOST}"
SSH_USER=${SSH_USER:-}
SSH_PORT=${SSH_PORT:-22}
DURATION=${DURATION:-10}
INTERVAL=${INTERVAL:-2}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-3}

target="$SSH_HOST"
if [[ -n "$SSH_USER" ]]; then
  target="${SSH_USER}@${SSH_HOST}"
fi

log "SSH: target=$target port=$SSH_PORT duration=${DURATION}s interval=${INTERVAL}s timeout=${CONNECT_TIMEOUT}s"

end=$((SECONDS + DURATION))
while [[ $SECONDS -lt $end ]]; do
  ssh -o BatchMode=yes -o ConnectTimeout="$CONNECT_TIMEOUT" -p "$SSH_PORT" "$target" true >/dev/null 2>&1 || true
  sleep "$INTERVAL"
done

log "SSH: done"
