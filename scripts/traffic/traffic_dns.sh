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

require_cmd dig

DNS_NAME=${DNS_NAME:-example.com}
DNS_SERVER=${DNS_SERVER:-}
DURATION=${DURATION:-10}
INTERVAL=${INTERVAL:-1}
TIMEOUT=${TIMEOUT:-1}

server_arg=()
if [[ -n "$DNS_SERVER" ]]; then
  server_arg=("@$DNS_SERVER")
fi

log "DNS: name=$DNS_NAME server=${DNS_SERVER:-default} duration=${DURATION}s interval=${INTERVAL}s timeout=${TIMEOUT}s"

end=$((SECONDS + DURATION))
while [[ $SECONDS -lt $end ]]; do
  dig +tries=1 +time="$TIMEOUT" "${server_arg[@]}" "$DNS_NAME" >/dev/null 2>&1 || true
  sleep "$INTERVAL"
done

log "DNS: done"
