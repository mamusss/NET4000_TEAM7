#!/usr/bin/env bash
# run_ebpf_export.sh
# Compile + attach tc_flow, wait while traffic is generated, export map data, cleanup.

set -euo pipefail

IFACE=${1:-lo}
DURATION=${2:-60}
OUTPUT=${3:-ml/data/real_flows.csv}
FILTER_PREF=${FILTER_PREF:-49155}
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SRC_DIR")"

log() {
  echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] $*"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "Missing command: $1"
  fi
}

require_cmd clang
require_cmd tc
require_cmd python3

if [[ $EUID -ne 0 ]]; then
  if [[ -t 0 ]]; then
    log "Root required for tc attach/detach. Requesting sudo auth..."
    sudo -v
    exec sudo -E bash "$0" "$@"
  fi
  die "Root privileges are required. Run: sudo -v && sudo -n bash $0 $*"
fi

had_clsact=0
if tc qdisc show dev "$IFACE" | grep -q " clsact "; then
  had_clsact=1
fi

cleanup() {
  tc filter del dev "$IFACE" ingress pref "$FILTER_PREF" 2>/dev/null || true
  if [[ $had_clsact -eq 0 ]]; then
    tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

log "Compiling tc_flow.bpf.c"
clang -O2 -g -target bpf \
  -c "$SRC_DIR/tc_flow.bpf.c" \
  -o "$SRC_DIR/tc_flow.bpf.o" \
  -I "$SRC_DIR/"
log "Compiled: src/tc_flow.bpf.o"

log "Attaching tc_flow to $IFACE ingress (pref=$FILTER_PREF)"
if [[ $had_clsact -eq 0 ]]; then
  tc qdisc add dev "$IFACE" clsact
fi
tc filter replace dev "$IFACE" ingress pref "$FILTER_PREF" bpf direct-action \
  obj "$SRC_DIR/tc_flow.bpf.o" sec tc

log "Capture window: ${DURATION}s"
if (( DURATION > 5 )); then
  log "Traffic helper: DURATION=$((DURATION - 5)) PARALLEL=1 ./scripts/traffic/run_all.sh"
fi

cd "$ROOT_DIR"
python3 src/ebpf_export.py \
  --iface "$IFACE" \
  --duration "$DURATION" \
  --output "$OUTPUT"

if [[ -n "${SUDO_USER:-}" ]]; then
  chown -f "$SUDO_USER":"$SUDO_USER" "$OUTPUT" "$SRC_DIR/tc_flow.bpf.o" 2>/dev/null || true
fi

log "Done. Results saved to $OUTPUT"
