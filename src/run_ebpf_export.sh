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
require_cmd bpftool

check_root() {
  if [[ $EUID -ne 0 ]]; then
    if [[ -t 0 ]]; then
      log "Root required for tc attach/detach. Requesting sudo auth..."
      sudo -v
      exec sudo -E bash "$0" "$@"
    fi
    die "Root privileges are required. Run: sudo -v && sudo -n bash $0 $*"
  fi
}

check_root "$@"

log "=== eBPF Flow Export Pipeline ==="
log "Interface: $IFACE"
log "Duration: ${DURATION}s"
log "Output: $OUTPUT"

log "--- Step 1: Verify interface exists and is up ---"
if ! ip link show "$IFACE" >/dev/null 2>&1; then
  die "Interface '$IFACE' does not exist. Available interfaces:"
  ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | tr -d ':'
fi

sleep 0.5

if ! ip link show "$IFACE" | grep -q "state UP"; then
  log "WARNING: Interface $IFACE is not UP. Attempting to bring it up..."
  ip link set "$IFACE" up || die "Failed to bring up interface $IFACE"
  sleep 0.5
fi
log "Interface $IFACE is ready"

log "--- Step 2: Check for existing clsact qdisc ---"
had_clsact=0
if tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "clsact"; then
  had_clsact=1
  log "Found existing clsact qdisc on $IFACE (will not remove on cleanup)"
else
  log "No clsact qdisc found on $IFACE"
fi

cleanup() {
  log "--- Cleanup: Removing tc filter and qdisc ---"
  tc filter del dev "$IFACE" ingress pref "$FILTER_PREF" 2>/dev/null || log "Note: No filter to remove (may not have been attached)"
  if [[ $had_clsact -eq 0 ]]; then
    tc qdisc del dev "$IFACE" clsact 2>/dev/null || log "Note: No clsact to remove"
  fi
  log "Cleanup complete"
}
trap cleanup EXIT INT TERM

log "--- Step 3: Compile tc_flow.bpf.c ---"
BPF_HEADERS_PATH=""
for path in /usr/include/bpf /usr/local/include/bpf /include; do
  if [[ -d "$path" ]]; then
    BPF_HEADERS_PATH="-I $path"
    break
  fi
done

clang -O2 -g -target bpf \
  -c "$SRC_DIR/tc_flow.bpf.c" \
  -o "$SRC_DIR/tc_flow.bpf.o" \
  -I "$SRC_DIR/" \
  $BPF_HEADERS_PATH \
  || die "Failed to compile tc_flow.bpf.c"

if [[ ! -s "$SRC_DIR/tc_flow.bpf.o" ]]; then
  die "BPF object file is empty or missing"
fi

if ! objdump -t "$SRC_DIR/tc_flow.bpf.o" | grep -q "flow_map"; then
  die "BPF object does not contain 'flow_map' - compilation may have failed"
fi

log "Compiled successfully: tc_flow.bpf.o ($(stat -c%s "$SRC_DIR/tc_flow.bpf.o") bytes)"

log "--- Step 4: Attach tc filter to $IFACE ingress ---"

if [[ $had_clsact -eq 0 ]]; then
  log "Adding clsact qdisc to $IFACE..."
  tc qdisc add dev "$IFACE" clsact 2>&1 || die "Failed to add clsact qdisc on $IFACE"
  log "clsact qdisc added"
fi

log "Attaching BPF filter (pref=$FILTER_PREF)..."
tc filter replace dev "$IFACE" ingress pref "$FILTER_PREF" bpf direct-action \
  obj "$SRC_DIR/tc_flow.bpf.o" sec tc 2>&1 \
  || die "Failed to attach BPF filter to $IFACE"

log "BPF filter attached successfully"

log "--- Step 5: Verify BPF filter is attached ---"
sleep 0.5
if ! tc filter show dev "$IFACE" ingress | grep -q "bpf"; then
  die "BPF filter NOT found on $IFACE ingress after attachment!"
fi
if ! tc filter show dev "$IFACE" ingress | grep -q "tc_flow"; then
  die "tc_flow program NOT found in filter!"
fi
log "BPF filter verified on $IFACE"

log "--- Step 6: Verify BPF map exists ---"
sleep 2

MAP_ID=$(bpftool map show 2>/dev/null | grep -B1 "flow_map" | grep "^[0-9]" | awk -F: '{print $1}' || true)
if [[ -z "$MAP_ID" ]]; then
  die "BPF map 'flow_map' not found after attachment. The eBPF program may have failed to load."
fi
log "BPF map 'flow_map' found with id=$MAP_ID"

log "--- Step 7: Start flow capture for ${DURATION}s ---"
if (( DURATION > 5 )); then
  log "To generate traffic, run in another terminal:"
  log "  DURATION=$((DURATION - 5)) PARALLEL=1 $ROOT_DIR/scripts/traffic/run_all.sh"
fi

cd "$ROOT_DIR"
python3 src/ebpf_export.py \
  --iface "$IFACE" \
  --duration "$DURATION" \
  --output "$OUTPUT" \
  || die "ebpf_export.py failed"

if [[ ! -f "$OUTPUT" ]]; then
  die "Output file $OUTPUT was not created"
fi

if [[ -n "${SUDO_USER:-}" ]]; then
  chown -f "$SUDO_USER":"$SUDO_USER" "$OUTPUT" "$SRC_DIR/tc_flow.bpf.o" 2>/dev/null || true
fi

log "=== eBPF Flow Export Complete ==="
log "Results saved to $OUTPUT"

FLOW_COUNT=$(tail -n +2 "$OUTPUT" | wc -l || echo "0")
log "Captured $FLOW_COUNT flows"
