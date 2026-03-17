#!/usr/bin/env bash
# test_ebpf_all_traffic.sh
# Comprehensive test for eBPF flow capture with all traffic types.

set -euo pipefail

IFACE=${1:-lo}
DURATION=${2:-20}
OUTPUT=${3:-ml/data/test_flows.csv}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        exec sudo -E bash "$0" "$@"
    fi
}

cleanup() {
    log "Cleaning up..."
    tc filter del dev "$IFACE" ingress pref 49155 2>/dev/null || true
    tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
}
trap cleanup EXIT

check_root "$@"

log "=== eBPF Flow Capture Test (All Traffic Types) ==="
log "Interface: $IFACE, Duration: ${DURATION}s"

# Ensure fresh output file to avoid column mismatch
rm -f "$OUTPUT"

# Compile BPF
log "Compiling tc_flow_full.bpf.c..."
clang -O2 -g -target bpf -c "$SCRIPT_DIR/tc_flow_full.bpf.c" \
    -o "$SCRIPT_DIR/tc_flow_full.bpf.o" -I"$SCRIPT_DIR/" \
    || die "Compilation failed"

# Check compiled object
if [[ ! -s "$SCRIPT_DIR/tc_flow_full.bpf.o" ]]; then
    die "BPF object file is empty"
fi

if ! objdump -t "$SCRIPT_DIR/tc_flow_full.bpf.o" | grep -q "flow_map"; then
    die "BPF object missing flow_map symbol"
fi

log "BPF compiled successfully"

# Setup tc
log "Setting up clsact qdisc..."
tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
tc qdisc add dev "$IFACE" clsact || die "Failed to add clsact"
tc filter replace dev "$IFACE" ingress pref 49155 bpf direct-action \
    obj "$SCRIPT_DIR/tc_flow_full.bpf.o" sec tc \
    || die "Failed to attach BPF filter"

# Verify attachment
sleep 1
if ! tc filter show dev "$IFACE" ingress | grep -q "tc_flow"; then
    die "BPF filter not attached"
fi
log "BPF filter attached"

# Check map
MAP_ID=$(bpftool map show 2>/dev/null | grep -B1 "flow_map" | grep "^[0-9]" | awk -F: '{print $1}')
if [[ -z "$MAP_ID" ]]; then
    die "BPF map not found"
fi
log "BPF map id=$MAP_ID ready"

log "Starting traffic generation for ${DURATION}s..."

# Start traffic generation in background
generate_traffic() {
    # ICMP
    ping -c 50 127.0.0.1 &>/dev/null &
    
    # TCP (various ports)
    for port in 80 443 22 8080; do
        (timeout 2 bash -c "echo '' | nc -w1 127.0.0.1 $port" >/dev/null 2>&1 || true) &
    done
    
    # UDP (DNS)
    nslookup google.com 127.0.0.1 &>/dev/null || true
    
    # UDP (QUIC simulated)
    (timeout 2 bash -c "echo 'quic' | nc -u -w1 127.0.0.1 443" 2>/dev/null || true) &
    
    # Multiple connections
    for i in {1..20}; do
        curl -s -o /dev/null --connect-timeout 1 http://127.0.0.1:8080/ 2>/dev/null &
    done
    
    # Raw TCP/UDP
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect(('127.0.0.1', 9999))
    s.send(b'test')
except: pass
s.close()
" &
}

generate_traffic &

# Run exporter
log "Running flow exporter..."
python3 "$SCRIPT_DIR/ebpf_export_full.py" \
    --iface "$IFACE" \
    --duration "$DURATION" \
    --output "$OUTPUT" \
    --bpf-obj tc_flow_full.bpf.o

# Check results
log "=== Test Results ==="
if [[ -f "$OUTPUT" ]]; then
    LINES=$(tail -n +2 "$OUTPUT" | wc -l)
    log "Flows captured: $LINES"
    
    if [[ "$LINES" -gt 0 ]]; then
        log "Output preview:"
        head -5 "$OUTPUT"
        
    # Check for different traffic types - protocol is the second field now
    ICMP_COUNT=$(cut -d, -f2 "$OUTPUT" | grep -E "^(1|58)$" | wc -l)
    TCP_COUNT=$(cut -d, -f2 "$OUTPUT" | grep -E "^6$" | wc -l)
    
    log "Traffic types detected:"
    log "  ICMP flows: $ICMP_COUNT"
    log "  TCP flows: $TCP_COUNT"
    
    if [[ $((ICMP_COUNT + TCP_COUNT)) -gt 0 ]]; then
            log "=== TEST PASSED ==="
            exit 0
        fi
    fi
fi

log "=== TEST FAILED ==="
exit 1
