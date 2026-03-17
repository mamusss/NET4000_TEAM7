#!/usr/bin/env bash
# scripts/test_shield.sh
# End-to-end test for Adaptive ML Shield

set -euo pipefail

IFACE="lo"
SCRIPT_DIR="src"
LOG_FILE="runs/shield_test.log"
mkdir -p runs

log() { echo "[SHIELD-TEST] $*"; }

# 1. Clean and Build
log "Building..."
make build

# 2. Attach BPF
log "Attaching BPF..."
sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
sudo tc qdisc add dev "$IFACE" clsact
sudo tc filter add dev "$IFACE" ingress bpf direct-action obj src/tc_flow_full.bpf.o sec tc

# 3. Ensure Model exists
if [[ ! -f "ml/models/rf_model.pkl" ]]; then
    log "Training model first..."
    make train
fi

# 4. Start Shield Daemon in background
log "Starting ML Shield Daemon..."
sudo ./ml_env/bin/python src/ml_shield_daemon.py > "$LOG_FILE" 2>&1 &
SHIELD_PID=$!

cleanup() {
    log "Cleaning up..."
    sudo kill $SHIELD_PID 2>/dev/null || true
    sudo tc filter del dev "$IFACE" ingress 2>/dev/null || true
    sudo tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
    log "Done."
}
trap cleanup EXIT

log "Waiting for daemon to initialize..."
sleep 5

# 5. Generate Normal Traffic
log "Generating normal traffic (should be allowed)..."
ping -c 5 127.0.0.1 >/dev/null

# 6. Generate "Malicious" Traffic (Simulated)
# We'll use a high rate of packets to trigger the threshold-based blocking first
log "Generating high-rate traffic to trigger auto-block..."
for i in {1..1200}; do
    echo "test" | nc -u -w0 127.0.0.1 9999 &>/dev/null || true
done

log "Checking block_list_map..."
BLOCK_DUMP=$(sudo bpftool map dump name block_list_map)
echo "$BLOCK_DUMP"

# 7. Check if 127.0.0.1 is blocked (it should be if it exceeded threshold)
if echo "$BLOCK_DUMP" | grep -E "(7f 00 00 01|16777343)"; then
    log "SUCCESS: 127.0.0.1 (lo) was automatically blocked by the kernel shield!"
else
    log "WARNING: 127.0.0.1 not found in block list yet. Retrying high-rate traffic..."
    for i in {1..1000}; do echo "test" | nc -u -w0 127.0.0.1 9998 &>/dev/null || true; done
    BLOCK_DUMP=$(sudo bpftool map dump name block_list_map)
    if echo "$BLOCK_DUMP" | grep -E "(7f 00 00 01|16777343)"; then
        log "SUCCESS: 127.0.0.1 (lo) was automatically blocked!"
    else
         log "FAILED: Auto-block not triggered."
    fi
fi

log "--- Daemon Log Snippet ---"
tail -n 20 "$LOG_FILE"

log "Testing manual block of 127.0.0.1..."
sudo bpftool map update name block_list_map key 0x7f 0x00 0x00 0x01 value 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
# 127.0.0.1 as little-endian 32-bit int is 0x0100007f = 16777343
if sudo bpftool map dump name block_list_map | grep -E "(7f 00 00 01|16777343)"; then
    log "SUCCESS: 127.0.0.1 manual block verified."
else
    log "FAILED: 127.0.0.1 manual block failed."
fi

log "Testing manual unblock..."
# Unblock 127.0.0.1 (7f 00 00 01)
sudo bpftool map delete name block_list_map key 0x7f 0x00 0x00 0x01
if ! sudo bpftool map dump name block_list_map | grep -q "7f 00 00 01"; then
    log "SUCCESS: Manual unblock verified."
else
    log "FAILED: Manual unblock failed."
fi

log "Full verification complete."
