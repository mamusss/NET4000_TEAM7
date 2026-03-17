#!/usr/bin/env bash
set -euo pipefail

IFACE=${1:-lo}
TARGET=${2:-127.0.0.1}
PING_COUNT=${3:-30}
OUT_CSV=${4:-runs/rtt_compare.csv}
PLOT_OUT=${5:-ml/results/rtt_compare.png}
FILTER_PREF=${FILTER_PREF:-49156}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_DIR="$ROOT_DIR/src"
BPF_SRC="$SRC_DIR/tc_icmp_rtt.bpf.c"
BPF_OBJ="$SRC_DIR/tc_icmp_rtt.bpf.o"

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
require_cmd bpftool
require_cmd ping
require_cmd python3

if [[ $EUID -ne 0 ]]; then
  if [[ -t 0 ]]; then
    log "Root required for tc/bpftool. Requesting sudo auth..."
    sudo -v
    exec sudo -E bash "$0" "$@"
  fi
  die "Root privileges are required. Run: sudo -v && sudo -n bash $0 $*"
fi

mkdir -p "$ROOT_DIR/$(dirname "$OUT_CSV")"
mkdir -p "$ROOT_DIR/$(dirname "$PLOT_OUT")"

had_clsact=0
if tc qdisc show dev "$IFACE" | grep -q " clsact "; then
  had_clsact=1
fi

baseline_log=$(mktemp)
ebpf_log=$(mktemp)

cleanup() {
  tc filter del dev "$IFACE" ingress pref "$FILTER_PREF" 2>/dev/null || true
  if [[ $had_clsact -eq 0 ]]; then
    tc qdisc del dev "$IFACE" clsact 2>/dev/null || true
  fi
  rm -f "$baseline_log" "$ebpf_log"
}
trap cleanup EXIT INT TERM

parse_ping_file() {
  local f=$1
  local min avg max mdev loss

  loss=$(sed -nE 's/.*, ([0-9.]+)% packet loss.*/\1/p' "$f" | tail -n1)
  local rtt_line
  rtt_line=$(grep -E '^(rtt|round-trip)' "$f" | tail -n1 || true)

  if [[ -z "$rtt_line" ]]; then
    echo "0 0 0 0 ${loss:-100}"
    return
  fi

  read -r min avg max mdev <<<"$(echo "$rtt_line" | sed -E 's/.*= ([0-9.]+)\/([0-9.]+)\/([0-9.]+)\/([0-9.]+).*/\1 \2 \3 \4/')"
  echo "$min $avg $max $mdev ${loss:-0}"
}

map_id_by_name() {
  local name=$1
  bpftool map show -j | python3 -c 'import json,sys
name = sys.argv[1]
maps = json.load(sys.stdin)
ids = [m["id"] for m in maps if m.get("name") == name]
print(max(ids) if ids else "")' "$name"
}

read_rtt_stats_ns() {
  local map_id=$1
  bpftool map dump id "$map_id" -j | python3 -c 'import json,sys

def to_u8(x):
    if isinstance(x, int):
        return x & 0xFF
    if isinstance(x, str):
        s = x.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    return int(x) & 0xFF

def normalize_bytes(raw):
    if isinstance(raw, dict):
        raw = raw.get("value", raw.get("bytes", []))
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        try:
            out.append(to_u8(item))
        except Exception:
            pass
    return out

def le64(buf, off):
    b = bytes(buf[off:off+8])
    if len(b) < 8:
        return 0
    return int.from_bytes(b, "little")

entries = json.load(sys.stdin)
count = 0
sum_ns = 0
min_ns = None
max_ns = 0

for entry in entries:
    values = entry.get("values")
    if values is None:
        values = [{"value": entry.get("value", [])}]

    for val in values:
        raw = normalize_bytes(val.get("value", []))
        if len(raw) < 32:
            continue

        c = le64(raw, 0)
        s = le64(raw, 8)
        mn = le64(raw, 16)
        mx = le64(raw, 24)

        if c == 0:
            continue

        count += c
        sum_ns += s
        if min_ns is None or mn < min_ns:
            min_ns = mn
        if mx > max_ns:
            max_ns = mx

if min_ns is None:
    min_ns = 0

avg_ns = int(sum_ns / count) if count else 0
print(f"{count},{sum_ns},{min_ns},{max_ns},{avg_ns}")'
}

log "Benchmark: iface=$IFACE target=$TARGET ping_count=$PING_COUNT"
log "Compiling $BPF_SRC"
clang -O2 -g -target bpf -c "$BPF_SRC" -o "$BPF_OBJ" -I "$SRC_DIR"

log "Running baseline ping (no eBPF RTT filter)"
tc filter del dev "$IFACE" ingress pref "$FILTER_PREF" 2>/dev/null || true
ping -c "$PING_COUNT" "$TARGET" > "$baseline_log"
read -r b_min b_avg b_max b_mdev b_loss <<<"$(parse_ping_file "$baseline_log")"

log "Attaching tc_icmp_rtt program (pref=$FILTER_PREF)"
if [[ $had_clsact -eq 0 ]]; then
  tc qdisc add dev "$IFACE" clsact
fi
tc filter replace dev "$IFACE" ingress pref "$FILTER_PREF" bpf da obj "$BPF_OBJ" sec tc

log "Running ping with eBPF RTT filter attached"
ping -c "$PING_COUNT" "$TARGET" > "$ebpf_log"
read -r e_min e_avg e_max e_mdev e_loss <<<"$(parse_ping_file "$ebpf_log")"

stats_id=$(map_id_by_name stats)
if [[ -z "$stats_id" ]]; then
  die "Could not find BPF map named 'stats'"
fi

read -r bpf_count bpf_sum_ns bpf_min_ns bpf_max_ns bpf_avg_ns <<<"$(read_rtt_stats_ns "$stats_id" | tr ',' ' ')"
if [[ -z "${bpf_count:-}" ]]; then
  die "Failed to parse BPF RTT map stats"
fi

bpf_avg_ms=$(awk -v n="$bpf_avg_ns" 'BEGIN{printf "%.6f", n/1000000.0}')
bpf_min_ms=$(awk -v n="$bpf_min_ns" 'BEGIN{printf "%.6f", n/1000000.0}')
bpf_max_ms=$(awk -v n="$bpf_max_ns" 'BEGIN{printf "%.6f", n/1000000.0}')
overhead_pct=$(awk -v b="$b_avg" -v e="$e_avg" 'BEGIN{if (b>0) printf "%.2f", ((e-b)/b)*100; else print "0.00"}')

out_path="$ROOT_DIR/$OUT_CSV"
cat > "$out_path" <<CSV
mode,iface,target,ping_count,ping_min_ms,ping_avg_ms,ping_max_ms,ping_mdev_ms,packet_loss_pct,bpf_rtt_count,bpf_rtt_avg_ms,bpf_rtt_min_ms,bpf_rtt_max_ms
baseline,$IFACE,$TARGET,$PING_COUNT,$b_min,$b_avg,$b_max,$b_mdev,$b_loss,0,0,0,0
ebpf,$IFACE,$TARGET,$PING_COUNT,$e_min,$e_avg,$e_max,$e_mdev,$e_loss,$bpf_count,$bpf_avg_ms,$bpf_min_ms,$bpf_max_ms
CSV

plot_py="$ROOT_DIR/ml/plot_rtt_compare.py"
if [[ -f "$plot_py" ]]; then
  py_bin="python3"
  if [[ -x "$ROOT_DIR/ml_env/bin/python" ]]; then
    py_bin="$ROOT_DIR/ml_env/bin/python"
  fi
  "$py_bin" "$plot_py" --input "$out_path" --output "$ROOT_DIR/$PLOT_OUT"
fi

if [[ -n "${SUDO_USER:-}" ]]; then
  chown -f "$SUDO_USER":"$SUDO_USER" "$out_path" "$BPF_OBJ" "$ROOT_DIR/$PLOT_OUT" 2>/dev/null || true
fi

log "Saved CSV: $OUT_CSV"
log "Saved plot: $PLOT_OUT"
log "Summary: baseline_avg_ms=$b_avg ebpf_avg_ms=$e_avg overhead_pct=$overhead_pct"
log "BPF RTT map stats: count=$bpf_count avg_ms=$bpf_avg_ms min_ms=$bpf_min_ms max_ms=$bpf_max_ms"
