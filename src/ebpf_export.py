# #!/usr/bin/env python3
"""
ebpf_export.py
Reads per-flow features from the tc_flow BPF map and exports to CSV.

Usage:
    # Attach eBPF program first (see instructions below), then:
    sudo python3 src/ebpf_export.py --iface <interface> --duration 60

Full workflow:
    # 1. Compile
    clang -O2 -g -target bpf -c src/tc_flow.bpf.c -o src/tc_flow.bpf.o \
        -I src/

    # 2. Attach to interface (e.g. lo or eth0)
    sudo tc qdisc add dev lo clsact
    sudo tc filter add dev lo ingress bpf direct-action obj src/tc_flow.bpf.o sec tc

    # 3. Run traffic + export
    sudo python3 src/ebpf_export.py --iface lo --duration 60

    # 4. Detach when done
    sudo tc filter del dev lo ingress
    sudo tc qdisc del dev lo clsact
"""

import argparse
import csv
import os
import subprocess
import time

# ── Label from protocol/ports ─────────────────────────────────────────────────
def label_flow(protocol, src_port, dst_port):
    ports = {src_port, dst_port}
    if protocol == 1:
        return "ICMP"
    if ports & {80, 443, 8000, 8080}:
        return "HTTP"
    if ports & {53}:
        return "DNS"
    if ports & {22}:
        return "SSH"
    if ports & {5201}:
        return "IPERF3"
    return "OTHER"

# ── Read BPF map via bpftool ──────────────────────────────────────────────────
def read_bpf_map(map_name="flow_map"):
    """
    Uses bpftool to dump the flow_map contents.
    Returns list of dicts with raw key/value data.
    """
    try:
        # Find the map id by name
        result = subprocess.run(
            ["bpftool", "map", "show", "-j"],
            capture_output=True, text=True, check=True
        )
        import json
        maps = json.loads(result.stdout)
        map_id = None
        for m in maps:
            if m.get("name") == map_name:
                map_id = m["id"]
                break

        if map_id is None:
            print(f"Map '{map_name}' not found. Is the eBPF program attached?")
            return []

        # Dump map contents
        result = subprocess.run(
            ["bpftool", "map", "dump", "id", str(map_id), "-j"],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"bpftool error: {e.stderr}")
        return []
    except Exception as e:
        print(f"Error reading BPF map: {e}")
        return []

# ── Parse raw bpftool output into flow records ────────────────────────────────
def parse_flows(raw_entries):
    flows = []
    for entry in raw_entries:
        try:
            key   = entry["key"]
            value = entry["value"]

            # key bytes: [protocol(1), pad(1), src_port(2), dst_port(2)]
            protocol = key[0]
            src_port = (key[2] << 8) | key[3]
            dst_port = (key[4] << 8) | key[5]

            # value fields (little-endian 64-bit each):
            # pkt_count, byte_count, first_ts, last_ts, ipt_sum
            def le64(b, offset):
                return int.from_bytes(b[offset:offset+8], "little")

            pkt_count  = le64(value, 0)
            byte_count = le64(value, 8)
            first_ts   = le64(value, 16)
            last_ts    = le64(value, 24)
            ipt_sum    = le64(value, 32)

            if pkt_count == 0:
                continue

            duration_ms = (last_ts - first_ts) / 1e6
            avg_ipt_ms  = (ipt_sum / (pkt_count - 1)) / 1e6 if pkt_count > 1 else 0.0

            flows.append({
                "protocol":    protocol,
                "src_port":    src_port,
                "dst_port":    dst_port,
                "pkt_count":   pkt_count,
                "byte_count":  byte_count,
                "duration_ms": round(duration_ms, 3),
                "avg_ipt_ms":  round(avg_ipt_ms, 3),
                "label":       label_flow(protocol, src_port, dst_port),
            })
        except Exception as e:
            continue

    return flows

# ── Export to CSV ─────────────────────────────────────────────────────────────
def export(flows, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fieldnames = ["protocol", "src_port", "dst_port", "pkt_count",
                  "byte_count", "duration_ms", "avg_ipt_ms", "label"]
    with open(output_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(flows)

    print(f"\nSaved {len(flows)} flows to {output_path}")
    from collections import Counter
    counts = Counter(r["label"] for r in flows)
    for lbl, cnt in sorted(counts.items()):
        print(f"  {lbl:10s}: {cnt} flows")

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface",    type=str, default="lo")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--output",   type=str, default="ml/data/real_flows.csv")
    args = parser.parse_args()

    print(f"Reading eBPF flow map for {args.duration}s on {args.iface}...")
    print("Make sure tc_flow.bpf.o is attached. Run traffic scripts now!\n")

    time.sleep(args.duration)

    print("Collecting flow data from kernel map...")
    raw = read_bpf_map("flow_map")
    flows = parse_flows(raw)
    export(flows, args.output)

