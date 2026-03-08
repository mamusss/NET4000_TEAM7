#!/usr/bin/env python3
"""
ebpf_export_full.py
Reads flow data from BPF map and perf ring buffer.
Supports real-time events and final flow dump.
"""

import argparse
import csv
import json
import os
import socket
import struct
import subprocess
import sys
import time
import threading
from collections import Counter
from dataclasses import dataclass

def log(msg, file=sys.stdout):
    print(msg, file=file)
    file.flush()

def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def check_root():
    if os.geteuid() != 0:
        die("Must run as root (use sudo)")

KERNEL_LABELS = {
    0: "OTHER",
    1: "ICMP",
    2: "HTTP",
    3: "HTTPS",
    4: "DNS",
    5: "SSH",
    6: "IPERF"
}

def kernel_label_name(val):
    return KERNEL_LABELS.get(val, "OTHER")

@dataclass
class FlowRecord:
    protocol: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    pkt_count: int
    byte_count: int
    duration_ms: float
    avg_ipt_ms: float
    min_ipt_ms: float
    max_ipt_ms: float
    kernel_label: str
    label: str

def label_flow(protocol, src_port, dst_port):
    ports = {src_port, dst_port}
    if protocol == 1:
        return "ICMP"
    if ports & {80, 443, 8000, 8080, 8888, 5000}:
        return "HTTP"
    if ports & {53, 5353}:
        return "DNS"
    if ports & {22, 2222}:
        return "SSH"
    if ports & {5201, 5202, 5203}:
        return "IPERF3"
    if ports & {21}:
        return "FTP"
    if ports & {25, 587, 465}:
        return "SMTP"
    if protocol == 6:
        return "TCP_OTHER"
    if protocol == 17:
        return "UDP_OTHER"
    return "OTHER"

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack('I', ip))

def parse_flows_from_map(raw_entries):
    """Parse raw bpftool output into flow records."""
    flows = []
    
    def parse_hex(val):
        if isinstance(val, str):
            return int(val, 16)
        return val
    
    for entry in raw_entries:
        try:
            key = entry.get("key", [])
            value = entry.get("value", [])
            
            if not key or not value:
                continue
            
            if len(key) < 16:
                continue
                
            if len(value) < 64:
                continue
            
            src_ip = parse_hex(key[0]) | (parse_hex(key[1]) << 8) | (parse_hex(key[2]) << 16) | (parse_hex(key[3]) << 24)
            dst_ip = parse_hex(key[4]) | (parse_hex(key[5]) << 8) | (parse_hex(key[6]) << 16) | (parse_hex(key[7]) << 24)
            protocol = parse_hex(key[8])
            src_port = parse_hex(key[12]) | (parse_hex(key[13]) << 8)
            dst_port = parse_hex(key[14]) | (parse_hex(key[15]) << 8)
            
            kernel_label_val = parse_hex(value[56]) if len(value) > 56 else 0
            
            def le64(b, offset):
                if offset + 8 > len(b):
                    return 0
                val = 0
                for i in range(8):
                    val |= parse_hex(b[offset + i]) << (i * 8)
                return val
            
            pkt_count = le64(value, 0)
            byte_count = le64(value, 8)
            first_ts = le64(value, 16)
            last_ts = le64(value, 24)
            ipt_sum = le64(value, 32)
            min_ipt = le64(value, 40)
            max_ipt = le64(value, 48)
            
            if pkt_count == 0:
                continue
            
            duration_ms = (last_ts - first_ts) / 1e6
            avg_ipt_ms = (ipt_sum / (pkt_count - 1)) / 1e6 if pkt_count > 1 else 0.0
            min_ipt_ms = min_ipt / 1e6 if min_ipt < 0xFFFFFFFFFFFFFFFF else 0.0
            max_ipt_ms = max_ipt / 1e6 if max_ipt > 0 else 0.0
            
            flows.append(FlowRecord(
                protocol=protocol,
                src_ip=ip_to_str(src_ip),
                dst_ip=ip_to_str(dst_ip),
                src_port=src_port,
                dst_port=dst_port,
                pkt_count=pkt_count,
                byte_count=byte_count,
                duration_ms=round(duration_ms, 3),
                avg_ipt_ms=round(avg_ipt_ms, 3),
                min_ipt_ms=round(min_ipt_ms, 3),
                max_ipt_ms=round(max_ipt_ms, 3),
                kernel_label=kernel_label_name(kernel_label_val),
                label=label_flow(protocol, src_port, dst_port)
            ))
        except Exception as e:
            continue
    
    return flows

def read_bpf_map(map_name="flow_map"):
    """Read all flows from BPF hash map."""
    try:
        result = subprocess.run(
            ["bpftool", "map", "show", "-j"],
            capture_output=True, text=True, check=True
        )
        maps = json.loads(result.stdout)
        
        map_id = None
        for m in maps:
            if m.get("name") == map_name:
                map_id = m["id"]
                break
        
        if map_id is None:
            return []
        
        result = subprocess.run(
            ["bpftool", "map", "dump", "id", str(map_id), "-j"],
            capture_output=True, text=True, check=True
        )
        return json.loads(result.stdout)
    
    except Exception as e:
        log(f"Error reading map: {e}")
        return []

def verify_bpf_attached(iface):
    """Verify BPF filter is attached."""
    try:
        result = subprocess.run(
            ["tc", "filter", "show", "dev", iface, "ingress"],
            capture_output=True, text=True, check=True
        )
        return "bpf" in result.stdout.lower()
    except:
        return False

def export(flows, output_path):
    """Export flows to CSV."""
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    
    fieldnames = ["protocol", "src_ip", "dst_ip", "src_port", "dst_port", 
                  "pkt_count", "byte_count", "duration_ms", "avg_ipt_ms", 
                  "min_ipt_ms", "max_ipt_ms", "kernel_label", "label"]
    
    with open(output_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for flow in flows:
            w.writerow({
                "protocol": flow.protocol,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "pkt_count": flow.pkt_count,
                "byte_count": flow.byte_count,
                "duration_ms": flow.duration_ms,
                "avg_ipt_ms": flow.avg_ipt_ms,
                "min_ipt_ms": flow.min_ipt_ms,
                "max_ipt_ms": flow.max_ipt_ms,
                "kernel_label": flow.kernel_label,
                "label": flow.label
            })
    
    log(f"\nSaved {len(flows)} flows to {output_path}")
    
    counts = Counter(f.label for f in flows)
    for lbl, cnt in sorted(counts.items()):
        log(f"  {lbl:12s}: {cnt} flows")
    
    return len(flows)

def main():
    parser = argparse.ArgumentParser(description="eBPF Flow Exporter (Full 5-tuple)")
    parser.add_argument("--iface", type=str, default="lo")
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--output", type=str, default="ml/data/real_flows.csv")
    parser.add_argument("--bpf-obj", type=str, default="tc_flow_full.bpf.o")
    args = parser.parse_args()
    
    log("=== eBPF Full Flow Exporter (5-tuple) ===")
    log(f"Interface: {args.iface}")
    log(f"Duration: {args.duration}s")
    log(f"Output: {args.output}")
    
    check_root()
    
    if not verify_bpf_attached(args.iface):
        die(f"No BPF filter on {args.iface}. Run attach script first.")
    
    log(f"\nCapturing for {args.duration}s...")
    log("Generating test traffic...\n")
    
    start = time.time()
    time.sleep(args.duration)
    
    log(f"Capture completed in {time.time() - start:.1f}s")
    log("Reading flow data...")
    
    raw = read_bpf_map("flow_map")
    
    if not raw:
        die("No flows captured - no traffic detected during capture period")
    
    flows = parse_flows_from_map(raw)
    
    if not flows:
        die("Failed to parse any flows from BPF map")
    
    count = export(flows, args.output)
    log(f"\n=== Export Complete: {count} flows ===")

if __name__ == "__main__":
    main()
