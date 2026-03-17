#!/usr/bin/env python3
"""
ebpf_export_full.py
Pro-grade flow exporter with IPv4/IPv6 support and TCP flags extraction.
"""

import sys, os, time, struct, socket, argparse, subprocess, json
from dataclasses import dataclass, fields
from collections import defaultdict


def log(msg, file=sys.stdout):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=file)


def die(msg):
    log(f"ERROR: {msg}", file=sys.stderr)
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
    6: "IPERF",
    7: "QUIC",
}


def kernel_label_name(val):
    return KERNEL_LABELS.get(val, "OTHER")


@dataclass
class FlowRecord:
    version: int
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
    tcp_flags: int
    kernel_label: str
    label: str


def label_flow(protocol, src_port, dst_port):
    ports = {src_port, dst_port}
    if protocol in [1, 58]:
        return "ICMP"
    if protocol == 17 and (ports & {443, 8443}):
        return "QUIC"
    if ports & {80, 443, 8000, 8080, 8888, 5000}:
        return "HTTP"
    if ports & {53, 5353}:
        return "DNS"
    if ports & {22, 2222}:
        return "SSH"
    if ports & {5201, 5202, 5203}:
        return "IPERF3"
    return "OTHER"


def ip_to_str(ver, ip_bytes):
    if ver == 4:
        return socket.inet_ntop(socket.AF_INET, ip_bytes[:4])
    return socket.inet_ntop(socket.AF_INET6, ip_bytes)


def parse_flows_from_map(raw_entries):
    flows = []

    def le64(b, offset):
        return struct.unpack("<Q", b[offset : offset + 8])[0]

    def to_bytes(raw):
        # Handle list of hex strings or a single hex string
        if isinstance(raw, list):
            return bytes([int(x, 16) for x in raw])
        if isinstance(raw, str):
            # Handle space-separated hex bytes if necessary
            return bytes.fromhex(raw.replace("0x", ""))
        return bytes(raw)

    for entry in raw_entries:
        try:
            key_raw = to_bytes(entry["key"])
            val_raw = to_bytes(entry["value"])

            # key: src_ip[4], dst_ip[4], proto(1), ver(1), src_port(2), dst_port(2) = 16+16+1+1+2+2 = 38 bytes
            # BPF might pad the key to 40 bytes or more.
            # src_ip is 0-16, dst_ip is 16-32.
            src_ip_bytes = key_raw[0:16]
            dst_ip_bytes = key_raw[16:32]
            proto = key_raw[32]
            ver = key_raw[33]
            # Ports are stored in host byte order (little endian on x86)
            src_port = struct.unpack("<H", key_raw[34:36])[0]
            dst_port = struct.unpack("<H", key_raw[36:38])[0]

            # value: pkt_count(8), byte_count(8), first_ts(8), last_ts(8), ipt_sum(8), min_ipt(8), max_ipt(8), tcp_flags(1), label(1), pad(6) = 64 bytes
            pkts = le64(val_raw, 0)
            bytes_count = le64(val_raw, 8)
            first_ts = le64(val_raw, 16)
            last_ts = le64(val_raw, 24)
            ipt_sum = le64(val_raw, 32)
            min_ipt = le64(val_raw, 40)
            max_ipt = le64(val_raw, 48)
            tcp_flags = val_raw[56]
            k_label = val_raw[57]

            duration_ms = (last_ts - first_ts) / 1e6
            avg_ipt_ms = (ipt_sum / (pkts - 1)) / 1e6 if pkts > 1 else 0
            min_ipt_ms = (min_ipt / 1e6) if min_ipt < 0xFFFFFFFFFFFFFFFF else 0
            max_ipt_ms = (max_ipt / 1e6)

            flows.append(
                FlowRecord(
                    version=ver,
                    protocol=proto,
                    src_ip=ip_to_str(ver, src_ip_bytes),
                    dst_ip=ip_to_str(ver, dst_ip_bytes),
                    src_port=src_port,
                    dst_port=dst_port,
                    pkt_count=pkts,
                    byte_count=bytes_count,
                    duration_ms=round(duration_ms, 3),
                    avg_ipt_ms=round(avg_ipt_ms, 3),
                    min_ipt_ms=round(min_ipt_ms, 3),
                    max_ipt_ms=round(max_ipt_ms, 3),
                    tcp_flags=tcp_flags,
                    kernel_label=kernel_label_name(k_label),
                    label=label_flow(proto, src_port, dst_port),
                )
            )
        except Exception as e:
            log(f"Failed to parse flow entry: {e}")
            continue
    return flows


def read_bpf_map(map_name="flow_map"):
    cmd = ["bpftool", "map", "show", "name", map_name, "-j"]
    try:
        res = subprocess.check_output(cmd)
        if not res:
            log(f"No map found with name {map_name}")
            return []
        map_info = json.loads(res)
        if not map_info:
            log(f"Map {map_name} info is empty")
            return []
        
        # bpftool can return a list or a single dict
        if isinstance(map_info, list):
            map_id = map_info[0]["id"]
        else:
            map_id = map_info["id"]
            
        log(f"Reading from map ID {map_id} ({map_name})")
        dump = subprocess.check_output(["bpftool", "map", "dump", "id", str(map_id), "-j"])
        return json.loads(dump)
    except subprocess.CalledProcessError as e:
        log(f"bpftool command failed: {e}")
        return []
    except Exception as e:
        import traceback
        log(f"Failed to read BPF map {map_name}: {e}")
        traceback.print_exc()
        return []


def verify_bpf_attached(iface):
    res = subprocess.getoutput(f"tc filter show dev {iface} ingress")
    if "tc_flow" not in res:
        die(f"BPF program not attached to {iface}")


def export(flows, output_path):
    import csv

    if not flows:
        log("No flows to export.")
        return

    field_names = [f.name for f in fields(FlowRecord)]
    file_exists = os.path.isfile(output_path)

    with open(output_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=field_names)
        if not file_exists:
            writer.writeheader()
        for flow in flows:
            writer.writerow(flow.__dict__)

    log(f"Saved {len(flows)} flows to {output_path}")


def main():
    check_root()
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", type=str, default="lo")
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--output", type=str, default="ml/data/real_flows.csv")
    parser.add_argument("--bpf-obj", type=str, default="tc_flow_full.bpf.o")
    args = parser.parse_args()

    verify_bpf_attached(args.iface)

    log(f"Capturing for {args.duration}s...")
    time.sleep(args.duration)

    log("Reading flow data...")
    raw_entries = read_bpf_map("flow_map")
    flows = parse_flows_from_map(raw_entries)
    export(flows, args.output)


if __name__ == "__main__":
    main()
