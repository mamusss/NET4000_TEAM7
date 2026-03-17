#!/usr/bin/env python3
"""
ebpf_export.py
Reads per-flow features from the tc_flow BPF map and exports to CSV.

Usage:
    sudo python3 src/ebpf_export.py --iface <interface> --duration 60

Full workflow:
    # 1. Attach eBPF program first (or use run_ebpf_export.sh which does it all)
    # 2. Run traffic + export
    # 3. Detach when done (run_ebpf_export.sh handles cleanup automatically)
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time


def log(msg, file=sys.stdout):
    print(msg, file=file)
    file.flush()


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def check_bpftool():
    """Check if bpftool is available."""
    try:
        subprocess.run(["bpftool", "version"], capture_output=True, check=True)
    except FileNotFoundError:
        die("bpftool not found. Install bpftool package.")
    except subprocess.CalledProcessError:
        die("bpftool failed to run.")


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        die("This script must be run as root (sudo)")


def verify_interface(iface):
    """Verify the interface exists and is up."""
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface], capture_output=True, text=True, check=True
        )
        if "state UP" not in result.stdout:
            log(f"WARNING: Interface {iface} may not be UP")
        return True
    except subprocess.CalledProcessError:
        die(f"Interface {iface} does not exist")
    return False


def verify_bpf_attached(iface):
    """Verify that a BPF filter is attached to the interface."""
    try:
        result = subprocess.run(
            ["tc", "filter", "show", "dev", iface, "ingress"],
            capture_output=True,
            text=True,
            check=True,
        )
        if "bpf" not in result.stdout.lower():
            die(f"No BPF filter attached to {iface} ingress")
        log(f"BPF filter verified on {iface}")
        return True
    except subprocess.CalledProcessError as e:
        die(f"Failed to check tc filters: {e}")
    return False


def label_flow(protocol, src_port, dst_port):
    """Label flow based on protocol and ports."""
    ports = {src_port, dst_port}
    if protocol == 1:
        return "ICMP"
    if ports & {80, 443, 8000, 8080, 8888}:
        return "HTTP"
    if ports & {53, 5353}:
        return "DNS"
    if ports & {22, 2222}:
        return "SSH"
    if ports & {5201, 5202, 5203}:
        return "IPERF3"
    if ports & {5000, 5001, 3000}:
        return "DEV"
    return "OTHER"


def read_bpf_map(map_name="flow_map"):
    """
    Uses bpftool to dump the flow_map contents.
    Returns list of dicts with raw key/value data.
    """
    log(f"Searching for BPF map '{map_name}'...")

    try:
        result = subprocess.run(
            ["bpftool", "map", "show", "-j"], capture_output=True, text=True, check=True
        )
        maps = json.loads(result.stdout)

        map_id = None
        for m in maps:
            if m.get("name") == map_name:
                map_id = m["id"]
                log(f"Found map '{map_name}' with id={map_id}")
                break

        if map_id is None:
            log("Available maps:")
            for m in maps:
                log(f"  - {m.get('name', 'unnamed')} (id={m.get('id')})")
            die(f"Map '{map_name}' not found. Is the eBPF program attached?")

        result = subprocess.run(
            ["bpftool", "map", "dump", "id", str(map_id), "-j"],
            capture_output=True,
            text=True,
            check=True,
        )
        entries = json.loads(result.stdout)
        log(f"Read {len(entries)} entries from map")
        return entries

    except subprocess.CalledProcessError as e:
        die(f"bpftool error: {e.stderr}")
    except json.JSONDecodeError as e:
        die(f"Failed to parse bpftool output: {e}")
    except Exception as e:
        die(f"Error reading BPF map: {e}")


def parse_flows(raw_entries):
    """Parse raw bpftool output into flow records."""
    flows = []
    for entry in raw_entries:
        try:
            key = entry.get("key", [])
            value = entry.get("value", [])

            if not key or not value:
                continue

            if len(key) < 6:
                log(f"Skipping invalid key (length {len(key)}): {key}")
                continue

            if len(value) < 40:
                log(f"Skipping invalid value (length {len(value)}): {value}")
                continue

            def parse_hex(val):
                if isinstance(val, str):
                    return int(val, 16)
                return val

            protocol = parse_hex(key[0])
            src_port = (parse_hex(key[2]) << 8) | parse_hex(key[3])
            dst_port = (parse_hex(key[4]) << 8) | parse_hex(key[5])

            def le64(b, offset):
                if offset + 8 > len(b):
                    return 0
                raw = b[offset : offset + 8]
                if isinstance(raw[0], str):
                    val = 0
                    for i, byte_val in enumerate(raw):
                        val |= parse_hex(byte_val) << (i * 8)
                    return val
                return int.from_bytes(raw, "little")

            pkt_count = le64(value, 0)
            byte_count = le64(value, 8)
            first_ts = le64(value, 16)
            last_ts = le64(value, 24)
            ipt_sum = le64(value, 32)

            if pkt_count == 0:
                continue

            duration_ms = (last_ts - first_ts) / 1e6
            avg_ipt_ms = (ipt_sum / (pkt_count - 1)) / 1e6 if pkt_count > 1 else 0.0

            flows.append(
                {
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "pkt_count": pkt_count,
                    "byte_count": byte_count,
                    "duration_ms": round(duration_ms, 3),
                    "avg_ipt_ms": round(avg_ipt_ms, 3),
                    "label": label_flow(protocol, src_port, dst_port),
                }
            )
        except Exception as e:
            log(f"Warning: Failed to parse entry: {e}")
            continue

    return flows


def export(flows, output_path):
    """Export flows to CSV."""
    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True,
    )
    fieldnames = [
        "protocol",
        "src_port",
        "dst_port",
        "pkt_count",
        "byte_count",
        "duration_ms",
        "avg_ipt_ms",
        "label",
    ]

    with open(output_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(flows)

    log(f"\nSaved {len(flows)} flows to {output_path}")

    from collections import Counter

    counts = Counter(r["label"] for r in flows)
    for lbl, cnt in sorted(counts.items()):
        log(f"  {lbl:10s}: {cnt} flows")

    return len(flows)


def main():
    parser = argparse.ArgumentParser(
        description="Export eBPF flow data to CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 src/ebpf_export.py --iface lo --duration 60
  sudo python3 src/ebpf_export.py --iface eth0 --duration 30 --output /tmp/flows.csv
        """,
    )
    parser.add_argument(
        "--iface",
        type=str,
        default="lo",
        help="Network interface to capture on (default: lo)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Capture duration in seconds (default: 60)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="ml/data/real_flows.csv",
        help="Output CSV file path (default: ml/data/real_flows.csv)",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip verification steps (for testing)",
    )
    args = parser.parse_args()

    log("=== eBPF Flow Exporter ===")
    log(f"Interface: {args.iface}")
    log(f"Duration: {args.duration}s")
    log(f"Output: {args.output}")

    if os.geteuid() != 0:
        die("Must run as root (use sudo)")

    if not args.skip_verify:
        log("\n--- Verification Steps ---")
        check_bpftool()
        verify_interface(args.iface)
        verify_bpf_attached(args.iface)

    log(f"\nCapturing flows for {args.duration}s...")
    log("Press Ctrl+C to stop early (data will still be exported)\n")

    start_time = time.time()
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        log("\nInterrupted by user")

    elapsed = time.time() - start_time
    log(f"\nCapture completed after {elapsed:.1f}s")

    log("Collecting flow data from kernel map...")
    raw = read_bpf_map("flow_map")

    if not raw:
        log("WARNING: No data in BPF map - no traffic was captured during the period")
        log("Possible reasons:")
        log("  1. No traffic was sent on interface $IFACE during capture")
        log("  2. eBPF filter not properly attached")
        log("  3. Traffic was filtered before reaching the BPF hook")
        export([], args.output)
        die("No flows captured")

    flows = parse_flows(raw)
    count = export(flows, args.output)

    if count == 0:
        die("Failed to parse any flows from BPF map")

    log("=== Export Complete ===")


if __name__ == "__main__":
    main()
