#!/usr/bin/env python3
"""
flow_monitor.py
Real-time TUI dashboard for eBPF flow monitoring.
"""

import matplotlib
matplotlib.use("Agg")
import sys, os, time, struct, socket, subprocess, json
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from rich import box

def read_bpf_map(map_name="flow_map"):
# ...
    cmd = ["bpftool", "map", "show", "name", map_name, "-j"]
    try:
        res = subprocess.check_output(cmd)
        map_info = json.loads(res)
        if not map_info: return []
        map_id = map_info[0]["id"]
        dump = subprocess.check_output(["bpftool", "map", "dump", "id", str(map_id), "-j"])
        return json.loads(dump)
    except: return []

def ip_to_str(ver, ip_bytes):
    try:
        if ver == 4:
            return socket.inet_ntop(socket.AF_INET, bytes(ip_bytes[:4]))
        return socket.inet_ntop(socket.AF_INET6, bytes(ip_bytes))
    except: return "???"

def get_tcp_flags_str(flags):
    f = []
    if flags & 0x01: f.append("F")
    if flags & 0x02: f.append("S")
    if flags & 0x04: f.append("R")
    if flags & 0x08: f.append("P")
    if flags & 0x10: f.append("A")
    if flags & 0x20: f.append("U")
    return "".join(f) if f else "-"

LABELS = {1:"ICMP", 2:"HTTP", 3:"HTTPS", 4:"DNS", 5:"SSH", 6:"IPERF", 7:"QUIC"}
THREATS = {0:"-", 1:"SCAN", 2:"SYN", 3:"RATE"}

def generate_table() -> Table:
    table = Table(box=box.SIMPLE)
    table.add_column("Ver", style="cyan")
    table.add_column("Proto", style="magenta")
    table.add_column("Source IP", style="green")
    table.add_column("Dest IP", style="green")
    table.add_column("Ports", style="yellow")
    table.add_column("Pkts", style="white")
    table.add_column("Flags", style="red")
    table.add_column("Threat", style="bold red")
    table.add_column("Label", style="bold blue")

    entries = read_bpf_map()
    # Sort by packet count descending
    parsed = []
    for e in entries:
        k, v = bytes(e['key']), bytes(e['value'])
        ver = k[33]
        parsed.append({
            'ver': ver,
            'proto': k[32],
            'src': ip_to_str(ver, k[0:16]),
            'dst': ip_to_str(ver, k[16:32]),
            'sport': struct.unpack(">H", k[34:36])[0],
            'dport': struct.unpack(">H", k[36:38])[0],
            'pkts': struct.unpack("<Q", v[0:8])[0],
            'flags': v[56],
            'label': LABELS.get(v[57], "OTHER"),
            'threat': THREATS.get(v[58], "???")
        })
    
    parsed.sort(key=lambda x: x['pkts'], reverse=True)

    for p in parsed[:15]:
        table.add_row(
            str(p['ver']),
            str(p['proto']),
            p['src'],
            p['dst'],
            f"{p['sport']}->{p['dport']}",
            f"{p['pkts']:,}",
            get_tcp_flags_str(p['flags']),
            p['threat'],
            p['label']
        )
    return table

def main():
    if os.geteuid() != 0:
        print("Error: Must run as root")
        sys.exit(1)

    console = Console()
    with Live(generate_table(), refresh_per_second=2, console=console) as live:
        try:
            while True:
                time.sleep(0.5)
                live.update(generate_table())
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
