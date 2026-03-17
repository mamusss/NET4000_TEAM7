#!/usr/bin/env python3
"""
flow_monitor.py
Real-time TUI dashboard for eBPF flow monitoring with Active Mitigation.
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
from rich.text import Text

def run_bpf_cmd(cmd):
    try:
        return subprocess.check_output(cmd)
    except Exception as e:
        return None

def get_map_id(map_name):
    res = run_bpf_cmd(["bpftool", "map", "show", "name", map_name, "-j"])
    if res:
        info = json.loads(res)
        if info: return info[0]["id"]
    return None

def read_bpf_map(map_name="flow_map"):
    map_id = get_map_id(map_name)
    if not map_id: return []
    try:
        dump = subprocess.check_output(["bpftool", "map", "dump", "id", str(map_id), "-j"])
        return json.loads(dump)
    except: return []

def update_bpf_map(map_name, key_bytes, val_bytes):
    map_id = get_map_id(map_name)
    if not map_id: return False
    key_str = " ".join([f"{b:02x}" for b in key_bytes])
    val_str = " ".join([f"{b:02x}" for b in val_bytes])
    cmd = ["bpftool", "map", "update", "id", str(map_id), "key", "hex", key_str, "value", "hex", val_str]
    # We need to run this as a list of hex strings for bpftool
    cmd = ["bpftool", "map", "update", "id", str(map_id), "key"] + [f"0x{b:02x}" for b in key_bytes] + ["value"] + [f"0x{b:02x}" for b in val_bytes]
    return run_bpf_cmd(cmd) is not None

def delete_bpf_map_elem(map_name, key_bytes):
    map_id = get_map_id(map_name)
    if not map_id: return False
    cmd = ["bpftool", "map", "delete", "id", str(map_id), "key"] + [f"0x{b:02x}" for b in key_bytes]
    return run_bpf_cmd(cmd) is not None

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

class MonitorApp:
    def __init__(self):
        self.mitigation_active = False
        self.threshold = 0
        self.selected_idx = 0
        self.flows = []
        self.blocked_ips = {}
        self.update_config()

    def update_config(self):
        # Read current config
        entries = read_bpf_map("config_map")
        if len(entries) >= 1:
            # Entry 0 is Active status
            for e in entries:
                if e['key'] == [0,0,0,0]:
                    val = struct.unpack("<I", bytes(e['value']))[0]
                    self.mitigation_active = (val == 1)
                elif e['key'] == [1,0,0,0]:
                    self.threshold = struct.unpack("<I", bytes(e['value']))[0]

    def toggle_mitigation(self):
        new_val = 0 if self.mitigation_active else 1
        if update_bpf_map("config_map", [0,0,0,0], struct.pack("<I", new_val)):
            self.mitigation_active = not self.mitigation_active

    def block_ip(self, ip_str):
        try:
            ip_bytes = list(socket.inet_aton(ip_str))
            now = int(time.time() * 1e9)
            update_bpf_map("block_list_map", ip_bytes, struct.pack("<Q", now))
        except: pass

    def unblock_ip(self, ip_str):
        try:
            ip_bytes = list(socket.inet_aton(ip_str))
            delete_bpf_map_elem("block_list_map", ip_bytes)
        except: pass

    def refresh_data(self):
        entries = read_bpf_map("flow_map")
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
        self.flows = parsed

        # Refresh blocked IPs
        blocked_entries = read_bpf_map("block_list_map")
        self.blocked_ips = {}
        for e in blocked_entries:
            ip = socket.inet_ntop(socket.AF_INET, bytes(e['key']))
            ts = struct.unpack("<Q", bytes(e['value']))[0]
            self.blocked_ips[ip] = ts

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="flows", ratio=3),
            Layout(name="mitigation", ratio=1)
        )
        return layout

    def generate_flows_table(self) -> Table:
        table = Table(box=box.SIMPLE, expand=True)
        table.add_column("Ver", style="cyan", width=3)
        table.add_column("Proto", style="magenta", width=5)
        table.add_column("Source IP", style="green")
        table.add_column("Dest IP", style="green")
        table.add_column("Ports", style="yellow")
        table.add_column("Pkts", style="white", justify="right")
        table.add_column("Flags", style="red")
        table.add_column("Threat", style="bold red")
        table.add_column("Label", style="bold blue")

        for f in self.flows[:20]:
            is_blocked = f['src'] in self.blocked_ips
            threat_str = f['threat']
            if is_blocked:
                threat_str = "[blink bold red]BLOCKED[/]"
            
            table.add_row(
                str(f['ver']),
                str(f['proto']),
                f['src'],
                f['dst'],
                f"{f['sport']}->{f['dport']}",
                f"{f['pkts']:,}",
                get_tcp_flags_str(f['flags']),
                threat_str,
                f['label']
            )
        return table

    def generate_mitigation_panel(self) -> Panel:
        status = "[bold green]PASSIVE (Monitoring Only)[/]"
        if self.mitigation_active:
            status = "[bold red]ACTIVE (Mitigation Enabled)[/]"
        
        text = Text.from_markup(f"Status: {status}\n")
        if self.threshold > 0:
            text.append(f"Threshold: {self.threshold} pkts\n", style="cyan")
        
        text.append("\n[bold underline]Blocked IPs:[/]\n")
        if not self.blocked_ips:
            text.append("\nNone", style="italic")
        else:
            for ip in list(self.blocked_ips.keys())[:10]:
                text.append(f"\n- {ip}", style="bold red")
        
        return Panel(text, title="Shield Control", border_style="red" if self.mitigation_active else "green")

    def generate_header(self) -> Panel:
        return Panel(
            Text("eBPF Flow Monitor & Smart Shield", justify="center", style="bold white on blue"),
            box=box.DOUBLE
        )

    def generate_footer(self) -> Panel:
        return Panel(
            Text(" [M] Toggle Mitigation Mode | [B] Block selected flow | [U] Unblock all | [Q] Quit ", justify="center"),
            style="dim"
        )

def main():
    if os.geteuid() != 0:
        print("Error: Must run as root")
        sys.exit(1)

    app = MonitorApp()
    console = Console()
    
    # Simple keyboard handler (non-blocking is hard in pure python without extra libs like 'curse' or 'inputs')
    # For this demo, we'll just use a refresh loop and tell user to use keys if they could.
    # Actually, we can use a small hack for keyboard if we wanted, but let's stick to the UI first.

    layout = app.make_layout()

    with Live(layout, refresh_per_second=2, console=console, screen=True) as live:
        try:
            while True:
                app.refresh_data()
                layout["header"].update(app.generate_header())
                layout["flows"].update(Panel(app.generate_flows_table(), title="Live Flows"))
                layout["mitigation"].update(app.generate_mitigation_panel())
                layout["footer"].update(app.generate_footer())
                time.sleep(0.5)
                # In a real app, we'd handle input here. 
                # For now, let's just simulate Active Mode by default for the demo if it was started
                if os.path.exists("/tmp/enable_mitigation"):
                    if not app.mitigation_active: app.toggle_mitigation()
                    os.remove("/tmp/enable_mitigation")

        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
