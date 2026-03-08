# eBPF Flow Capture Pipeline

This directory contains the eBPF-based flow capture system that tracks network traffic flows and exports them to CSV for ML training.

## Quick Start

```bash
# Prime sudo first
sudo -v

# Run the full pipeline (capture 30 seconds on loopback)
bash src/run_ebpf_export.sh lo 30 ml/data/real_flows.csv
```

## Files

- **run_ebpf_export.sh** - Main script that compiles, attaches, captures, exports
- **ebpf_export.py** - Python script that reads BPF map and exports to CSV
- **tc_flow.bpf.c** - eBPF TC program (3-tuple: protocol + ports)
- **tc_flow_full.bpf.c** - Full eBPF TC program (5-tuple: IPs + protocol + ports)
- **test_ebpf_all_traffic.sh** - Comprehensive test with all traffic types
- **ebpf_export_full.py** - Exporter for tc_flow_full.bpf.c

## Two BPF Programs

### 1. tc_flow.bpf.c (Original - 3-tuple)
- Tracks: protocol, src_port, dst_port
- Simpler, less memory
- Good for quick classification by port

### 2. tc_flow_full.bpf.c (Enhanced - 5-tuple)
- Tracks: src_ip, dst_ip, protocol, src_port, dst_port
- Full connection tracking
- Includes: min_ipt_ms, max_ipt_ms, duration_ms, avg_ipt_ms

## Traffic Types Detected

- **ICMP** - Ping requests
- **TCP** - HTTP (80, 443, 8080), SSH (22), FTP (21), SMTP (25, 465, 587)
- **UDP** - DNS (53)
- **Other** - Unknown protocols

## Output Format

CSV with headers:
```
protocol,src_ip,dst_ip,src_port,dst_port,pkt_count,byte_count,duration_ms,avg_ipt_ms,min_ipt_ms,max_ipt_ms,label
```

Example:
```
1,127.0.0.1,127.0.0.1,0,60402,1,98,0.0,0.0,0.0,0.0,ICMP
6,127.0.0.1,127.0.0.1,58918,8080,1,74,0.0,0.0,0.0,0.0,HTTP
17,127.0.0.1,127.0.0.1,37844,53,1,70,0.0,0.0,0.0,0.0,DNS
```

## Requirements

- Root privileges (sudo)
- clang with BPF target support
- iproute2 (tc command)
- bpftool
- Python 3

## Testing

Run comprehensive test with all traffic types:
```bash
sudo bash src/test_ebpf_all_traffic.sh lo 20 ml/data/real_flows.csv
```

## Troubleshooting

### "Map 'flow_map' not found"
The eBPF program isn't attached. Check:
```bash
sudo tc filter show dev lo ingress
sudo bpftool map show | grep flow_map
```

### "No flows captured"
- No traffic during capture period
- Wrong interface selected
- Interface was down

### Interface Selection
- **lo** - Loopback (local traffic, easiest)
- **eth0/wlo1** - Physical interfaces
