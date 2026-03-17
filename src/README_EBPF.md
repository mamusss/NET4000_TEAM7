# eBPF Flow Capture Pipeline

Technical documentation for the high-performance eBPF capture suite.

## Core Component: tc_flow_full.bpf.c

This program implements a unified IPv4/IPv6 flow tracker attached to the Traffic Control (TC) ingress hook.

### Unified Flow Key
The program handles dual-stack traffic using a 40-byte `flow_key`:
- `src_ip[4]`, `dst_ip[4]`: 16-byte address buffers.
- `protocol`: L4 protocol (TCP=6, UDP=17, ICMP=1, ICMPv6=58).
- `version`: IP version (4 or 6).
- `src_port`, `dst_port`: L4 source and destination ports.

### TCP Flags Extraction
For TCP traffic, the program extracts flags from the header and aggregates them using a bitwise OR operation across the flow's lifetime.
- SYN (0x02), ACK (0x10), FIN (0x01), RST (0x04), PSH (0x08), URG (0x20)
- These flags are exposed in the `tcp_flags` column of the exported dataset, enabling advanced ML analysis for session behavior and threat detection.

## Monitoring & Exporting

- **Real-time TUI**: `src/flow_monitor.py` provides a live view of active flows, including packet counts, byte sizes, and classifications. Requires the `rich` library.
- **CSV Exporter**: `src/ebpf_export_full.py` polls the `flow_map` and writes sanitized flow records to a CSV file.

### Output CSV Columns
| Column | Description |
|--------|-------------|
| `version` | IP version (4 or 6) |
| `protocol` | L4 protocol ID |
| `src_ip`, `dst_ip` | Source and destination addresses (string) |
| `src_port`, `dst_port` | L4 ports |
| `pkt_count`, `byte_count` | Aggregated counters |
| `duration_ms` | Flow lifetime in milliseconds |
| `avg_ipt_ms` | Average Inter-packet Time |
| `tcp_flags` | Cumulative TCP flags bitmask |
| `kernel_label` | Rule-based classification from the kernel |
| `label` | Ground truth classification for ML training |

## Build & Attach

The Makefile handles standard build and attach operations:
```bash
make build
sudo tc filter add dev lo ingress bpf da obj src/tc_flow_full.bpf.o sec tc
```
