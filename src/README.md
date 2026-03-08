# eBPF Flow Capture

Capture network traffic flows for ML training using eBPF.

## Quick Start

```bash
# Capture 30 seconds of traffic on loopback
sudo bash src/run_ebpf_export.sh lo 30 ml/data/real_flows.csv

# Or run test with all traffic types
sudo bash src/test_ebpf_all_traffic.sh lo 20 ml/data/real_flows.csv
```

## Output

`real_flows.csv` with columns:
- protocol (1=ICMP, 6=TCP, 17=UDP)
- src_ip, dst_ip, src_port, dst_port
- pkt_count, byte_count, duration_ms, avg_ipt_ms
- label (HTTP, DNS, ICMP, SSH, etc.)

## Files

- `run_ebpf_export.sh` - Main capture script
- `ebpf_export.py` - Python exporter
- `tc_flow.bpf.c` - eBPF program (3-tuple)
- `tc_flow_full.bpf.c` - eBPF program (5-tuple)
- `test_ebpf_all_traffic.sh` - Test with all traffic types

## RTT Benchmark

```bash
sudo bash scripts/bench/compare_rtt.sh lo 127.0.0.1 30
```

Outputs: `runs/rtt_compare.csv`, `ml/results/rtt_compare.png`
