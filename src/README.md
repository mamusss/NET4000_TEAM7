# eBPF Flow Capture Pipeline

Capture and classify network traffic using eBPF with real-time threat detection.

## Quick Start

```bash
sudo bash src/test_ebpf_all_traffic.sh lo 20 ml/data/real_flows.csv
```

## What It Does

1. Captures network flows with eBPF
2. Classifies traffic (HTTP, DNS, SSH, ICMP, etc.)
3. Detects threats in real-time (port scan, rate limiting)
4. **Adaptive ML Shield**: Mitigates threats by dropping packets in kernel.
5. Compares kernel vs ML classification

## Run Separately

```bash
# Capture traffic
sudo bash src/run_ebpf_export.sh lo 30 ml/data/real_flows.csv

# Compare classifiers
./ml_env/bin/python ml/compare_classifiers.py

# Train ML model
./ml_env/bin/python ml/train.py
```

## Output Files

| File | Description |
|------|-------------|
| `ml/data/real_flows.csv` | Flow data with classifications |
| `ml/results/classifier_comparison.png` | Kernel vs ML comparison |
| `ml/results/confusion_matrices.png` | ML performance |
| `ml/results/accuracy_vs_overhead.png` | Accuracy vs latency |

## CSV Format

```
protocol,src_ip,dst_ip,src_port,dst_port,pkt_count,...,kernel_label,threat,label
```

- `kernel_label` - Rule-based classification in kernel
- `threat` - Detected threats (none, port_scan, rate_limit)
- `label` - ML classification

## Threat Detection

Detects threats **in real-time at kernel level** before they reach user-space:

| Threat | Description | Threshold |
|--------|------------|-----------|
| `port_scan` | Many different ports contacted | >50 unique ports |
| `rate_limit` | Too many packets from same IP | >500 packets |
| `none` | Normal traffic | - |

Benefits:
- Zero latency (runs in kernel)
- Can drop/block malicious packets immediately
- No user-space processing needed
