# eBPF Flow Capture Pipeline

Capture network traffic and classify flows using eBPF.

## Quick Start (One Command)

```bash
sudo bash src/test_ebpf_all_traffic.sh lo 20 ml/data/real_flows.csv
```

This captures traffic, runs ML classification, and produces results.

## What Happens

1. eBPF program captures network flows (kernel-space)
2. Flows are classified rule-based in kernel
3. ML model classifies in user-space
4. Results saved to CSV

## Run Components Separately

```bash
# Capture traffic only
sudo bash src/run_ebpf_export.sh lo 30 ml/data/real_flows.csv

# Compare classifiers (kernel vs ML)
./ml_env/bin/python ml/compare_classifiers.py

# Train ML model
./ml_env/bin/python ml/train.py
```

## Output Files

| File | Description |
|------|-------------|
| `ml/data/real_flows.csv` | Captured flow data with classifications |
| `ml/results/classifier_comparison.png` | Kernel vs ML comparison |
| `ml/results/confusion_matrices.png` | ML model performance |
| `ml/results/accuracy_vs_overhead.png` | Model accuracy vs latency |

## CSV Format

```
protocol,src_ip,dst_ip,src_port,dst_port,pkt_count,byte_count,
duration_ms,avg_ipt_ms,min_ipt_ms,max_ipt_ms,kernel_label,label
```

- `kernel_label` = classification from eBPF (rule-based)
- `label` = classification from ML model
