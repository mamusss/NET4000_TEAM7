# eBPF Flow Capture Pipeline

Capture and classify network traffic using eBPF.

## Quick Start

```bash
sudo bash src/test_ebpf_all_traffic.sh lo 20 ml/data/real_flows.csv
```

## What It Does

1. Captures network flows with eBPF
2. Classifies in kernel (rule-based) and user-space (ML)
3. Compares both classifiers with statistics
4. Outputs results to CSV and plots

## Run Separately

```bash
# Capture
sudo bash src/run_ebpf_export.sh lo 30 ml/data/real_flows.csv

# Compare
./ml_env/bin/python ml/compare_classifiers.py

# Train
./ml_env/bin/python ml/train.py
```

## Output Files

- `ml/data/real_flows.csv` - Flow data
- `ml/results/classifier_comparison.png` - Kernel vs ML
- `ml/results/confusion_matrices.png` - ML performance
- `ml/results/accuracy_vs_overhead.png` - Accuracy vs latency
