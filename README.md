# NET4000_TEAM7 - Network Traffic Classification with eBPF

Capture and classify network traffic using eBPF for ML training.

## Quick Start

```bash
# Capture traffic flows
sudo bash src/run_ebpf_export.sh lo 30 ml/data/real_flows.csv

# Train ML model
python3 ml/train.py
```

## Project Structure

- `src/` - eBPF programs and capture scripts
- `ml/` - ML training and data
- `scripts/traffic/` - Traffic generation
- `scripts/bench/` - Benchmarks

## See Also

- `src/README.md` - eBPF flow capture details
- `scripts/traffic/README.md` - Traffic generation details
