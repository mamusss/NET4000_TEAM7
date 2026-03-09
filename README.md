# NET4000_TEAM7 - Network Traffic Classification with eBPF

Capture and classify network traffic using eBPF for ML training.

## Quick Start

```bash
# Full pipeline
sudo bash src/test_ebpf_all_traffic.sh lo 20 ml/data/real_flows.csv

# Train ML
./ml_env/bin/python ml/train.py
```

## Project Structure

- [src/](./src) - eBPF programs and capture scripts
- [ml/](./ml) - ML training and data
- [scripts/traffic/](./scripts/traffic) - Traffic generation
- [scripts/bench/](./scripts/bench) - Benchmarks
