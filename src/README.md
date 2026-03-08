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

---

## Developer Guide

### Create New eBPF Program

```c
#include "bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct { ... } my_map SEC(".maps");

SEC("tc")
int my_prog(struct __sk_buff *skb) {
    // process packet
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
```

### Compile

```bash
clang -O2 -g -target bpf -c src/my_prog.bpf.c -o src/my_prog.bpf.o -I./src
```

### Attach Manually

```bash
sudo tc qdisc replace dev lo clsact
sudo tc filter replace dev lo ingress bpf da obj src/my_prog.bpf.o sec tc
```

### Verify

```bash
sudo tc filter show dev lo ingress
sudo bpftool map show | grep my_map
```

### Cleanup

```bash
sudo tc filter del dev lo ingress
sudo tc qdisc del dev lo clsact
```
