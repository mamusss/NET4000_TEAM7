# eBPF (tc) Mini Guide

Write → Compile → Attach → Verify → View Results

> **Prerequisite:** Your environment must already have clang, bpftool, tc, and vmlinux.h generation configured and working.

---

## Step 1: Create a New eBPF TC Program

Create a new file:
```
src/<name>.bpf.c
```
### Minimum Required Includes

```c
#include "bpf/vmlinux.h"      // BTF types (generated vmlinux.h)
#include <bpf/bpf_helpers.h>  // SEC(), helpers, map macros
#include <bpf/bpf_endian.h>   // optional: byte order helpers
```

### About These Headers

- **vmlinux.h:** Generated from your running kernel's BTF. Lets you use kernel types safely (CO-RE style approach).
- **bpf_helpers.h:** Provides the `SEC()` macro and helper function declarations.

---
## Step 2: Compile the .bpf.c into a bpf.o

Run from the repo root (important so `-I./src` finds `src/bpf/vmlinux.h`):

```bash
clang -O2 -g -target bpf -c src/<file-name>.bpf.c -o src/<file-name>.bpf.o -I./src
ls -l src/<file-name>.bpf.o
```

---

## Step 3: Attach to a Network Interface Using tc

### 1. Pick Your Interface

List available interfaces:
```bash
ip link
```

Examples: `wlo1`, `eth0`, `ens3`

### 2. Attach to Ingress

```bash
sudo tc qdisc replace dev wlo1 clsact
sudo tc filter replace dev wlo1 ingress bpf da obj src/tc_count.bpf.o sec tc
```

### What This Does

- **clsact:** Creates tc hooks for ingress + egress
- **tc filter ... ingress bpf:** Attaches your eBPF program at the ingress hook
- **da (direct-action):** The eBPF return code directly decides what happens (pass/drop/etc.)

---

## Step 4: Verify It's Attached

```bash
sudo tc qdisc show dev wlo1
sudo tc filter show dev wlo1 ingress
```

You should see:
- ✓ `qdisc clsact` is present on the interface
- ✓ A `bpf` filter is attached to ingress
- ✓ `jited` indicates the program was JIT-compiled by the kernel

---

## Step 5: View Results (Map Counters)

### Find the Map ID

```bash
sudo bpftool map show | grep "name pkt_cnt"
```

### Dump Per-CPU Counters

Replace `3` with your actual map ID:

```bash
sudo bpftool map dump id 3
```

---

## Step 6: Cleanup

### Remove the Ingress Filter

```bash
sudo tc filter del dev wlo1 ingress
```

### Remove the clsact qdisc

```bash
sudo tc qdisc del dev wlo1 clsact
```

This removes all hooks from the interface.
