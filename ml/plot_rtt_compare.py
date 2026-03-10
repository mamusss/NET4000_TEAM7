#!/usr/bin/env python3
import argparse
import csv
import os

import matplotlib.pyplot as plt


def load_rows(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))

    by_mode = {row["mode"]: row for row in rows}
    if "baseline" not in by_mode or "ebpf" not in by_mode:
        raise ValueError("CSV must contain 'baseline' and 'ebpf' rows")
    return by_mode


def f(row, key, default=0.0):
    val = row.get(key, "")
    if val is None or val == "":
        return default
    return float(val)


def main():
    parser = argparse.ArgumentParser(description="Plot baseline vs eBPF RTT comparison")
    parser.add_argument("--input", default="runs/rtt_compare.csv")
    parser.add_argument("--output", default="ml/results/rtt_compare.png")
    args = parser.parse_args()

    data = load_rows(args.input)
    baseline = data["baseline"]
    ebpf = data["ebpf"]

    b_avg = f(baseline, "ping_avg_ms")
    b_mdev = f(baseline, "ping_mdev_ms")
    e_avg = f(ebpf, "ping_avg_ms")
    e_mdev = f(ebpf, "ping_mdev_ms")
    bpf_avg = f(ebpf, "bpf_rtt_avg_ms")

    overhead_pct = ((e_avg - b_avg) / b_avg * 100.0) if b_avg > 0 else 0.0

    fig, ax = plt.subplots(figsize=(8, 5))

    labels = ["Baseline ping", "Ping with eBPF"]
    values = [b_avg, e_avg]
    errs = [b_mdev, e_mdev]
    colors = ["#4C78A8", "#F58518"]

    bars = ax.bar(labels, values, yerr=errs, capsize=6, color=colors)
    ax.set_ylabel("Average RTT (ms)")
    ax.set_title("Baseline vs eBPF RTT Overhead")
    ax.grid(axis="y", alpha=0.25)

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            val,
            f"{val:.4f} ms",
            ha="center",
            va="bottom",
            fontsize=10,
        )

    details = (
        f"Overhead: {overhead_pct:.2f}%\\n"
        f"eBPF map avg RTT: {bpf_avg:.4f} ms"
    )
    ax.text(
        0.02,
        0.98,
        details,
        transform=ax.transAxes,
        va="top",
        ha="left",
        bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "#cccccc"},
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    fig.tight_layout()
    fig.savefig(args.output, dpi=150)
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
