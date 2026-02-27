#!/usr/bin/env python3
import argparse, csv, os, time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

def flow_key(pkt):
    if IP not in pkt:
        return None
    proto = pkt[IP].proto
    src, dst = pkt[IP].src, pkt[IP].dst
    sport = dport = 0
    if TCP in pkt: sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt: sport, dport = pkt[UDP].sport, pkt[UDP].dport
    if (src, sport) > (dst, dport):
        src, dst, sport, dport = dst, src, dport, sport
    return (proto, src, sport, dst, dport)

def label_flow(proto, sport, dport):
    ports = {sport, dport}
    if proto == 1: return "ICMP"
    if ports & {80, 443, 8000, 8080}: return "HTTP"
    if ports & {53}: return "DNS"
    if ports & {22}: return "SSH"
    if ports & {5201}: return "IPERF3"
    return "OTHER"

flows = defaultdict(lambda: {"pkts": [], "bytes": 0})

def process_packet(pkt):
    key = flow_key(pkt)
    if key is None: return
    flows[key]["pkts"].append(time.time())
    flows[key]["bytes"] += len(pkt)

def export(output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    rows = []
    for (proto, src, sport, dst, dport), data in flows.items():
        pkts = data["pkts"]
        if len(pkts) < 1: continue
        pkt_count  = len(pkts)
        byte_count = data["bytes"]
        duration_ms = (pkts[-1] - pkts[0]) * 1000 if len(pkts) > 1 else 0.0
        ipts = [(pkts[i+1] - pkts[i]) * 1000 for i in range(len(pkts)-1)]
        avg_ipt_ms = sum(ipts) / len(ipts) if ipts else 0.0
        rows.append({
            "protocol": proto, "src_port": sport, "dst_port": dport,
            "pkt_count": pkt_count, "byte_count": byte_count,
            "duration_ms": round(duration_ms, 3),
            "avg_ipt_ms": round(avg_ipt_ms, 3),
            "label": label_flow(proto, sport, dport),
        })
    fieldnames = ["protocol","src_port","dst_port","pkt_count","byte_count","duration_ms","avg_ipt_ms","label"]
    with open(output_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader(); w.writerows(rows)
    print(f"\nSaved {len(rows)} flows to {output_path}")
    from collections import Counter
    for lbl, cnt in sorted(Counter(r["label"] for r in rows).items()):
        print(f"  {lbl:10s}: {cnt} flows")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--iface", type=str, default="lo")
    parser.add_argument("--output", type=str, default="ml/data/real_flows.csv")
    args = parser.parse_args()
    print(f"Capturing on {args.iface} for {args.duration}s ...")
    print("Run your traffic scripts now!\n")
    sniff(iface=args.iface, filter="ip", prn=process_packet, timeout=args.duration, store=False)
    export(args.output)
