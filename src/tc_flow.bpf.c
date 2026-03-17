#// tc_flow.bpf.c
// TC eBPF program that tracks per-flow features in kernel space.
// Features tracked per flow:
//   - protocol, src_port, dst_port
//   - packet count, byte count
//   - first seen timestamp, last seen timestamp (for duration + avg IPT)

#include "bpf/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// ── Flow key (5-tuple without src/dst IP for simplicity) ─────────────────────
struct flow_key {
  __u8 protocol;
  __u16 src_port;
  __u16 dst_port;
};

// ── Flow stats stored in the map ─────────────────────────────────────────────
struct flow_metrics {
  __u64 pkt_count;
  __u64 byte_count;
  __u64 first_ts; // nanoseconds (bpf_ktime_get_ns)
  __u64 last_ts;  // nanoseconds
  __u64 ipt_sum;  // sum of inter-packet times in ns
};

// ── BPF hash map: flow_key -> flow_stats, max 10000 flows ────────────────────
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, struct flow_key);
  __type(value, struct flow_metrics);
} flow_map SEC(".maps");

// ── TC ingress hook
// ───────────────────────────────────────────────────────────
SEC("tc")
int tc_flow(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // Parse Ethernet header (14 bytes)
  if (data + 14 > data_end)
    return BPF_OK;

  __u16 eth_proto = __bpf_ntohs(*(__u16 *)(data + 12));

  // Only handle IPv4 (0x0800)
  if (eth_proto != 0x0800)
    return BPF_OK;

  // Parse IPv4 header
  struct iphdr *ip = data + 14;
  if ((void *)(ip + 1) > data_end)
    return BPF_OK;

  __u8 ihl = (ip->ihl & 0x0f) * 4;

  struct flow_key key = {};
  key.protocol = ip->protocol;
  key.src_port = 0;
  key.dst_port = 0;

  // Extract ports for TCP/UDP
  if (ip->protocol == 6 || ip->protocol == 17) {
    void *transport = (void *)ip + ihl;
    if (transport + 4 > data_end)
      return BPF_OK;
    key.src_port = __bpf_ntohs(*(__u16 *)transport);
    key.dst_port = __bpf_ntohs(*(__u16 *)(transport + 2));
  }

  __u64 now = bpf_ktime_get_ns();
  __u32 plen = skb->len;

  struct flow_metrics *stats = bpf_map_lookup_elem(&flow_map, &key);
  if (stats) {
    __u64 ipt = now - stats->last_ts;
    stats->ipt_sum += ipt;
    stats->last_ts = now;
    stats->pkt_count += 1;
    stats->byte_count += plen;
  } else {
    struct flow_metrics new_stats = {};
    new_stats.pkt_count = 1;
    new_stats.byte_count = plen;
    new_stats.first_ts = now;
    new_stats.last_ts = now;
    new_stats.ipt_sum = 0;
    bpf_map_update_elem(&flow_map, &key, &new_stats, BPF_ANY);
  }

  return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
