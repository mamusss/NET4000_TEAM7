#include "bpf/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1

struct ethhdr_ {
  __u8 h_dest[6];
  __u8 h_source[6];
  __be16 h_proto;
};

struct iphdr_ {
  __u8 ihl : 4, version : 4;
  __u8 tos;
  __be16 tot_len;
  __be16 id;
  __be16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __be16 check;
  __be32 saddr;
  __be32 daddr;
};

struct icmphdr_ {
  __u8 type;
  __u8 code;
  __be16 checksum;
  __be16 id;
  __be16 sequence;
};

struct rtt_key {
  __u16 id;
  __u16 seq;
  __u32 remote_ip; // request uses daddr, reply uses saddr
};

struct rtt_stats {
  __u64 count;
  __u64 sum_ns;
  __u64 min_ns;
  __u64 max_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct rtt_key);
  __type(value, __u64); // send timestamp (ns)
} send_ts SEC(".maps");

// Per-CPU stats so updates are cheap and verifier-friendly.
// You aggregate per-CPU values in user space (bpftool dump).
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct rtt_stats);
} stats SEC(".maps");

static __always_inline int parse_and_handle(struct __sk_buff *skb) {
  struct ethhdr_ eth;
  struct iphdr_ ip;
  struct icmphdr_ icmp;

  // Read Ethernet header
  if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
    return BPF_OK;

  if (bpf_ntohs(eth.h_proto) != ETH_P_IP)
    return BPF_OK;

  // Read IPv4 header (assume no VLAN; works for typical labs)
  if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0)
    return BPF_OK;

  if (ip.protocol != IPPROTO_ICMP)
    return BPF_OK;

  // Compute IP header length (ihl is in 32-bit words)
  __u32 ip_hlen = (__u32)ip.ihl * 4;
  if (ip_hlen < 20 || ip_hlen > 60)
    return BPF_OK;

  // Read ICMP header after Ethernet+IP header
  __u32 icmp_off = sizeof(eth) + ip_hlen;
  if (bpf_skb_load_bytes(skb, icmp_off, &icmp, sizeof(icmp)) < 0)
    return BPF_OK;

  // ICMP Echo Request = 8, Echo Reply = 0
  if (!(icmp.type == 8 || icmp.type == 0))
    return BPF_OK;

  struct rtt_key key = {};
  key.id = bpf_ntohs(icmp.id);
  key.seq = bpf_ntohs(icmp.sequence);

  __u64 now = bpf_ktime_get_ns();

  if (icmp.type == 8) {
    // Echo request: remote is destination
    key.remote_ip = ip.daddr;

    // Store timestamp
    bpf_map_update_elem(&send_ts, &key, &now, BPF_ANY);
    return BPF_OK;
  }

  // Echo reply: remote is source
  key.remote_ip = ip.saddr;

  __u64 *t0 = bpf_map_lookup_elem(&send_ts, &key);
  if (!t0)
    return BPF_OK;

  __u64 rtt = now - *t0;

  // Update per-CPU stats
  __u32 s_key = 0;
  struct rtt_stats *st = bpf_map_lookup_elem(&stats, &s_key);
  if (st) {
    if (st->count == 0) {
      st->min_ns = rtt;
      st->max_ns = rtt;
    } else {
      if (rtt < st->min_ns)
        st->min_ns = rtt;
      if (rtt > st->max_ns)
        st->max_ns = rtt;
    }
    st->count += 1;
    st->sum_ns += rtt;
  }

  // Prevent map from growing forever
  bpf_map_delete_elem(&send_ts, &key);

  return BPF_OK;
}

SEC("tc")
int tc_icmp_rtt(struct __sk_buff *skb) { return parse_and_handle(skb); }

char LICENSE[] SEC("license") = "GPL";
