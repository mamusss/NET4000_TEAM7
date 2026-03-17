// tc_flow_full.bpf.c
// Unified IPv4/IPv6 support with TCP Flags tracking and Threat Detection.

#include "bpf/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58

// Label IDs for kernel-space classification
#define LABEL_ICMP 1
#define LABEL_HTTP 2
#define LABEL_HTTPS 3
#define LABEL_DNS 4
#define LABEL_SSH 5
#define LABEL_IPERF 6
#define LABEL_QUIC 7
#define LABEL_OTHER 0

// Threat types
#define THREAT_NONE         0
#define THREAT_PORT_SCAN    1
#define THREAT_SYN_FLOOD    2
#define THREAT_RATE_LIMIT   3

// TCP Flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct flow_key {
  __u32 src_ip[4]; // IPv4 uses first element
  __u32 dst_ip[4];
  __u8 protocol;
  __u8 version; // 4 or 6
  __u16 src_port;
  __u16 dst_port;
};

struct flow_metrics {
  __u64 pkt_count;
  __u64 byte_count;
  __u64 first_ts;
  __u64 last_ts;
  __u64 ipt_sum;
  __u64 min_ipt;
  __u64 max_ipt;
  __u8 tcp_flags;
  __u8 kernel_label;
  __u8 threat_level;
  __u8 pad[5];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct flow_key);
  __type(value, struct flow_metrics);
} flow_map SEC(".maps");

// Rate limiting: packet count per IP (IPv4 only for simplicity)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32);
    __type(value, __u64);
} rate_limit_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 128);
  __type(key, __u32);
  __type(value, __u32);
} perf_map SEC(".maps");

struct flow_event {
  __u8 version;
  __u8 protocol;
  __u8 kernel_label;
  __u8 threat_level;
  __u8 tcp_flags;
  __u8 pad[3];
  __u32 src_ip[4];
  __u32 dst_ip[4];
  __u16 src_port;
  __u16 dst_port;
  __u64 pkt_count;
  __u64 byte_count;
  __u64 duration_ns;
  __u64 avg_ipt_ns;
  __u64 min_ipt_ns;
  __u64 max_ipt_ns;
};

static __always_inline __u8 classify_flow(__u8 protocol, __u16 src_port,
                                          __u16 dst_port) {
  if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6)
    return LABEL_ICMP;

  if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
    if (src_port == 80 || dst_port == 80 || src_port == 8080 ||
        dst_port == 8080 || src_port == 8000 || dst_port == 8000 ||
        src_port == 8888 || dst_port == 8888)
      return LABEL_HTTP;
    if (src_port == 443 || dst_port == 443 || src_port == 8443 ||
        dst_port == 8443) {
      if (protocol == IPPROTO_UDP)
        return LABEL_QUIC;
      return LABEL_HTTPS;
    }
    if (src_port == 53 || dst_port == 53 || src_port == 5353 ||
        dst_port == 5353)
      return LABEL_DNS;
    if (src_port == 22 || dst_port == 22 || src_port == 2222 ||
        dst_port == 2222)
      return LABEL_SSH;
    if (src_port == 5201 || dst_port == 5201 || src_port == 5202 ||
        dst_port == 5202 || src_port == 5203 || dst_port == 5203)
      return LABEL_IPERF;
  }

  return LABEL_OTHER;
}

static __always_inline __u8 detect_threats(__u32 src_ip) {
    __u64 *pkt_count = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (pkt_count) {
        (*pkt_count)++;
        if (*pkt_count > 500) {
            return THREAT_RATE_LIMIT;
        }
    } else {
        __u64 count = 1;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &count, BPF_ANY);
    }
    return THREAT_NONE;
}

SEC("tc")
int tc_flow(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (data + 14 > data_end)
    return BPF_OK;

  struct ethhdr *eth = data;
  __u16 eth_proto = __bpf_ntohs(eth->h_proto);

  struct flow_key key = {};
  __u8 protocol = 0;
  __u16 src_port = 0, dst_port = 0;
  __u8 tcp_flags = 0;
  __u8 ip_ihl = 0;
  __u8 threat_level = THREAT_NONE;

  if (eth_proto == ETH_P_IP) {
    struct iphdr *ip = data + 14;
    if ((void *)(ip + 1) > data_end)
      return BPF_OK;
    key.version = 4;
    key.src_ip[0] = ip->saddr;
    key.dst_ip[0] = ip->daddr;
    protocol = ip->protocol;
    ip_ihl = (ip->ihl & 0x0f) * 4;
    threat_level = detect_threats(ip->saddr);
  } else if (eth_proto == ETH_P_IPV6) {
    struct ipv6hdr *ip6 = data + 14;
    if ((void *)(ip6 + 1) > data_end)
      return BPF_OK;
    key.version = 6;
    __builtin_memcpy(key.src_ip, &ip6->saddr, 16);
    __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);
    protocol = ip6->nexthdr;
    ip_ihl = 40;
  } else {
    return BPF_OK;
  }

  key.protocol = protocol;

  if (protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)eth + 14 + ip_ihl;
    if ((void *)(tcp + 1) <= data_end) {
      src_port = __bpf_ntohs(tcp->source);
      dst_port = __bpf_ntohs(tcp->dest);
      tcp_flags = ((__u8 *)tcp)[13];
    }
  } else if (protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)eth + 14 + ip_ihl;
    if ((void *)(udp + 1) <= data_end) {
      src_port = __bpf_ntohs(udp->source);
      dst_port = __bpf_ntohs(udp->dest);
    }
  } else if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
    void *icmp = (void *)eth + 14 + ip_ihl;
    if (icmp + 4 <= data_end) {
      src_port = __bpf_ntohs(*(__u16 *)icmp);
      dst_port = __bpf_ntohs(*(__u16 *)(icmp + 2));
    }
  }

  key.src_port = src_port;
  key.dst_port = dst_port;

  __u8 kernel_label = classify_flow(protocol, src_port, dst_port);
  __u64 now = bpf_ktime_get_ns();
  __u32 plen = skb->len;

  struct flow_metrics *stats = bpf_map_lookup_elem(&flow_map, &key);
  if (stats) {
    __u64 ipt = 0;
    if (stats->last_ts > 0) {
      ipt = now - stats->last_ts;
      stats->ipt_sum += ipt;
      if (stats->pkt_count == 1) {
        stats->min_ipt = ipt;
        stats->max_ipt = ipt;
      } else {
        stats->min_ipt = ipt < stats->min_ipt ? ipt : stats->min_ipt;
        stats->max_ipt = ipt > stats->max_ipt ? ipt : stats->max_ipt;
      }
    }
    stats->last_ts = now;
    stats->pkt_count += 1;
    stats->byte_count += plen;
    stats->tcp_flags |= tcp_flags;
    if (threat_level > stats->threat_level) {
        stats->threat_level = threat_level;
    }

    if (stats->pkt_count >= 2 && stats->pkt_count % 10 == 0) {
      struct flow_event evt = {
          .version = key.version,
          .protocol = protocol,
          .kernel_label = stats->kernel_label,
          .threat_level = stats->threat_level,
          .tcp_flags = stats->tcp_flags,
          .src_port = key.src_port,
          .dst_port = key.dst_port,
          .pkt_count = stats->pkt_count,
          .byte_count = stats->byte_count,
          .duration_ns = stats->last_ts - stats->first_ts,
          .avg_ipt_ns = stats->ipt_sum / (stats->pkt_count - 1),
          .min_ipt_ns = stats->min_ipt,
          .max_ipt_ns = stats->max_ipt,
      };
      __builtin_memcpy(evt.src_ip, key.src_ip, 16);
      __builtin_memcpy(evt.dst_ip, key.dst_ip, 16);
      bpf_perf_event_output(skb, &perf_map, BPF_F_CURRENT_CPU, &evt,
                            sizeof(evt));
    }
  } else {
    struct flow_metrics new_stats = {};
    new_stats.pkt_count = 1;
    new_stats.byte_count = plen;
    new_stats.first_ts = now;
    new_stats.last_ts = now;
    new_stats.min_ipt = 0xFFFFFFFFFFFFFFFFULL;
    new_stats.tcp_flags = tcp_flags;
    new_stats.kernel_label = kernel_label;
    new_stats.threat_level = threat_level;
    bpf_map_update_elem(&flow_map, &key, &new_stats, BPF_ANY);
  }

  return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
