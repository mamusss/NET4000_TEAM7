// tc_flow_full.bpf.c
// Full-featured eBPF TC program with 5-tuple flow tracking (IPv4).
// Tracks: src_ip, dst_ip, protocol, src_port, dst_port
// Includes kernel-space classification (rule-based)

#include "bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP     0x0800
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1

// Label IDs for kernel-space classification
#define LABEL_ICMP      1
#define LABEL_HTTP      2
#define LABEL_HTTPS     3
#define LABEL_DNS       4
#define LABEL_SSH       5
#define LABEL_IPERF     6
#define LABEL_OTHER     0

struct flow_key_v4 {
    __u32 src_ip;
    __u32 dst_ip;
    __u8  protocol;
    __u8  pad[3];
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
    __u8  kernel_label;    // Classification from kernel (rule-based)
    __u8  pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   struct flow_key_v4);
    __type(value, struct flow_metrics);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u32);
} perf_map SEC(".maps");

struct flow_event {
    __u8  version;
    __u8  protocol;
    __u8  kernel_label;
    __u8  pad[5];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u64 pkt_count;
    __u64 byte_count;
    __u64 duration_ns;
    __u64 avg_ipt_ns;
    __u64 min_ipt_ns;
    __u64 max_ipt_ns;
};

static __always_inline __u8 classify_flow(__u8 protocol, __u16 src_port, __u16 dst_port) {
    if (protocol == IPPROTO_ICMP)
        return LABEL_ICMP;
    
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        if (src_port == 80 || dst_port == 80 ||
            src_port == 8080 || dst_port == 8080 ||
            src_port == 8000 || dst_port == 8000 ||
            src_port == 8888 || dst_port == 8888)
            return LABEL_HTTP;
        if (src_port == 443 || dst_port == 443 ||
            src_port == 8443 || dst_port == 8443)
            return LABEL_HTTPS;
        if (src_port == 53 || dst_port == 53 ||
            src_port == 5353 || dst_port == 5353)
            return LABEL_DNS;
        if (src_port == 22 || dst_port == 22 ||
            src_port == 2222 || dst_port == 2222)
            return LABEL_SSH;
        if (src_port == 5201 || dst_port == 5201 ||
            src_port == 5202 || dst_port == 5202 ||
            src_port == 5203 || dst_port == 5203)
            return LABEL_IPERF;
    }
    
    return LABEL_OTHER;
}

static __always_inline int parse_tcp_udp_ports(void *transport, void *data_end, __u16 *src_port, __u16 *dst_port) {
    if (transport + 4 > data_end)
        return 0;
    *src_port = __bpf_ntohs(*(__u16 *)transport);
    *dst_port = __bpf_ntohs(*(__u16 *)(transport + 2));
    return 1;
}

SEC("tc")
int tc_flow(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + 20 > data_end)
        return BPF_OK;

    __u16 eth_proto = __bpf_ntohs(*(__u16 *)(data + 12));
    if (eth_proto != ETH_P_IP)
        return BPF_OK;

    struct iphdr *ip = data + 14;
    if ((void *)(ip + 1) > data_end)
        return BPF_OK;

    struct flow_key_v4 key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    __u8 ihl = (ip->ihl & 0x0f) * 4;
    __u16 src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        void *transport = (void *)ip + ihl;
        parse_tcp_udp_ports(transport, data_end, &src_port, &dst_port);
    } else if (ip->protocol == IPPROTO_ICMP) {
        void *transport = (void *)ip + ihl;
        if (transport + 4 > data_end)
            return BPF_OK;
        src_port = __bpf_ntohs(*(__u16 *)transport);
        dst_port = __bpf_ntohs(*(__u16 *)(transport + 2));
    }

    key.src_port = src_port;
    key.dst_port = dst_port;

    __u8 kernel_label = classify_flow(ip->protocol, src_port, dst_port);
    __u64 now  = bpf_ktime_get_ns();
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
        
        stats->last_ts     = now;
        stats->pkt_count  += 1;
        stats->byte_count += plen;
        
        if (stats->pkt_count >= 2 && stats->pkt_count % 10 == 0) {
            struct flow_event evt = {
                .version      = 2,
                .protocol     = key.protocol,
                .kernel_label = stats->kernel_label,
                .src_ip       = key.src_ip,
                .dst_ip       = key.dst_ip,
                .src_port     = key.src_port,
                .dst_port     = key.dst_port,
                .pkt_count    = stats->pkt_count,
                .byte_count   = stats->byte_count,
                .duration_ns  = stats->last_ts - stats->first_ts,
                .avg_ipt_ns   = stats->pkt_count > 1 ? stats->ipt_sum / (stats->pkt_count - 1) : 0,
                .min_ipt_ns   = stats->min_ipt,
                .max_ipt_ns   = stats->max_ipt,
            };
            bpf_perf_event_output(skb, &perf_map, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        }
    } else {
        struct flow_metrics new_stats = {};
        new_stats.pkt_count   = 1;
        new_stats.byte_count = plen;
        new_stats.first_ts   = now;
        new_stats.last_ts    = now;
        new_stats.ipt_sum   = 0;
        new_stats.min_ipt   = 0xFFFFFFFFFFFFFFFFULL;
        new_stats.max_ipt   = 0;
        new_stats.kernel_label = kernel_label;
        
        bpf_map_update_elem(&flow_map, &key, &new_stats, BPF_ANY);
    }

    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
