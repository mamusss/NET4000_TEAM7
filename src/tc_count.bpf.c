#include "bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} pkt_cnt SEC(".maps");

SEC("tc")
int tc_count(struct __sk_buff *skb) {
  __u32 key = 0;
  __u64 *val = bpf_map_lookup_elem(&pkt_cnt, &key);
  if (val) {
    __sync_fetch_and_add(val, 1);
  }
  return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
