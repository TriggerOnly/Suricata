// xdp_blacklist.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* eBPF map: ключ = IPv4 в сетевом порядке (u32), значение = uint8_t (1 = blocked) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u8);
} blacklist_map SEC(".maps");

SEC("xdp")
int xdp_blacklist_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;

    __u32 src = ip->saddr;
    __u32 dst = ip->daddr;

    /* ищем сначала dst, потом src — блокируем и входящие, и исходящие по IP */
    __u8 *v = bpf_map_lookup_elem(&blacklist_map, &dst);
    if (v && *v) return XDP_DROP;

    v = bpf_map_lookup_elem(&blacklist_map, &src);
    if (v && *v) return XDP_DROP;

    return XDP_PASS;
}
