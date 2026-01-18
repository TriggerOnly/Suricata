// xdp_block.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_block_ip(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)(ip + 1) > data_end) return XDP_PASS;

        // пример: блокируем 77.222.61.184 -> 0x4DDE3DB8
        if (ip->saddr == htonl(0x4DDE3DB8)) {
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
