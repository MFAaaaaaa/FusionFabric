// 文件名: xdp_reflect.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

// 交换源和目的MAC地址的辅助函数
static __always_inline void swap_mac_addresses(struct ethhdr *eth) {
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

SEC("xdp")
int xdp_reflect_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 至少需要一个完整的以太网头才能处理
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS; // 奇怪的数据包交还给内核处理
    }

    struct ethhdr *eth = data;

    swap_mac_addresses(eth);

    // 从同一个网卡将修改后的包发送出去
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
