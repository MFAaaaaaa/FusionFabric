// 文件名: xdp_router.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// 定义一个 BPF Map 用于存放“黑名单”
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Key: IP 地址
    __type(value, __u8);  // Value: 任意值，仅用于存在性检查
} blacklist_map SEC(".maps");

// IP校验和计算的辅助函数
static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
    #pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline void ipv4_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = 0;
    __u16 *buf = (__u16 *)iph;
    #pragma unroll
    for (int i = 0; i < sizeof(*iph) >> 1; i++) {
        csum += *buf++;
    }
    iph->check = csum_fold_helper(csum);
}

SEC("xdp")
int xdp_router_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 1. 防火墙功能：查询黑名单 Map
    __u32 dest_ip = iph->daddr;
    if (bpf_map_lookup_elem(&blacklist_map, &dest_ip)) {
        return XDP_DROP; // 如果在黑名单中，丢弃
    }

    // 2. 路由器功能：TTL 减 1
    if (iph->ttl <= 1)
        return XDP_DROP;
    iph->ttl--;

    // 3. 重新计算 IP 校验和
    ipv4_csum(iph);

    // 4. 交换 MAC 地址准备转发
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
