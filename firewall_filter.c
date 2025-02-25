#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

BPF_HASH(block_table, u32, u32);

int xdp_filter(struct __sk_buff *skb) {
    struct iphdr *ip = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    
    u32 *blocked = block_table.lookup(&ip->saddr);
    if (blocked) {
        return XDP_DROP;
    }
    return XDP_PASS;
}