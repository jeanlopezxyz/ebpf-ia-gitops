#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct network_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 packet_size;
    __u64 timestamp;
    __u8  tcp_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} port_unique_count SEC(".maps");

SEC("xdp")
int network_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct network_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    event->src_ip = bpf_ntohl(ip->saddr);
    event->dst_ip = bpf_ntohl(ip->daddr);
    event->protocol = ip->protocol;
    event->packet_size = (unsigned long)data_end - (unsigned long)data;
    event->timestamp = bpf_ktime_get_ns();
    event->tcp_flags = 0;
    event->src_port = 0;
    event->dst_port = 0;

    void *l4 = (void *)ip + (ip->ihl * 4);
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) <= data_end) {
            event->src_port = bpf_ntohs(tcp->source);
            event->dst_port = bpf_ntohs(tcp->dest);
            if (tcp->fin) event->tcp_flags |= 0x01;
            if (tcp->syn) event->tcp_flags |= 0x02;
            if (tcp->rst) event->tcp_flags |= 0x04;
            if (tcp->ack) event->tcp_flags |= 0x10;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end) {
            event->src_port = bpf_ntohs(udp->source);
            event->dst_port = bpf_ntohs(udp->dest);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";