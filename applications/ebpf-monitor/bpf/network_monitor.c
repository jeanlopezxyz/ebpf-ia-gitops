// network_monitor.c - Simplified eBPF program for network monitoring
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Estructura para eventos de red
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

// Mapa para eventos (ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8MB buffer
} events SEC(".maps");

// Mapa para conteo de puertos únicos (detección port-scan)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // IP origen
    __type(value, __u32); // conteo de puertos únicos
    __uint(max_entries, 16384);
} port_unique_count SEC(".maps");

SEC("xdp")
int network_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Solo procesar IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Crear evento
    struct network_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS;

    evt->src_ip = bpf_ntohl(ip->saddr);
    evt->dst_ip = bpf_ntohl(ip->daddr);
    evt->protocol = ip->protocol;
    evt->packet_size = (unsigned long)data_end - (unsigned long)data;
    evt->timestamp = bpf_ktime_get_ns();
    evt->tcp_flags = 0;
    evt->src_port = 0;
    evt->dst_port = 0;

    // Parse layer 4
    void *l4 = (void *)ip + (ip->ihl * 4);
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) <= data_end) {
            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);
            
            // TCP flags
            if (tcp->fin) evt->tcp_flags |= 0x01;
            if (tcp->syn) evt->tcp_flags |= 0x02;
            if (tcp->rst) evt->tcp_flags |= 0x04;
            if (tcp->ack) evt->tcp_flags |= 0x10;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) <= data_end) {
            evt->src_port = bpf_ntohs(udp->source);
            evt->dst_port = bpf_ntohs(udp->dest);
        }
    }

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";