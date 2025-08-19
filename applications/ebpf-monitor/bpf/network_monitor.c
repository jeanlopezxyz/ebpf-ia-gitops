// network_monitor.c - eBPF program for network monitoring
#include <vmlinux.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Estructura para estadísticas de red
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

// TCP flag masks (standard values)
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

// VLAN ethertypes
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

// Minimal VLAN header structure
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// Mapa para eventos (ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8MB buffer
} events SEC(".maps");

// Mapas opcionales para conteo de puertos únicos por IP (detección port-scan)
struct ip_port_key { __u32 ip; __u16 port; };

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ip_port_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
} seen_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);   // IP origen (host order)
    __type(value, __u32); // conteo de puertos únicos
    __uint(max_entries, 16384);
} port_unique_count SEC(".maps");

static __always_inline void update_unique_port(__u32 src_ip_host, __u16 dst_port)
{
    struct ip_port_key key = { .ip = src_ip_host, .port = dst_port };
    __u8 one = 1;
    if (bpf_map_update_elem(&seen_ports, &key, &one, BPF_NOEXIST) == 0) {
        __u32 *cnt = bpf_map_lookup_elem(&port_unique_count, &src_ip_host);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        } else {
            __u32 init = 1;
            bpf_map_update_elem(&port_unique_count, &src_ip_host, &init, BPF_ANY);
        }
    }
}

static __always_inline int parse_eth(void **cursor, void *data_end, __u16 *proto)
{
    struct ethhdr *eth = (struct ethhdr *)*cursor;
    if ((void *)(eth + 1) > data_end) return 0;
    __u16 p = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (p == ETH_P_8021Q || p == ETH_P_8021AD) {
            struct vlan_hdr *vh = nh;
            if ((void *)(vh + 1) > data_end) return 0;
            p = bpf_ntohs(vh->h_vlan_encapsulated_proto);
            nh = (void *)(vh + 1);
        }
    }
    *proto = p;
    *cursor = nh;
    return 1;
}

SEC("xdp")
int network_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet (+ VLAN)
    __u16 eth_proto = 0;
    if (!parse_eth(&data, data_end, &eth_proto))
        return XDP_PASS;

    // IPv4 path
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = data;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        struct network_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt)
            return XDP_PASS;

        // Validate IHL
        if (ip->ihl < 5) {
            bpf_ringbuf_discard(evt, 0);
            return XDP_PASS;
        }
        __u32 ihl_bytes = ip->ihl * 4;
        evt->src_ip = bpf_ntohl(ip->saddr);
        evt->dst_ip = bpf_ntohl(ip->daddr);
        evt->protocol = ip->protocol;
        evt->packet_size = (unsigned long)data_end - (unsigned long)ctx->data;
        evt->timestamp = bpf_ktime_get_ns();
        evt->tcp_flags = 0;

        void *l4 = (void *)ip + ihl_bytes;
        if (ip->protocol == 6) { // TCP
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end) { bpf_ringbuf_discard(evt, 0); return XDP_PASS; }
            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);
            if (tcp->fin) evt->tcp_flags |= TCP_FIN;
            if (tcp->syn) evt->tcp_flags |= TCP_SYN;
            if (tcp->rst) evt->tcp_flags |= TCP_RST;
            if (tcp->ack) evt->tcp_flags |= TCP_ACK;
            if (tcp->syn && !tcp->ack) {
                update_unique_port(evt->src_ip, evt->dst_port);
            }
        } else if (ip->protocol == 17) { // UDP
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end) { bpf_ringbuf_discard(evt, 0); return XDP_PASS; }
            evt->src_port = bpf_ntohs(udp->source);
            evt->dst_port = bpf_ntohs(udp->dest);
        } else {
            evt->src_port = 0; evt->dst_port = 0;
        }
        bpf_ringbuf_submit(evt, 0);
        return XDP_PASS;
    }

    // Minimal IPv6 handling (no extension headers). Note: event holds IPv4 fields only.
    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = data;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        struct network_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) return XDP_PASS;
        evt->src_ip = 0; evt->dst_ip = 0; // not supported
        evt->protocol = ip6->nexthdr;
        evt->packet_size = (unsigned long)data_end - (unsigned long)ctx->data;
        evt->timestamp = bpf_ktime_get_ns();
        evt->tcp_flags = 0;
        void *l4 = (void *)(ip6 + 1);
        if (ip6->nexthdr == 6) {
            struct tcphdr *tcp = l4;
            if ((void *)(tcp + 1) > data_end) { bpf_ringbuf_discard(evt, 0); return XDP_PASS; }
            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);
            if (tcp->fin) evt->tcp_flags |= TCP_FIN;
            if (tcp->syn) evt->tcp_flags |= TCP_SYN;
            if (tcp->rst) evt->tcp_flags |= TCP_RST;
            if (tcp->ack) evt->tcp_flags |= TCP_ACK;
        } else if (ip6->nexthdr == 17) {
            struct udphdr *udp = l4;
            if ((void *)(udp + 1) > data_end) { bpf_ringbuf_discard(evt, 0); return XDP_PASS; }
            evt->src_port = bpf_ntohs(udp->source);
            evt->dst_port = bpf_ntohs(udp->dest);
        } else {
            evt->src_port = 0; evt->dst_port = 0;
        }
        bpf_ringbuf_submit(evt, 0);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
