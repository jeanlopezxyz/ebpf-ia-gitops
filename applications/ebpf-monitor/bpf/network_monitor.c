// network_monitor.c - eBPF program for network monitoring
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Protocol constants (from linux/in.h)
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP  
#define IPPROTO_UDP 17
#endif

// TCP flag constants
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10

// Network event structure that matches Go struct
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

// Ring buffer for network events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8MB buffer
} events SEC(".maps");

// Hash map for unique port counting (port scan detection)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // Source IP
    __type(value, __u32); // Unique port count
    __uint(max_entries, 16384);
} port_unique_count SEC(".maps");

// Helper function to safely access IP header fields
static __always_inline int parse_ip_header(struct iphdr *ip, void *data_end, 
                                          __u32 *src_ip, __u32 *dst_ip, __u8 *protocol) {
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    // Validate IP header length
    if (ip->ihl < 5)
        return -1;
    
    *src_ip = bpf_ntohl(ip->saddr);
    *dst_ip = bpf_ntohl(ip->daddr);
    *protocol = ip->protocol;
    
    return ip->ihl * 4; // Return header length in bytes
}

// Helper function to parse TCP header
static __always_inline int parse_tcp_header(struct tcphdr *tcp, void *data_end,
                                           __u16 *src_port, __u16 *dst_port, __u8 *flags) {
    if ((void *)(tcp + 1) > data_end)
        return -1;
    
    *src_port = bpf_ntohs(tcp->source);
    *dst_port = bpf_ntohs(tcp->dest);
    
    *flags = 0;
    if (tcp->fin) *flags |= TCP_FIN;
    if (tcp->syn) *flags |= TCP_SYN;
    if (tcp->rst) *flags |= TCP_RST;
    if (tcp->ack) *flags |= TCP_ACK;
    
    return 0;
}

// Helper function to parse UDP header
static __always_inline int parse_udp_header(struct udphdr *udp, void *data_end,
                                           __u16 *src_port, __u16 *dst_port) {
    if ((void *)(udp + 1) > data_end)
        return -1;
    
    *src_port = bpf_ntohs(udp->source);
    *dst_port = bpf_ntohs(udp->dest);
    
    return 0;
}

SEC("xdp")
int network_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    __u32 src_ip, dst_ip;
    __u8 protocol;
    
    int ip_hlen = parse_ip_header(ip, data_end, &src_ip, &dst_ip, &protocol);
    if (ip_hlen < 0)
        return XDP_PASS;

    // Reserve space in ring buffer for event
    struct network_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS;

    // Fill basic event information
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->protocol = protocol;
    evt->packet_size = (unsigned long)data_end - (unsigned long)data;
    evt->timestamp = bpf_ktime_get_ns();
    evt->tcp_flags = 0;
    evt->src_port = 0;
    evt->dst_port = 0;

    // Parse layer 4 protocols
    void *l4 = (void *)ip + ip_hlen;
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        __u16 src_port, dst_port;
        __u8 tcp_flags;
        
        if (parse_tcp_header(tcp, data_end, &src_port, &dst_port, &tcp_flags) == 0) {
            evt->src_port = src_port;
            evt->dst_port = dst_port;
            evt->tcp_flags = tcp_flags;
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        __u16 src_port, dst_port;
        
        if (parse_udp_header(udp, data_end, &src_port, &dst_port) == 0) {
            evt->src_port = src_port;
            evt->dst_port = dst_port;
        }
    }

    // Submit event to ring buffer
    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";