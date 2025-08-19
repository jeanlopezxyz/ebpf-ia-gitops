// network_monitor.c - eBPF program for network monitoring
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
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

// Mapa para eventos (ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB buffer
} events SEC(".maps");

// Mapa para contadores por IP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);   // IP address
    __type(value, __u64); // packet count
    __uint(max_entries, 10240);
} ip_counts SEC(".maps");

// Mapa para detectar port scanning
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);   // Source IP
    __type(value, __u32); // Unique ports count
    __uint(max_entries, 10240);
} port_scan_detector SEC(".maps");

SEC("xdp")
int network_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IP packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    struct network_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS;
    
    // Fill basic event data
    evt->src_ip = ip->saddr;
    evt->dst_ip = ip->daddr;
    evt->protocol = ip->protocol;
    evt->packet_size = data_end - data;
    evt->timestamp = bpf_ktime_get_ns();
    evt->tcp_flags = 0;
    
    // Parse TCP/UDP ports
    if (ip->protocol == 6) { // TCP
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) {
            bpf_ringbuf_discard(evt, 0);
            return XDP_PASS;
        }
        evt->src_port = bpf_ntohs(tcp->source);
        evt->dst_port = bpf_ntohs(tcp->dest);
        evt->tcp_flags = tcp->syn << 1 | tcp->ack << 4 | tcp->fin | tcp->rst << 2;
        
        // Detect SYN flood
        if (tcp->syn && !tcp->ack) {
            __u64 *count = bpf_map_lookup_elem(&ip_counts, &ip->saddr);
            if (count) {
                __sync_fetch_and_add(count, 1);
            } else {
                __u64 init_count = 1;
                bpf_map_update_elem(&ip_counts, &ip->saddr, &init_count, BPF_ANY);
            }
        }
        
        // Track unique ports for port scan detection
        __u32 *port_count = bpf_map_lookup_elem(&port_scan_detector, &ip->saddr);
        if (port_count) {
            if (*port_count < 100) // Threshold
                __sync_fetch_and_add(port_count, 1);
        } else {
            __u32 init = 1;
            bpf_map_update_elem(&port_scan_detector, &ip->saddr, &init, BPF_ANY);
        }
        
    } else if (ip->protocol == 17) { // UDP
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) {
            bpf_ringbuf_discard(evt, 0);
            return XDP_PASS;
        }
        evt->src_port = bpf_ntohs(udp->source);
        evt->dst_port = bpf_ntohs(udp->dest);
    } else {
        evt->src_port = 0;
        evt->dst_port = 0;
    }
    
    // Submit event
    bpf_ringbuf_submit(evt, 0);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";