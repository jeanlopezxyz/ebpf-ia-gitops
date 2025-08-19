package processor

import (
    "sync"
    "time"

    m "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/metrics"
)

type NetworkEvent struct {
    SrcIP      uint32
    DstIP      uint32
    SrcPort    uint16
    DstPort    uint16
    Protocol   uint8
    PacketSize uint32
    Timestamp  uint64
    TCPFlags   uint8
}

type NetworkStats struct {
    PacketsPerSecond float64 `json:"packets_per_second"`
    BytesPerSecond   float64 `json:"bytes_per_second"`
    UniqueIPs        int     `json:"unique_ips"`
    UniquePorts      int     `json:"unique_ports"`
    TCPPackets       int64   `json:"tcp_packets"`
    UDPPackets       int64   `json:"udp_packets"`
    SYNPackets       int64   `json:"syn_packets"`
}

type Processor struct {
    mu          sync.Mutex
    evCh        chan NetworkEvent
    stopCh      chan struct{}
    window      time.Duration
    lastTick    time.Time
    // accumulators for current window
    ips         map[uint32]struct{}
    ports       map[uint16]struct{}
    tcpPackets  int64
    udpPackets  int64
    synPackets  int64
    totalBytes  uint64
    totalPkts   uint64
    stats       NetworkStats
}

func New(window time.Duration, buf int) *Processor {
    return &Processor{
        evCh:     make(chan NetworkEvent, buf),
        stopCh:   make(chan struct{}),
        window:   window,
        lastTick: time.Now(),
        ips:      make(map[uint32]struct{}),
        ports:    make(map[uint16]struct{}),
    }
}

func (p *Processor) Input() chan<- NetworkEvent { return p.evCh }

func (p *Processor) Start() {
    ticker := time.NewTicker(p.window)
    go func() {
        for {
            select {
            case ev := <-p.evCh:
                p.handle(ev)
            case <-ticker.C:
                p.tick()
            case <-p.stopCh:
                ticker.Stop()
                return
            }
        }
    }()
}

func (p *Processor) Stop() { close(p.stopCh) }

func (p *Processor) handle(ev NetworkEvent) {
    p.mu.Lock()
    defer p.mu.Unlock()
    // basic metrics
    proto := "other"
    switch ev.Protocol {
    case 6:
        proto = "tcp"
        p.tcpPackets++
    case 17:
        proto = "udp"
        p.udpPackets++
    }
    m.PacketsProcessed.WithLabelValues(proto, "ingress").Inc()
    m.BytesProcessed.WithLabelValues(proto).Add(float64(ev.PacketSize))
    if ev.Protocol == 6 && (ev.TCPFlags&0x02) != 0 && (ev.TCPFlags&0x10) == 0 { // SYN && !ACK
        p.synPackets++
        m.SynPacketsTotal.Inc()
    }
    p.ips[ev.SrcIP] = struct{}{}
    p.ips[ev.DstIP] = struct{}{}
    p.ports[ev.SrcPort] = struct{}{}
    p.ports[ev.DstPort] = struct{}{}
    p.totalBytes += uint64(ev.PacketSize)
    p.totalPkts++
}

func (p *Processor) tick() {
    p.mu.Lock()
    defer p.mu.Unlock()
    now := time.Now()
    elapsed := now.Sub(p.lastTick).Seconds()
    if elapsed <= 0 {
        return
    }
    p.stats.PacketsPerSecond = float64(p.totalPkts) / elapsed
    p.stats.BytesPerSecond = float64(p.totalBytes) / elapsed
    p.stats.UniqueIPs = len(p.ips)
    p.stats.UniquePorts = len(p.ports)
    p.stats.TCPPackets = p.tcpPackets
    p.stats.UDPPackets = p.udpPackets
    p.stats.SYNPackets = p.synPackets
    // export gauges
    m.PacketsPerSecond.Set(p.stats.PacketsPerSecond)
    m.BytesPerSecond.Set(p.stats.BytesPerSecond)
    m.UniqueIPs.Set(float64(p.stats.UniqueIPs))
    m.UniquePorts.Set(float64(p.stats.UniquePorts))
    // reset window accumulators
    p.lastTick = now
    p.ips = make(map[uint32]struct{})
    p.ports = make(map[uint16]struct{})
    p.tcpPackets = 0
    p.udpPackets = 0
    p.synPackets = 0
    p.totalBytes = 0
    p.totalPkts = 0
}

func (p *Processor) Stats() NetworkStats {
    p.mu.Lock()
    defer p.mu.Unlock()
    return p.stats
}

