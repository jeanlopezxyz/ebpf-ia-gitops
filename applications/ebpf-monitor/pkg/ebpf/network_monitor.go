package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/config"
	"github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/metrics"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" network ../../bpf/network_monitor.c

// NetworkEvent represents a network event (must match C struct)
type NetworkEvent struct {
	SrcIP      uint32 `json:"src_ip"`
	DstIP      uint32 `json:"dst_ip"`
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Protocol   uint8  `json:"protocol"`
	PacketSize uint32 `json:"packet_size"`
	Timestamp  uint64 `json:"timestamp"`
	TCPFlags   uint8  `json:"tcp_flags"`
}

// NetworkStats holds aggregated statistics
type NetworkStats struct {
	PacketsPerSecond float64 `json:"packets_per_second"`
	BytesPerSecond   float64 `json:"bytes_per_second"`
	UniqueIPs        int     `json:"unique_ips"`
	UniquePorts      int     `json:"unique_ports"`
	TCPPackets       int64   `json:"tcp_packets"`
	UDPPackets       int64   `json:"udp_packets"`
	SYNPackets       int64   `json:"syn_packets"`
	
	// QoS metrics (Rakuten-style transport layer analysis)
	AvgLatencyMs     float64 `json:"avg_latency_ms"`
	MaxLatencyMs     float64 `json:"max_latency_ms"`  
	MinLatencyMs     float64 `json:"min_latency_ms"`
	JitterMs         float64 `json:"jitter_ms"`
	PacketLossRate   float64 `json:"packet_loss_rate"`
	RetransmitRate   float64 `json:"retransmit_rate"`
}

// Monitor handles eBPF network monitoring
type Monitor struct {
	config config.Config
	ctx    context.Context
	cancel context.CancelFunc

	// eBPF resources
	objs   *networkObjects
	link   link.Link
	reader *ringbuf.Reader

	// Statistics tracking
	mu         sync.RWMutex
	stats      NetworkStats
	ips        map[uint32]struct{}
	ports      map[uint16]struct{}
	ipCounts   map[uint32]int64
	portCounts map[uint16]int64
	tcpPackets int64
	udpPackets int64
	synPackets int64
	totalBytes uint64
	totalPkts  uint64
	lastReset  time.Time
	
	// QoS tracking
	latencies    []float64
	lastSeen     map[uint32]uint64
	retransmits  int64
}

// NewMonitor creates a new eBPF network monitor
func NewMonitor(cfg config.Config) (*Monitor, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Monitor{
		config:     cfg,
		ctx:        ctx,
		cancel:     cancel,
		ips:        make(map[uint32]struct{}),
		ports:      make(map[uint16]struct{}),
		ipCounts:   make(map[uint32]int64),
		portCounts: make(map[uint16]int64),
		lastSeen:   make(map[uint32]uint64),
		latencies:  make([]float64, 0, 1000),
		lastReset:  time.Now(),
	}, nil
}

// Start initializes and starts the eBPF monitor
func (m *Monitor) Start() error {
	log.Printf("🚀 Starting eBPF Network Monitor v3.0.0")
	
	// Setup eBPF program
	if err := m.setupEBPF(); err != nil {
		return fmt.Errorf("eBPF setup failed: %w", err)
	}
	
	// Start all goroutines
	go m.updateStats()
	m.startEventProcessor()
	
	log.Printf("✅ eBPF Network Monitor ready - capturing REAL network traffic!")
	return nil
}

// Stop gracefully shuts down the monitor
func (m *Monitor) Stop() {
	log.Printf("🛑 Stopping eBPF Network Monitor...")
	m.cancel()
	m.cleanup()
}

// GetStats returns current network statistics
func (m *Monitor) GetStats() NetworkStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// GetTopIPs returns top N IPs by packet count
func (m *Monitor) GetTopIPs(n int) map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	type ipCount struct {
		ip    string
		count int64
	}
	
	var ips []ipCount
	for ip, count := range m.ipCounts {
		ips = append(ips, ipCount{ipToString(ip), count})
	}
	
	// Simple sort - get top N
	result := make(map[string]int64)
	for i := 0; i < len(ips) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(ips); j++ {
			if ips[j].count > ips[maxIdx].count {
				maxIdx = j
			}
		}
		if maxIdx != i {
			ips[i], ips[maxIdx] = ips[maxIdx], ips[i]
		}
		result[ips[i].ip] = ips[i].count
	}
	return result
}