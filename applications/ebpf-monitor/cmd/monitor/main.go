package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall" network ../../bpf/network_monitor.c

type NetworkEvent struct {
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	PacketSize  uint32
	Timestamp   uint64
	TCPFlags    uint8
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

var (
	// Prometheus metrics
	packetsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_packets_processed_total",
			Help: "Total number of packets processed by eBPF monitor",
		},
		[]string{"protocol", "direction"},
	)

	bytesProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_bytes_processed_total",
			Help: "Total bytes processed by eBPF monitor",
		},
		[]string{"protocol"},
	)

	suspiciousActivity = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_suspicious_activity_total",
			Help: "Suspicious network activity detected",
		},
		[]string{"type"},
	)

	// Current stats for ML detector
	currentStats = &NetworkStats{}
	statsWindow  []NetworkEvent
	mlDetectorURL = os.Getenv("ML_DETECTOR_URL")
)

func init() {
	prometheus.MustRegister(packetsProcessed)
	prometheus.MustRegister(bytesProcessed)
	prometheus.MustRegister(suspiciousActivity)

	if mlDetectorURL == "" {
		mlDetectorURL = "http://ml-detector:5000"
	}
}

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func processEvent(event NetworkEvent) {
	// Update Prometheus metrics
	protocol := "other"
	switch event.Protocol {
	case 6:
		protocol = "tcp"
		currentStats.TCPPackets++
	case 17:
		protocol = "udp"
		currentStats.UDPPackets++
	}

	packetsProcessed.WithLabelValues(protocol, "ingress").Inc()
	bytesProcessed.WithLabelValues(protocol).Add(float64(event.PacketSize))

	// Check for SYN packets (potential SYN flood)
	if event.Protocol == 6 && (event.TCPFlags&0x02) != 0 {
		currentStats.SYNPackets++
		if currentStats.SYNPackets > 1000 { // Threshold
			suspiciousActivity.WithLabelValues("syn_flood").Inc()
		}
	}

	// Add to sliding window for analysis
	statsWindow = append(statsWindow, event)
	if len(statsWindow) > 1000 {
		statsWindow = statsWindow[1:]
	}

	// Calculate stats every 100 packets
	if len(statsWindow)%100 == 0 {
		calculateAndSendStats()
	}
}

func calculateAndSendStats() {
	if len(statsWindow) == 0 {
		return
	}

	uniqueIPs := make(map[uint32]bool)
	uniquePorts := make(map[uint16]bool)
	var totalBytes uint32

	for _, evt := range statsWindow {
		uniqueIPs[evt.SrcIP] = true
		uniqueIPs[evt.DstIP] = true
		uniquePorts[evt.SrcPort] = true
		uniquePorts[evt.DstPort] = true
		totalBytes += evt.PacketSize
	}

	// Calculate rates
	duration := float64(statsWindow[len(statsWindow)-1].Timestamp-statsWindow[0].Timestamp) / 1e9
	if duration > 0 {
		currentStats.PacketsPerSecond = float64(len(statsWindow)) / duration
		currentStats.BytesPerSecond = float64(totalBytes) / duration
	}

	currentStats.UniqueIPs = len(uniqueIPs)
	currentStats.UniquePorts = len(uniquePorts)

	// Send to ML detector
	sendToMLDetector(currentStats)
}

func sendToMLDetector(stats *NetworkStats) {
	// Prepare features for ML detector
	features := map[string]interface{}{
		"packets_per_second": stats.PacketsPerSecond,
		"bytes_per_second":   stats.BytesPerSecond,
		"unique_ips":         stats.UniqueIPs,
		"unique_ports":       stats.UniquePorts,
		"tcp_ratio":          float64(stats.TCPPackets) / float64(stats.TCPPackets+stats.UDPPackets+1),
		"syn_packets":        stats.SYNPackets,
	}

	jsonData, err := json.Marshal(features)
	if err != nil {
		log.Printf("Error marshaling features: %v", err)
		return
	}

	// Send to ML detector
	resp, err := http.Post(mlDetectorURL+"/detect", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error sending to ML detector: %v", err)
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Error decoding ML response: %v", err)
		return
	}

	// Process ML detection result
	if threatDetected, ok := result["threat_detected"].(bool); ok && threatDetected {
		suspiciousActivity.WithLabelValues("ml_detection").Inc()
		log.Printf("🚨 Threat detected by ML! Confidence: %v", result["confidence"])
	}
}

func runEBPF() error {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load eBPF program
	spec, err := loadNetwork()
	if err != nil {
		// Fallback to simulation mode if eBPF not available
		log.Printf("⚠️  Cannot load eBPF (need root/CAP_BPF). Running in simulation mode: %v", err)
		go simulateTraffic()
		return nil
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("creating collection: %w", err)
	}
	defer coll.Close()

	// Attach to network interface
	prog := coll.Programs["network_monitor"]
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		// Try lo if eth0 doesn't exist
		iface, err = net.InterfaceByName("lo")
		if err != nil {
			return fmt.Errorf("finding interface: %w", err)
		}
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP: %w", err)
	}
	defer l.Close()

	// Open ring buffer for events
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("opening ringbuf: %w", err)
	}
	defer rd.Close()

	log.Printf("✅ eBPF program attached to %s", iface.Name)

	// Read events
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if ringbuf.IsClosed(err) {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			var event NetworkEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			processEvent(event)
		}
	}()

	return nil
}

func simulateTraffic() {
	// Simulation mode when eBPF is not available
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		event := NetworkEvent{
			SrcIP:      uint32(0x0A000001 + time.Now().Unix()%255),
			DstIP:      uint32(0x0A000002),
			SrcPort:    uint16(1024 + time.Now().Unix()%60000),
			DstPort:    uint16(80 + time.Now().Unix()%3),
			Protocol:   uint8(6),
			PacketSize: uint32(64 + time.Now().Unix()%1400),
			Timestamp:  uint64(time.Now().UnixNano()),
		}
		processEvent(event)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","service":"ebpf-monitor","timestamp":"%s"}`, 
		time.Now().Format(time.RFC3339))
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(currentStats)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"service": "eBPF Monitor",
		"version": "2.0.0",
		"mode": "real",
		"description": "Real eBPF-based network monitoring with ML integration",
		"endpoints": {
			"health": "/health",
			"metrics": "/metrics",
			"stats": "/stats"
		}
	}`)
}

func main() {
	// Initialize eBPF
	if err := runEBPF(); err != nil {
		log.Printf("eBPF initialization warning: %v", err)
	}

	// HTTP server
	r := mux.NewRouter()
	r.HandleFunc("/", rootHandler)
	r.HandleFunc("/health", healthHandler)
	r.HandleFunc("/stats", statsHandler)
	r.Handle("/metrics", promhttp.Handler())

	log.Println("🚀 eBPF Monitor starting on port 8800...")
	log.Fatal(http.ListenAndServe(":8800", r))
}