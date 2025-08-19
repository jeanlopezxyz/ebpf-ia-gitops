package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/config"
	"github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/metrics"
)

// NetworkEvent represents a network event
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

// NetworkStats holds aggregated network statistics
type NetworkStats struct {
	PacketsPerSecond float64 `json:"packets_per_second"`
	BytesPerSecond   float64 `json:"bytes_per_second"`
	UniqueIPs        int     `json:"unique_ips"`
	UniquePorts      int     `json:"unique_ports"`
	TCPRatio         float64 `json:"tcp_ratio"`
	SYNPackets       int64   `json:"syn_packets"`
}

// Application represents the main application
type Application struct {
	config config.Config
	ctx    context.Context
	cancel context.CancelFunc

	// Statistics tracking
	mu         sync.RWMutex
	stats      NetworkStats
	ips        map[uint32]struct{}
	ports      map[uint16]struct{}
	tcpPackets int64
	udpPackets int64
	synPackets int64
	totalBytes uint64
	totalPkts  uint64
	lastReset  time.Time
}

// NewApplication creates a new application instance
func NewApplication() (*Application, error) {
	cfg := config.New()
	metrics.Init()

	ctx, cancel := context.WithCancel(context.Background())

	return &Application{
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		ips:       make(map[uint32]struct{}),
		ports:     make(map[uint16]struct{}),
		lastReset: time.Now(),
	}, nil
}

// ipToString converts IP from uint32 to string (little-endian)
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}


// processEvent processes a single network event
func (app *Application) processEvent(event NetworkEvent) {
	app.mu.Lock()
	defer app.mu.Unlock()

	protocol := "other"
	switch event.Protocol {
	case 6: // TCP
		protocol = "tcp"
		app.tcpPackets++
		if event.TCPFlags&0x02 != 0 { // SYN flag
			app.synPackets++
			metrics.SynPacketsTotal.Inc()
		}
	case 17: // UDP
		protocol = "udp"
		app.udpPackets++
	}

	// Update Prometheus metrics
	metrics.PacketsProcessed.WithLabelValues(protocol, "inbound").Inc()
	metrics.BytesProcessed.WithLabelValues(protocol).Add(float64(event.PacketSize))

	// Track unique IPs and ports
	app.ips[event.SrcIP] = struct{}{}
	app.ips[event.DstIP] = struct{}{}
	if event.SrcPort != 0 {
		app.ports[event.SrcPort] = struct{}{}
	}
	if event.DstPort != 0 {
		app.ports[event.DstPort] = struct{}{}
	}

	app.totalBytes += uint64(event.PacketSize)
	app.totalPkts++
}

// updateStats calculates and updates statistics periodically
func (app *Application) updateStats() {
	ticker := time.NewTicker(app.config.StatsWindow)
	defer ticker.Stop()

	for {
		select {
		case <-app.ctx.Done():
			return
		case <-ticker.C:
			app.mu.Lock()
			elapsed := time.Since(app.lastReset).Seconds()
			if elapsed > 0 {
				app.stats.PacketsPerSecond = float64(app.totalPkts) / elapsed
				app.stats.BytesPerSecond = float64(app.totalBytes) / elapsed
				app.stats.UniqueIPs = len(app.ips)
				app.stats.UniquePorts = len(app.ports)
				app.stats.SYNPackets = app.synPackets

				total := app.tcpPackets + app.udpPackets
				if total > 0 {
					app.stats.TCPRatio = float64(app.tcpPackets) / float64(total)
				}

				// Update Prometheus gauges
				metrics.PacketsPerSecond.Set(app.stats.PacketsPerSecond)
				metrics.BytesPerSecond.Set(app.stats.BytesPerSecond)
				metrics.UniqueIPs.Set(float64(app.stats.UniqueIPs))
				metrics.UniquePorts.Set(float64(app.stats.UniquePorts))

				// Reset counters for next window
				app.ips = make(map[uint32]struct{})
				app.ports = make(map[uint16]struct{})
				app.tcpPackets = 0
				app.udpPackets = 0
				app.synPackets = 0
				app.totalBytes = 0
				app.totalPkts = 0
				app.lastReset = time.Now()
			}
			app.mu.Unlock()
		}
	}
}

// getStats returns current statistics
func (app *Application) getStats() NetworkStats {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.stats
}

// startHTTPServer starts the HTTP server
func (app *Application) startHTTPServer() error {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"service":   "ebpf-monitor",
			"version":   "2.1.0",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	// Statistics endpoint
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(app.getStats())
	})

	// Root endpoint with service info
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"service":     "eBPF Network Monitor",
			"version":     "2.1.0",
			"description": "eBPF-based network monitoring with ML integration",
			"endpoints": map[string]string{
				"health":  "/health",
				"stats":   "/stats",
				"metrics": "/metrics",
			},
		})
	})

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	log.Printf("🌐 Starting HTTP server on %s", app.config.HTTPAddr)

	server := &http.Server{
		Addr:         app.config.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  app.config.ReadTimeout,
		WriteTimeout: app.config.WriteTimeout,
		IdleTimeout:  app.config.IdleTimeout,
	}

	go func() {
		<-app.ctx.Done()
		log.Printf("🛑 Shutting down HTTP server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	return server.ListenAndServe()
}

// simulateTraffic generates synthetic network events for testing
func (app *Application) simulateTraffic() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	counter := uint32(0)
	log.Printf("🔄 Starting traffic simulation (eBPF not available)...")

	for {
		select {
		case <-app.ctx.Done():
			return
		case <-ticker.C:
			counter++

			event := NetworkEvent{
				SrcIP:      0x0A000001 + (counter % 255), // 10.0.0.1-10.0.0.255
				DstIP:      0x0A000002,                   // 10.0.0.2
				SrcPort:    1024 + uint16(counter%60000),
				DstPort:    80 + uint16(counter%3),
				Protocol:   6, // TCP
				PacketSize: 64 + (counter % 1400),
				Timestamp:  uint64(time.Now().UnixNano()),
				TCPFlags:   0x18, // ACK + PSH
			}

			app.processEvent(event)
			metrics.EventsProcessedTotal.Inc()
		}
	}
}

// startMLClient sends statistics to ML Detector periodically
func (app *Application) startMLClient() {
	ticker := time.NewTicker(app.config.PostInterval)
	defer ticker.Stop()

	log.Printf("🤖 Starting ML Detector client (posting to %s every %v)", 
		app.config.MLDetectorURL, app.config.PostInterval)

	go func() {
		backoff := time.Second
		
		for {
			select {
			case <-app.ctx.Done():
				return
			case <-ticker.C:
				stats := app.getStats()
				
				// Prepare features for ML Detector
				features := map[string]interface{}{
					"packets_per_second": stats.PacketsPerSecond,
					"bytes_per_second":   stats.BytesPerSecond,
					"unique_ips":         stats.UniqueIPs,
					"unique_ports":       stats.UniquePorts,
					"tcp_ratio":          stats.TCPRatio,
					"syn_packets":        stats.SYNPackets,
				}

				// Send to ML Detector
				if err := app.postToMLDetector(features); err != nil {
					log.Printf("⚠️  ML Detector error: %v", err)
					metrics.MLPostFailuresTotal.Inc()
					
					// Exponential backoff
					time.Sleep(backoff)
					if backoff < 10*time.Second {
						backoff *= 2
					}
				} else {
					backoff = time.Second // Reset backoff on success
				}
			}
		}
	}()
}

// postToMLDetector sends features to ML Detector API
func (app *Application) postToMLDetector(features map[string]interface{}) error {
	jsonData, err := json.Marshal(features)
	if err != nil {
		return fmt.Errorf("marshaling features: %w", err)
	}

	client := &http.Client{Timeout: app.config.HTTPClientTimeout}
	
	resp, err := client.Post(
		app.config.MLDetectorURL+"/detect", 
		"application/json", 
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("posting to ML detector: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ML detector returned status %d", resp.StatusCode)
	}

	// Log ML detector response for debugging
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if threatDetected, ok := result["threat_detected"].(bool); ok && threatDetected {
			log.Printf("🚨 ML Detector found threat: %v", result)
		}
	}

	return nil
}

// Run starts the application
func (app *Application) Run() error {
	log.Printf("🚀 Starting eBPF Network Monitor v2.1.0...")
	log.Printf("📊 Config: Interface=%s, HTTPAddr=%s",
		app.config.Interface, app.config.HTTPAddr)

	// Start statistics updater
	go app.updateStats()

	// Start ML detector client
	go app.startMLClient()

	// Start in simulation mode (eBPF requires kernel capabilities)
	log.Printf("🔄 Starting network traffic simulation...")
	go app.simulateTraffic()

	// Start HTTP server
	go func() {
		if err := app.startHTTPServer(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ HTTP server error: %v", err)
		}
	}()

	log.Printf("✅ eBPF Network Monitor ready on %s", app.config.HTTPAddr)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Printf("🛑 Shutdown signal received")

	app.cleanup()
	return nil
}

// cleanup performs cleanup operations
func (app *Application) cleanup() {
	log.Printf("🧹 Cleaning up...")
	app.cancel()
	log.Printf("✅ Cleanup completed")
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	app, err := NewApplication()
	if err != nil {
		log.Fatalf("❌ Failed to create application: %v", err)
	}

	if err := app.Run(); err != nil {
		log.Fatalf("❌ Application error: %v", err)
	}
}
