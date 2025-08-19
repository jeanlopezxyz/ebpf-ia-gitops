package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/config"
	"github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/metrics"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall" network ../../bpf/network_monitor.c

// NetworkEvent represents a network event from eBPF program
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

// Application represents the main application
type Application struct {
	config config.Config
	objs   *networkObjects
	link   link.Link
	reader *ringbuf.Reader
	ctx    context.Context
	cancel context.CancelFunc
}

// NewApplication creates a new application instance
func NewApplication() (*Application, error) {
	// Load configuration
	cfg := config.New()

	// Initialize metrics
	metrics.Init()

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	return &Application{
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// ipToString converts IP from uint32 to string
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// setupEBPF initializes and loads the eBPF program
func (app *Application) setupEBPF() error {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load eBPF objects
	app.objs = &networkObjects{}
	if err := loadNetworkObjects(app.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Find network interface
	iface, err := app.findNetworkInterface()
	if err != nil {
		return fmt.Errorf("finding network interface: %w", err)
	}

	// Attach XDP program to interface
	app.link, err = link.AttachXDP(link.XDPOptions{
		Program:   app.objs.NetworkMonitor,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP program to %s: %w", iface.Name, err)
	}

	// Create ring buffer reader
	app.reader, err = ringbuf.NewReader(app.objs.Events)
	if err != nil {
		return fmt.Errorf("opening ring buffer: %w", err)
	}

	log.Printf("✅ eBPF program attached to interface %s", iface.Name)
	return nil
}

// findNetworkInterface finds a suitable network interface
func (app *Application) findNetworkInterface() (*net.Interface, error) {
	// Try configured interface first
	if app.config.Interface != "" {
		if iface, err := net.InterfaceByName(app.config.Interface); err == nil {
			return iface, nil
		}
		log.Printf("⚠️  Interface %s not found, trying fallbacks", app.config.Interface)
	}

	// Try common interfaces
	fallbacks := []string{"eth0", "lo", "cilium_host", "cni0", "docker0"}
	for _, name := range fallbacks {
		if iface, err := net.InterfaceByName(name); err == nil && iface.Flags&net.FlagUp != 0 {
			log.Printf("✅ Using fallback interface: %s", name)
			return iface, nil
		}
	}

	return nil, fmt.Errorf("no suitable network interface found")
}

// startEventProcessor starts the eBPF event processing goroutine
func (app *Application) startEventProcessor() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ Event processor panic: %v", r)
				metrics.ProcessorErrorsTotal.Inc()
			}
		}()

		log.Printf("🔄 Starting eBPF event processor...")
		
		for {
			select {
			case <-app.ctx.Done():
				log.Printf("🛑 Event processor stopping...")
				return
			default:
				record, err := app.reader.Read()
				if err != nil {
					if app.isShuttingDown(err) {
						return
					}
					log.Printf("⚠️  Error reading from ring buffer: %v", err)
					metrics.RingbufLostEventsTotal.Inc()
					time.Sleep(10 * time.Millisecond)
					continue
				}

				var event NetworkEvent
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
					log.Printf("⚠️  Error parsing event: %v", err)
					metrics.ParseErrorsTotal.Inc()
					continue
				}

				// Process event
				app.processEvent(event)
				metrics.EventsProcessedTotal.Inc()
			}
		}
	}()
}

// processEvent processes a single network event
func (app *Application) processEvent(event NetworkEvent) {
	// Update metrics
	protocol := "other"
	switch event.Protocol {
	case 6:
		protocol = "tcp"
		metrics.SynPacketsTotal.Inc()
	case 17:
		protocol = "udp"
	}

	metrics.PacketsProcessed.WithLabelValues(protocol, "inbound").Inc()
	metrics.BytesProcessed.WithLabelValues(protocol).Add(float64(event.PacketSize))

	// Simple logging for demo purposes
	if event.SrcPort != 0 || event.DstPort != 0 {
		log.Printf("📊 %s:%d -> %s:%d [%s] %d bytes", 
			ipToString(event.SrcIP), event.SrcPort,
			ipToString(event.DstIP), event.DstPort,
			protocol, event.PacketSize)
	}
}

// isShuttingDown checks if error indicates shutdown
func (app *Application) isShuttingDown(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "closed") || 
		   strings.Contains(errStr, "EOF") ||
		   strings.Contains(errStr, "context canceled")
}

// startHTTPServer starts the HTTP server for metrics and health checks
func (app *Application) startHTTPServer() error {
	mux := http.NewServeMux()
	
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"ebpf-monitor"}`))
	})

	// Metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	log.Printf("🌐 Starting HTTP server on %s", app.config.HTTPAddr)
	
	server := &http.Server{
		Addr:    app.config.HTTPAddr,
		Handler: mux,
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

// cleanup performs cleanup operations
func (app *Application) cleanup() {
	log.Printf("🧹 Cleaning up...")
	
	// Cancel context to stop goroutines
	app.cancel()
	
	// Close ring buffer reader
	if app.reader != nil {
		app.reader.Close()
	}
	
	// Detach XDP program
	if app.link != nil {
		app.link.Close()
	}
	
	// Close eBPF objects
	if app.objs != nil {
		app.objs.Close()
	}
	
	log.Printf("✅ Cleanup completed")
}

// Run starts the application
func (app *Application) Run() error {
	log.Printf("🚀 Starting eBPF Network Monitor...")
	log.Printf("📊 Config: Interface=%s, HTTPAddr=%s", 
		app.config.Interface, app.config.HTTPAddr)

	// Setup eBPF
	if err := app.setupEBPF(); err != nil {
		return fmt.Errorf("setting up eBPF: %w", err)
	}

	// Start event processor
	app.startEventProcessor()

	// Start HTTP server in background
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

func main() {
	// Set log format
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	// Create application
	app, err := NewApplication()
	if err != nil {
		log.Fatalf("❌ Failed to create application: %v", err)
	}

	// Run application
	if err := app.Run(); err != nil {
		log.Fatalf("❌ Application error: %v", err)
	}
}