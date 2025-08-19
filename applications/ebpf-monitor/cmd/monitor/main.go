package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	cfgpkg "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/config"
	httpserver "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/httpserver"
	met "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/metrics"
	ml "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/mlclient"
	proc "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/processor"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall" network ../../bpf/network_monitor.c

// NetworkEvent represents a network event from eBPF program
// Must match the C struct in network_monitor.c
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
	config    *cfgpkg.Config
	processor *proc.Processor
	mlClient  *ml.Client
	server    *httpserver.Server
	objs      *networkObjects
	link      link.Link
	reader    *ringbuf.Reader
	events    chan proc.NetworkEvent
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewApplication creates a new application instance
func NewApplication() (*Application, error) {
	// Load configuration
	config := cfgpkg.New()

	// Initialize metrics
	met.Init()

	// Create ML client
	mlClient, err := ml.NewClient(config.MLDetectorURL, config.HTTPClientTimeout)
	if err != nil {
		return nil, fmt.Errorf("creating ML client: %w", err)
	}

	// Create processor
	processor := proc.NewProcessor(mlClient, config.StatsWindow)

	// Create HTTP server
	server := httpserver.NewServer(config.HTTPAddr, processor)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Create event channel
	events := make(chan proc.NetworkEvent, 1000)

	return &Application{
		config:    config,
		processor: processor,
		mlClient:  mlClient,
		server:    server,
		events:    events,
		ctx:       ctx,
		cancel:    cancel,
	}, nil
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
	fallbacks := []string{"eth0", "lo", "cilium_host", "cni0", "docker0", "br-+"}
	for _, name := range fallbacks {
		if strings.HasSuffix(name, "+") {
			// Handle pattern matching for bridges
			prefix := strings.TrimSuffix(name, "+")
			interfaces, err := net.Interfaces()
			if err != nil {
				continue
			}
			for _, iface := range interfaces {
				if strings.HasPrefix(iface.Name, prefix) && iface.Flags&net.FlagUp != 0 {
					log.Printf("✅ Using interface: %s", iface.Name)
					return &iface, nil
				}
			}
		} else {
			if iface, err := net.InterfaceByName(name); err == nil && iface.Flags&net.FlagUp != 0 {
				log.Printf("✅ Using fallback interface: %s", name)
				return iface, nil
			}
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
				met.ProcessorErrorsTotal.Inc()
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
					met.RingbufLostEventsTotal.Inc()
					time.Sleep(10 * time.Millisecond)
					continue
				}

				var event NetworkEvent
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
					log.Printf("⚠️  Error parsing event: %v", err)
					met.ParseErrorsTotal.Inc()
					continue
				}

				// Convert to processor event and send to channel
				procEvent := app.convertEvent(event)
				select {
				case app.events <- procEvent:
					met.EventsProcessedTotal.Inc()
				default:
					// Channel full, drop event
					met.EventsDroppedTotal.Inc()
				}
			}
		}
	}()
}

// convertEvent converts eBPF event to processor event
func (app *Application) convertEvent(event NetworkEvent) proc.NetworkEvent {
	return proc.NetworkEvent{
		SrcIP:      event.SrcIP,
		DstIP:      event.DstIP,
		SrcPort:    event.SrcPort,
		DstPort:    event.DstPort,
		Protocol:   event.Protocol,
		PacketSize: event.PacketSize,
		Timestamp:  event.Timestamp,
		TCPFlags:   event.TCPFlags,
	}
}

// isShuttingDown checks if error indicates shutdown
func (app *Application) isShuttingDown(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "closed") || 
		   strings.Contains(errStr, "EOF") ||
		   strings.Contains(errStr, "context canceled")
}

// startEventConsumer starts the event consumer that processes events
func (app *Application) startEventConsumer() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("❌ Event consumer panic: %v", r)
			}
		}()

		log.Printf("🔄 Starting event consumer...")
		
		for {
			select {
			case <-app.ctx.Done():
				log.Printf("🛑 Event consumer stopping...")
				return
			case event := <-app.events:
				app.processor.ProcessEvent(event)
			}
		}
	}()
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
	
	// Stop HTTP server
	if app.server != nil {
		app.server.Stop()
	}
	
	// Close event channel
	close(app.events)
	
	log.Printf("✅ Cleanup completed")
}

// Run starts the application
func (app *Application) Run() error {
	log.Printf("🚀 Starting eBPF Network Monitor...")
	log.Printf("📊 Config: Interface=%s, MLDetector=%s", 
		app.config.Interface, app.config.MLDetectorURL)

	// Setup eBPF
	if err := app.setupEBPF(); err != nil {
		return fmt.Errorf("setting up eBPF: %w", err)
	}

	// Start event processor
	app.startEventProcessor()
	
	// Start event consumer
	app.startEventConsumer()

	// Start HTTP server
	go func() {
		if err := app.server.Start(); err != nil {
			log.Printf("❌ HTTP server error: %v", err)
		}
	}()

	// Start processor statistics
	go app.processor.Start(app.ctx)

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