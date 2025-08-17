package main

import (
    "fmt"
    "log"
    "net/http"
    "time"
    
    "github.com/gorilla/mux"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    // Prometheus metrics
    packetsProcessed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ebpf_packets_processed_total",
            Help: "Total number of packets processed by eBPF monitor",
        },
        []string{"interface", "protocol"},
    )
    
    bytesProcessed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ebpf_bytes_processed_total", 
            Help: "Total bytes processed by eBPF monitor",
        },
        []string{"interface", "direction"},
    )
)

func init() {
    // Register metrics
    prometheus.MustRegister(packetsProcessed)
    prometheus.MustRegister(bytesProcessed)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `{"status":"healthy","service":"ebpf-monitor","timestamp":"%s"}`, time.Now().Format(time.RFC3339))
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `{
        "service": "eBPF Monitor",
        "version": "1.0.0", 
        "description": "eBPF-based network monitoring and metrics collection",
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics"
        }
    }`)
}

func simulateeBPFMonitoring() {
    // Simulate eBPF packet processing
    go func() {
        for {
            // Simulate random network activity
            packetsProcessed.WithLabelValues("eth0", "tcp").Add(float64(10 + (time.Now().Unix() % 50)))
            packetsProcessed.WithLabelValues("eth0", "udp").Add(float64(5 + (time.Now().Unix() % 20)))
            bytesProcessed.WithLabelValues("eth0", "ingress").Add(float64(1024 * (10 + (time.Now().Unix() % 100))))
            bytesProcessed.WithLabelValues("eth0", "egress").Add(float64(512 * (5 + (time.Now().Unix() % 50))))
            
            time.Sleep(10 * time.Second)
        }
    }()
}

func main() {
    r := mux.NewRouter()
    
    // Routes
    r.HandleFunc("/", rootHandler)
    r.HandleFunc("/health", healthHandler)
    r.Handle("/metrics", promhttp.Handler())
    
    // Start eBPF monitoring simulation
    simulateeBPFMonitoring()
    
    // Start server
    log.Println("eBPF Monitor starting on port 8800...")
    log.Fatal(http.ListenAndServe(":8800", r))
}