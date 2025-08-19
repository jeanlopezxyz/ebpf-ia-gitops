package httpserver

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/gorilla/mux"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    p "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/processor"
)

type Server struct {
    srv   *http.Server
    stats func() p.NetworkStats
    ready func() bool
}

func New(addr string, readHeader, read, write, idle time.Duration, stats func() p.NetworkStats, ready func() bool) *Server {
    r := mux.NewRouter()
    s := &Server{stats: stats, ready: ready}
    r.HandleFunc("/", s.rootHandler)
    r.HandleFunc("/health", s.healthHandler)
    r.HandleFunc("/ready", s.readyHandler)
    r.HandleFunc("/stats", s.statsHandler)
    r.Handle("/metrics", promhttp.Handler())
    s.srv = &http.Server{
        Addr:              addr,
        Handler:           r,
        ReadHeaderTimeout: readHeader,
        ReadTimeout:       read,
        WriteTimeout:      write,
        IdleTimeout:       idle,
    }
    return s
}

func (s *Server) Start() error { return s.srv.ListenAndServe() }
func (s *Server) Shutdown() error { return s.srv.Close() }

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]any{
        "status": "healthy",
        "service": "ebpf-monitor",
        "timestamp": time.Now().Format(time.RFC3339),
    })
}

func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
    if s.ready != nil && !s.ready() {
        http.Error(w, "not ready", http.StatusServiceUnavailable)
        return
    }
    w.WriteHeader(http.StatusOK)
}

func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(s.stats())
}

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{
        "service": "eBPF Monitor",
        "version": "2.1.0",
        "description": "eBPF-based network monitoring with ML integration",
        "endpoints": {"health":"/health","ready":"/ready","metrics":"/metrics","stats":"/stats"}
    }`))
}

