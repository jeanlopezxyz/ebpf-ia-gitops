package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
)

var (
    PacketsProcessed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ebpf_packets_processed_total",
            Help: "Total number of packets processed by eBPF monitor",
        },
        []string{"protocol", "direction"},
    )

    BytesProcessed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ebpf_bytes_processed_total",
            Help: "Total bytes processed by eBPF monitor",
        },
        []string{"protocol"},
    )

    SuspiciousActivity = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ebpf_suspicious_activity_total",
            Help: "Suspicious network activity detected",
        },
        []string{"type"},
    )

    SynPacketsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "ebpf_syn_packets_total",
            Help: "Total SYN packets observed",
        },
    )

    UniqueIPs = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "ebpf_unique_ips",
            Help: "Unique IPs seen in the current window",
        },
    )

    UniquePorts = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "ebpf_unique_ports",
            Help: "Unique ports seen in the current window",
        },
    )

    PacketsPerSecond = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "ebpf_packets_per_second",
            Help: "Estimated packets per second over the window",
        },
    )

    BytesPerSecond = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "ebpf_bytes_per_second",
            Help: "Estimated bytes per second over the window",
        },
    )

    RingbufLostEventsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "ebpf_ringbuf_lost_events_total",
            Help: "Number of events lost due to ringbuf issues",
        },
    )

    MLPostFailuresTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "ebpf_ml_post_failures_total",
            Help: "Number of ML detector post failures",
        },
    )

    // Gauge that reflects unique ports counted at BPF layer (optional, via map iteration)
    BPFUniquePorts = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "ebpf_unique_ports_bpf",
            Help: "Sum of per-IP unique destination ports tracked in BPF map",
        },
    )
)

// Additional metrics for the main application
var (
    EventsProcessedTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "ebpf_events_processed_total",
            Help: "Total number of events processed from ring buffer",
        },
    )

    EventsDroppedTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "ebpf_events_dropped_total", 
            Help: "Total number of events dropped due to channel backpressure",
        },
    )

    ParseErrorsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "ebpf_parse_errors_total",
            Help: "Total number of event parsing errors",
        },
    )

    ProcessorErrorsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "ebpf_processor_errors_total",
            Help: "Total number of processor errors/panics",
        },
    )
)

// Init initializes and registers all metrics
func Init() {
    Register()
}

func Register() {
    prometheus.MustRegister(PacketsProcessed)
    prometheus.MustRegister(BytesProcessed)
    prometheus.MustRegister(SuspiciousActivity)
    prometheus.MustRegister(SynPacketsTotal)
    prometheus.MustRegister(UniqueIPs)
    prometheus.MustRegister(UniquePorts)
    prometheus.MustRegister(PacketsPerSecond)
    prometheus.MustRegister(BytesPerSecond)
    prometheus.MustRegister(RingbufLostEventsTotal)
    prometheus.MustRegister(MLPostFailuresTotal)
    prometheus.MustRegister(BPFUniquePorts)
    prometheus.MustRegister(EventsProcessedTotal)
    prometheus.MustRegister(EventsDroppedTotal)
    prometheus.MustRegister(ParseErrorsTotal)
    prometheus.MustRegister(ProcessorErrorsTotal)
}
