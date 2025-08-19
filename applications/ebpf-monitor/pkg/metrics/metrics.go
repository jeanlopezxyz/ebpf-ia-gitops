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
)

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
}

