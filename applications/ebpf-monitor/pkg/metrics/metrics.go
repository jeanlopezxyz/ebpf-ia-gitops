package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Core metrics used by the application
var (
	// Traffic volume metrics
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

	// Connection tracking metrics
	SynPacketsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_syn_packets_total",
			Help: "Total SYN packets observed",
		},
	)

	// Window-based gauge metrics
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

	// Error tracking metrics
	EventsProcessedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_events_processed_total",
			Help: "Total number of events processed from ring buffer",
		},
	)

	RingbufLostEventsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_ringbuf_lost_events_total",
			Help: "Number of events lost due to ringbuf issues",
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

	MLPostFailuresTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ebpf_ml_post_failures_total",
			Help: "Number of ML detector post failures",
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
	prometheus.MustRegister(SynPacketsTotal)
	prometheus.MustRegister(UniqueIPs)
	prometheus.MustRegister(UniquePorts)
	prometheus.MustRegister(PacketsPerSecond)
	prometheus.MustRegister(BytesPerSecond)
	prometheus.MustRegister(EventsProcessedTotal)
	prometheus.MustRegister(RingbufLostEventsTotal)
	prometheus.MustRegister(ParseErrorsTotal)
	prometheus.MustRegister(ProcessorErrorsTotal)
	prometheus.MustRegister(MLPostFailuresTotal)
}
