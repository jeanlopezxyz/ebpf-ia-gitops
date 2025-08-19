# ebpf-ai Helm Chart

Purpose
- Deploys the eBPF + AI stack: ml-detector (Python), ebpf-monitor (Go), optional Prometheus/Grafana, and dashboards.

Install
- helm install ebpf-ai ./helm/charts/ebpf-ai -n ebpf-security --create-namespace

Key values
- mlDetector.image.repository/tag, mlDetector.service.port
- ebpfMonitor.enabled, ebpfMonitor.service.port
- prometheus.enabled, grafana.enabled (default: false)
- serviceMonitor.enabled (use with Prometheus Operator)
- metrics.addPrometheusAnnotations (default: true)

