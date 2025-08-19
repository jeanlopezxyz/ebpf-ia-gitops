eBPF Monitor
============

Captura eventos de red con eBPF (XDP) y expone métricas Prometheus. Agrega estadísticas por ventana de tiempo y envía features al servicio `ml-detector` periódicamente.

Ejecución
- Requiere privilegios/capacidades para eBPF (root, `CAP_BPF`, `CAP_NET_ADMIN`).
- Si no puede adjuntar eBPF, entra en modo simulación automáticamente.

Endpoints
- `/health`: liveness.
- `/ready`: readiness (ok cuando hay eventos, simulación o eBPF listo).
- `/metrics`: métricas Prometheus.
- `/stats`: último snapshot de estadísticas.

Métricas clave
- `ebpf_packets_processed_total{protocol,direction}`
- `ebpf_bytes_processed_total{protocol}`
- `ebpf_suspicious_activity_total{type}`
- `ebpf_syn_packets_total`
- `ebpf_unique_ips` (gauge por ventana)
- `ebpf_unique_ports` (gauge por ventana)
- `ebpf_packets_per_second`, `ebpf_bytes_per_second`
- `ebpf_ringbuf_lost_events_total`

Variables de entorno
- `INTERFACE`: interfaz (default `eth0`).
- `MODE`: `auto|xdp|sim` (actualmente `auto/sim`).
- `HTTP_ADDR`: dirección (default `:8800`).
- `HTTP_READ_HEADER_TIMEOUT`/`HTTP_READ_TIMEOUT`/`HTTP_WRITE_TIMEOUT`/`HTTP_IDLE_TIMEOUT`.
- `STATS_WINDOW`: tamaño de ventana (default `1s`).
- `POST_INTERVAL`: frecuencia de envío a `ml-detector` (default `2s`).
- `ML_DETECTOR_URL`: URL del detector (default `http://ml-detector:5000`).
- `HTTP_CLIENT_TIMEOUT`: timeout cliente ML (default `2s`).
- `LOG_LEVEL`: nivel de log.

Contenerización
- Usa `applications/ebpf-monitor/Dockerfile`. Corre como root por eBPF.
- En Kubernetes, añade securityContext con capacidades o `privileged: true` y monta `bpffs` si es necesario.

