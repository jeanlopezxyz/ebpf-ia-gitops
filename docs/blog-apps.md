## eBPF + IA: del paquete al veredicto (dentro de `applications/`)

Este artículo recorre, de forma práctica, cómo las dos apps principales de este repo convierten tráfico en señales y decisiones. La plataforma se orquesta por GitOps (Argo CD) y se observa con Prometheus/Grafana, pero aquí nos centramos en el “motor”: `applications/ebpf-monitor` (Go, eBPF) y `applications/ml-detector` (Python, ML + API).

### eBPF Monitor (Go): captar, agregar, exponer
- Captura eBPF: adjunta un programa XDP al interfaz de red (`cilium/ebpf`, ring buffer). Estructura `NetworkEvent` replica el struct C; un lector `ringbuf.Reader` procesa eventos en tiempo real.
- Agregación por ventana: cuenta PPS/BPS, IPs/puertos únicos y SYNs; reinicia el acumulado con un ticker configurable (`STATS_WINDOW`).
- Endpoints HTTP (`:8800`):
  - `/metrics`: expone métricas Prometheus con `promhttp` (ej. `ebpf_packets_processed_total{protocol,direction}`, `ebpf_bytes_per_second`, `ebpf_unique_ips`, `ebpf_ringbuf_lost_events_total`).
  - `/health`, `/stats` y `/` para liveness y snapshot.
- Envío al detector: cada `POST_INTERVAL` construye un JSON de features y lo envía a `ML_DETECTOR_URL/detect` (por defecto `http://ml-detector:5000`). Retries simples y contadores de fallo (`ml_post_failures_total`).
- Contenedor: requiere capacidades eBPF; si no están disponibles, puede operar en modo simulado (ver README para flags y securityContext sugerido).

### ML Detector (Python/Flask): señales → amenazas
- API compacta (Flask):
  - `POST /detect`: recibe features (pps, bps, ips únicos, puertos, tcp_ratio, syn_packets), ejecuta detección y responde `{threat_detected, confidence, threat_types}`.
  - `GET|POST /detect/prom`: arma un snapshot consultando Prometheus (PromQL, ventana configurable) y ejecuta la misma detección.
  - `/metrics`, `/health`, `/stats`, `/` (descubrimiento).
- Detección híbrida:
  - Reglas: umbrales por `port_scan`, `ddos`, `data_exfiltration`, `syn_flood` (rápido y explícito).
  - ML: ensamble ligero con `MiniBatchKMeans`, `LocalOutlierFactor (novelty)`, `OneClassSVM`. Calcula un score medio y lo mapea a `ml_low/medium/high_risk`.
  - Entrenamiento continuo: ventana deslizante con `StandardScaler`; thread de background y persistencia de modelos (`joblib` en `MODEL_PATH`). Si no hay modelos, se “siembra” un baseline.
- Métricas ricas (Prometheus):
  - Contadores por tipo (`ml_detector_port_scan_total{severity}`, `ml_detector_ddos_total{attack_type}`, `ml_detector_data_exfiltration_total{direction}`) y genérico (`ml_detector_threats_total{threat_type,confidence_level,source_ip}`).
  - Histogramas de latencia (`ml_detector_processing_seconds`) y confianza (`ml_detector_threat_confidence{threat_type}`); gauges de features y severidad.
  - Soporte multiproceso vía `PROMETHEUS_MULTIPROC_DIR`.

### Flujo extremo a extremo
1) eBPF Monitor observa el tráfico y expone métricas; además postea features al detector.
2) ML Detector combina reglas + modelos y devuelve un veredicto con confianza; emite métricas por cada alerta.
3) Prometheus scrapea `/metrics` de ambos. Las reglas en Helm pueden disparar `PrometheusRule` (ej. “ThreatDetected”, “PortScanDetected”). Grafana muestra paneles JSON embebidos en el chart.

### Probarlo rápido
- Bootstrap: `make bootstrap` y luego `make port-forward` para abrir Grafana/Prometheus/servicios.
- Salud rápida:
  - `curl -fsS http://localhost:8800/health` (ebpf-monitor)
  - `curl -fsS http://localhost:5000/health` (ml-detector)
- Detección manual:
  - `curl -X POST :5000/detect -H 'content-type: application/json' -d '{"packets_per_second":1200,"bytes_per_second":1500000,"unique_ips":30,"unique_ports":50,"tcp_ratio":0.95,"syn_packets":800}'`
- Observabilidad:
  - Prometheus: `http://localhost:9090` (consulta `ml_detector_threats_total` y `ebpf_packets_per_second`).
  - Grafana: dashboards de seguridad incluidos en el chart principal (`helm/charts/ebpf-ai/grafana/*.json`).

### Diseño opinado y siguientes pasos
- Separación de responsabilidades: Go para captura a bajo nivel; Python para decisiones y ML.
- Métricas primero: todo emite señales cuantificables; fácil de alertar y depurar.
- Acoplado por HTTP + Prometheus: sustituible y escalable (ServiceMonitor opcional en Helm).
- Próximos pasos sugeridos: afinar umbrales con datos reales, añadir features de flujo (duración/ratio conexiones), y entrenamientos batch con muestras etiquetadas.

