# eBPF + IA: Detección de Amenazas en Tiempo Real

## ¿Cómo detectar ataques cibernéticos en tiempo real sin impactar el rendimiento?

Imagina un sistema que puede analizar **cada paquete de red** que pasa por tu infraestructura, detectar patrones sospechosos como ataques DDoS o escaneos de puertos, y alertarte en segundos - todo esto sin afectar la velocidad de tu red. Esto es exactamente lo que logra este proyecto combinando **eBPF** (observabilidad a nivel del kernel) con **Inteligencia Artificial**.

### El Problema que Resolvemos

Los sistemas tradicionales de seguridad enfrentan un dilema:
- **Monitoreo superficial**: Rápido pero pierde detalles críticos  
- **Análisis profundo**: Detecta todo pero ralentiza el sistema

Nuestra solución rompe este compromiso usando eBPF para capturar datos a velocidad del kernel, y modelos de ML para detectar tanto amenazas conocidas como anomalías nuevas.

### Arquitectura en 2 Minutos

El sistema tiene dos componentes principales que trabajan en conjunto:

1. **`ebpf-monitor`** (Go + eBPF): El "sensor" que captura tráfico de red
2. **`ml-detector`** (Python + Flask): El "cerebro" que analiza y decide

Todo se despliega automáticamente via GitOps con ArgoCD y se monitorea con Prometheus/Grafana.

## Los Componentes en Acción

### 🔍 eBPF Monitor: El Sensor de Red Inteligente

**Ubicación**: `applications/ebpf-monitor/`  
**Lenguaje**: Go + eBPF (C)  
**Puerto**: 8800  

Este es nuestro "radar" que nunca duerme. Aquí es donde la magia de eBPF sucede:

#### 1. Captura a Velocidad del Kernel
```go
// Estructura que replica exactamente el struct C del kernel
type NetworkEvent struct {
    SrcIP      uint32 // IP origen
    DstIP      uint32 // IP destino  
    SrcPort    uint16 // Puerto origen
    DstPort    uint16 // Puerto destino
    Protocol   uint8  // TCP/UDP/ICMP
    PacketSize uint32 // Tamaño en bytes
    Timestamp  uint64 // Cuándo ocurrió
    TCPFlags   uint8  // SYN, ACK, etc.
}
```

**¿Cómo lo hace tan rápido?**
- El programa eBPF (en C) vive en el kernel y "ve" cada paquete
- Envía eventos via ring buffer (canal ultrarrápido)
- Go consume eventos sin interrumpir el kernel

#### 2. Agregación Inteligente por Ventanas
En lugar de procesar paquete por paquete, agrupa datos en "ventanas" de tiempo:

```
Ventana de 1 segundo:
├── 1,247 paquetes/seg
├── 987,432 bytes/seg  
├── 23 IPs únicas
├── 15 puertos únicos
└── 89 paquetes SYN
```

**Configuración**: Variable `STATS_WINDOW` (por defecto 1s)

#### 3. API HTTP Rica en Información
- **`/health`**: ¿Está vivo el monitor?
- **`/ready`**: ¿eBPF funcionando o modo simulación activo?
- **`/metrics`**: Métricas Prometheus para observabilidad
- **`/stats`**: Snapshot actual de estadísticas

#### 4. Comunicación con la IA
Cada `POST_INTERVAL` (2s por defecto), envía un POST a `ml-detector`:

```json
{
  "packets_per_second": 1247,
  "bytes_per_second": 987432,
  "unique_ips": 23,
  "unique_ports": 15,
  "tcp_ratio": 0.85,
  "syn_packets": 89
}
```

#### 5. Modo de Emergencia
**Sin privilegios eBPF?** No hay problema - se activa **modo simulación**:
- Genera datos sintéticos realistas
- Mantiene APIs funcionando
- Ideal para desarrollo y testing

### 🧠 ML Detector: El Cerebro que Decide

**Ubicación**: `applications/ml-detector/`  
**Lenguaje**: Python + Flask + Scikit-learn  
**Puerto**: 5000  

Este es donde los datos se transforman en decisiones inteligentes. El detector combina **reglas explícitas** con **modelos de machine learning** para detectar tanto amenazas conocidas como anomalías nuevas.

#### 1. API Simple pero Poderosa

```python
# El endpoint principal
POST /detect
Content-Type: application/json

{
  "packets_per_second": 1200,
  "bytes_per_second": 1500000,
  "unique_ips": 30,
  "unique_ports": 50,
  "tcp_ratio": 0.95,
  "syn_packets": 800
}

# Respuesta con veredicto
{
  "threat_detected": true,
  "confidence": 0.87,
  "threat_types": ["port_scan", "ml_medium_risk"]
}
```

**Otros endpoints útiles:**
- **`GET /detect/prom`**: Consulta Prometheus directamente y analiza
- **`/health`**: Estado del servicio y modelos
- **`/metrics`**: Métricas detalladas para Prometheus
- **`/train`**: Reentrenamiento manual de modelos

#### 2. Detección Híbrida: Reglas + IA

##### A) Reglas Rápidas y Explicables
```python
thresholds = {
    "port_scan": {
        "unique_ports": 20,      # >20 puertos únicos
        "packets_per_second": 100 # + alto PPS = sospechoso
    },
    "ddos": {
        "packets_per_second": 1000,   # >1000 PPS
        "bytes_per_second": 1_000_000 # + 1MB/s = posible DDoS
    },
    "syn_flood": {
        "syn_packets": 500,     # >500 SYNs/ventana
        "tcp_ratio": 0.95       # + 95% TCP = SYN flood
    }
}
```

##### B) Modelos ML para Anomalías Desconocidas

**Ensamble de 3 algoritmos** que se complementan:

1. **MiniBatchKMeans** (Clustering)
   - **Propósito**: Define qué es "tráfico normal" con centros de clusters
   - **Detección**: Distancia > umbral = anómalo
   - **Fortaleza**: Muy rápido, ideal para streaming

2. **LocalOutlierFactor** (Densidad)
   - **Propósito**: Detecta puntos con densidad local baja
   - **Detección**: Sensible a anomalías sutiles
   - **Fortaleza**: Capta patrones complejos

3. **OneClassSVM** (Frontera de decisión)
   - **Propósito**: Delimita región "normal" con kernel lineal
   - **Detección**: Puntos fuera de región = anómalos
   - **Fortaleza**: Robusto en dimensiones moderadas

**Decisión final**: Promedio de scores → `ml_low/medium/high_risk`

#### 3. Entrenamiento Continuo en Background

```python
# Hilo separado que reentrena cada 30s
def background_training():
    while True:
        if len(training_window) > 50:  # Datos suficientes
            train_models()
            save_models()  # Persistencia con joblib
        time.sleep(TRAINING_INTERVAL)
```

**Características clave:**
- **Ventana deslizante**: Solo últimos 1000 samples para adaptarse
- **Persistencia**: Modelos se guardan en `/tmp/models` 
- **Baseline automático**: Si no hay modelos, genera datos sintéticos para iniciar
- **Thread seguro**: Usa locks para evitar conflictos

#### 4. Métricas Detalladas para Observabilidad

El detector emite métricas ricas para monitoreo:

```prometheus
# Amenazas por tipo específico
ml_detector_port_scan_total{severity="high"} 15
ml_detector_ddos_total{attack_type="volumetric"} 3
ml_detector_syn_flood_total{severity="medium"} 8

# Métricas generales
ml_detector_threats_total{threat_type="ml_high_risk",confidence_level="high"} 12
ml_detector_processing_seconds_bucket{le="0.1"} 1247  # Latencia

# Estado de modelos
ml_detector_model_accuracy{model="kmeans"} 0.91
ml_detector_threat_confidence{threat_type="port_scan"} 0.87
```

## Fundamentos: Las Tecnologías que Hacen la Magia Posible

### eBPF: Tu "Microscopio" del Kernel Linux

Piensa en **eBPF** como un microscopio súper potente que puede observar lo que pasa dentro del kernel Linux sin romper nada. 

**¿Cómo funciona en términos simples?**
- Es una "máquina virtual segura" que vive **dentro** del kernel
- Ejecuta pequeños programas que pueden "espiar" el tráfico de red, llamadas del sistema, etc.
- **Seguridad garantizada**: Linux verifica que el programa no pueda crashear el sistema
- **Rendimiento extremo**: Acceso directo a datos sin copiarlos múltiples veces

**Analogía**: Es como tener un fotógrafo profesional tomando fotos perfectas del tráfico en una autopista, sin crear ningún embotellamiento.

### XDP: La Primera Línea de Defensa  

**XDP (Express Data Path)** es el punto más temprano donde podemos "interceptar" un paquete de red:

```
Internet → Tarjeta de Red → XDP (AQUÍ!) → Stack TCP/IP → Aplicación
```

**¿Por qué es importante?**
- Procesa paquetes **antes** de que lleguen al sistema operativo
- Velocidad máxima: hasta 20+ millones de paquetes por segundo
- En nuestro proyecto: **solo observa, no bloquea** (modo pasivo)

### Ring Buffer: El Túnel de Datos Ultrarrápido

El **ring buffer** es como una cinta transportadora súper eficiente entre el kernel y nuestra aplicación Go:

```
Kernel (eBPF) → [Ring Buffer] → Go App
   Productor       256KB         Consumidor
```

**Ventajas vs. métodos tradicionales:**
- **10x menos latencia** que `perf_event`
- **Sin pérdida de datos** bajo alta carga  
- **Memoria compartida**: sin copiar datos innecesariamente

### Métricas de Red: Los "Síntomas" que Analizamos

Nuestro sistema rastrea estas señales clave:

| Métrica | Qué Significa | Cuándo es Sospechoso |
|---------|---------------|---------------------|
| **PPS** (Packets/sec) | Volumen de tráfico | >1000 puede ser DDoS |
| **BPS** (Bytes/sec) | Ancho de banda usado | Picos súbitos = exfiltración |
| **SYN Packets** | Intentos de conexión | >500/sec = SYN Flood |
| **IPs Únicas** | Diversidad de fuentes | >30 con alto PPS = port scan |
| **TCP Ratio** | % tráfico TCP vs total | >95% = tráfico muy dirigido |

### Por qué y cómo se usa aquí
- eBPF en XDP da telemetría casi en tiempo real con impacto mínimo, ideal para derivar features simples pero informativas.
- `ringbuf.Reader` consume eventos, actualiza métricas y ventanas; cada `POST_INTERVAL` se envía un snapshot estable a ML.
- Estas features alimentan reglas rápidas + ensamble de modelos no supervisados en `ml-detector` para cubrir patrones conocidos y desconocidos.

### Modelos ML: propósito y elección
- MiniBatchKMeans (clustering): modela lo “normal” en centros; distancia al centroide = rareza.
  - Pros: rápido, apto para streaming; capta macro-patrones de carga.
  - Contras: asume clusters aproximadamente esféricos; requiere escalado (se usa `StandardScaler`).
- Local Outlier Factor (LOF, novelty): detecta puntos con densidad local baja frente a vecinos.
  - Pros: sensible a anomalías locales (p. ej., subida de puertos únicos sin gran BPS).
  - Contras: parámetros a calibrar; coste > KMeans.
- One-Class SVM (kernel lineal): delimita la región “normal” y marca lo externo como novedad.
  - Pros: robusto en dimensiones moderadas, lineal = rápido.
  - Contras: sensible a outliers en entrenamiento; necesita datos escalados.
- Ensamble y decisión: se promedian scores normalizados (KMeans/LOF/SVM) → `ANOMALY_SCORE` y se discretiza en `ml_{low,medium,high}_risk`. En paralelo, reglas determinísticas (`port_scan`, `ddos`, `data_exfiltration`, `syn_flood`) aportan explicabilidad inmediata.
- Entrenamiento/deriva: reentrenos periódicos sobre ventana deslizante; persistencia con `joblib` en `MODEL_PATH`. Si no hay modelos, se siembra baseline sintético; ajustar umbrales con tráfico real para reducir falsos positivos.

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

### Diagrama (ASCII)

```
        Tráfico
          │
          ▼
   [XDP eBPF prog]
          │  (ringbuf events)
          ▼
   ebpf-monitor (Go)
      ├── /metrics  ─────────────┐
      ├── /health   ──┐          │ scrape
      └── → POST /detect (ML)    │
                                 ▼
        ml-detector (Flask/ML)  /metrics
                 │                  │
                 └───────┐          │
                         ▼          ▼
                      Prometheus  ←─────
                         │
                         ▼
                        Grafana (dashboards)

   (Deploy y sync vía Argo CD; charts Helm en repo)
```

### Consultas PromQL útiles
- Amenazas por tipo (últimos 15m):
  - `sum by (threat_type)(increase(ml_detector_threats_total[15m]))`
- Top 5 amenazas recientes:
  - `topk(5, sum by (threat_type)(increase(ml_detector_threats_total[30m])))`
- Latencia p95 del detector:
  - `histogram_quantile(0.95, sum by (le)(rate(ml_detector_processing_seconds_bucket[5m])))`
- Tráfico actual desde eBPF:
  - `ebpf_packets_per_second`
  - `ebpf_bytes_per_second`
- Reboots/errores del eBPF monitor:
  - `rate(ebpf_ringbuf_lost_events_total[5m])`

Sugerencias de paneles (Grafana):
- Timeseries de `ml_detector_threats_total` por `threat_type` con transform “rate()” y leyenda por etiqueta.
- Gauge para `ebpf_packets_per_second` y `ebpf_bytes_per_second` con umbrales.
- Tabla de “Top threats” usando `topk()` con `increase()` en 30 min.
- Heatmap de latencia con `ml_detector_processing_seconds_bucket` y `histogram_quantile()` para p50/p95/p99.
