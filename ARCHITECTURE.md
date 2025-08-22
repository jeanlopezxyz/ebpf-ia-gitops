# System Architecture - eBPF + AI GitOps Security Platform

## Overview

This document explains the complete architecture of our eBPF-based AI security monitoring platform, designed for production use with enterprise-grade threat detection capabilities.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     KUBERNETES CLUSTER                         │
│                                                                 │
│  ┌──────────────────┐         ┌─────────────────────┐          │
│  │   eBPF Monitor   │ ──HTTP──▶│   ML Detector       │          │
│  │   (Data Plane)   │ /detect  │   (Control Plane)   │          │
│  │                  │         │                     │          │
│  │ • XDP Hook       │         │ • Rule Engine       │          │
│  │ • Ring Buffer    │         │ • DBSCAN Model      │          │
│  │ • Go Aggregation │         │ • VAE Model         │          │
│  │ • QoS Metrics    │         │ • ZMAD Statistics   │          │
│  └──────┬───────────┘         └─────────┬───────────┘          │
│         │                               │                      │
│         │ /metrics              /metrics│                      │
│  ┌──────▼───────────────────────────────▼──────────────────┐   │
│  │                 Prometheus                              │   │
│  │           (Metrics Storage & Query)                     │   │
│  └──────────────────────┬──────────────────────────────────┘   │
│                         │                                      │
│  ┌──────────────────────▼──────────────────────────────────┐   │
│  │                   Grafana                               │   │
│  │            (Dashboards & Alerting)                      │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### eBPF Monitor (Data Plane)

**Location**: `applications/ebpf-monitor/`
**Language**: Go + eBPF (C)
**Purpose**: High-performance network data capture and aggregation

#### Architecture:
```
applications/ebpf-monitor/
├── cmd/monitor/main.go          # Application entry point
├── pkg/
│   ├── config/config.go         # Configuration management
│   ├── metrics/metrics.go       # Prometheus metrics
│   ├── ebpf/network_monitor.go  # eBPF coordination  
│   └── qos/calculator.go        # QoS calculations
└── bpf/network_monitor.c        # eBPF kernel program
```

#### Key Responsibilities:
1. **Packet Capture**: XDP eBPF program captures every network packet
2. **Feature Extraction**: Aggregates packets into meaningful features
3. **QoS Analysis**: Calculates latency, jitter, packet loss metrics
4. **IP Tracking**: Identifies top attacking IPs with packet counts
5. **Data Export**: Sends features to ML Detector via HTTP POST

### ML Detector (Control Plane)

**Location**: `applications/ml-detector/`
**Language**: Python + TensorFlow + Scikit-learn
**Purpose**: Intelligent threat analysis and decision making

#### Architecture:
```
applications/ml-detector/
├── constants.py              # Centralized configuration
├── threat_detector.py        # Main orchestrator
├── models/
│   ├── base.py              # Abstract interfaces
│   ├── spatial.py           # DBSCAN clustering
│   ├── temporal.py          # VAE sequence analysis
│   └── statistical.py       # ZMAD statistical detection
├── rules/
│   └── network_rules.py     # Rule-based detection
├── api.py                   # REST API
├── app.py                   # Flask application
├── metrics.py               # Prometheus metrics
└── schemas.py               # Request/response schemas
```

#### Key Responsibilities:
1. **Rule Engine**: Fast detection of known attack patterns
2. **ML Ensemble**: 3-model consensus for unknown anomalies
3. **Feature Engineering**: Extracts features for ML models
4. **Training Management**: Continuous model retraining with clean data
5. **Metrics Export**: Detailed Prometheus metrics for monitoring

## Data Flow

### 1. Network Traffic Capture
```
Internet Traffic → XDP eBPF Hook → Ring Buffer → Go Processing
```

### 2. Feature Aggregation  
```
Raw Packets → Window Aggregation → Feature Vector → ML Analysis
```

### 3. Threat Detection
```
Features → Rule Engine + ML Ensemble → Consensus Decision → Alert
```

### 4. Metrics Export
```
Threat Data → Prometheus Metrics → Grafana Dashboards → SOC Team
```

## Detection Models

### Rule-Based Detection (Fast Response)
- **Network Rules**: Port scan, DDoS, data exfiltration, SYN flood
- **QoS Rules**: Latency, jitter, packet loss thresholds
- **Auth Rules**: Brute force, credential stuffing, username confusion
- **Response Time**: <1ms per detection

### ML Ensemble (Comprehensive Analysis)
- **DBSCAN**: Spatial clustering, handles arbitrary cluster shapes
- **VAE**: Temporal sequence analysis, detects time-series anomalies
- **ZMAD**: Statistical baseline, robust against outliers
- **Consensus**: Requires agreement from ≥2 models for high-confidence alerts

## Data Management

### Training Data Strategy
1. **High-Confidence Window**: Clean data for conservative models
2. **All-Data Window**: Complete patterns including edge cases
3. **Recent Window**: Last 10 minutes for similarity analysis
4. **Time-Series Window**: Sequences for VAE temporal analysis

### Quality Control
- **Confidence Weighting**: Probabilistic inclusion vs binary filtering
- **Clean Data Filtering**: Avoids training on attack data
- **Historical Similarity**: Validates new patterns against known good traffic

## Deployment

### GitOps Integration
```
Git Push → Tekton Pipeline → Container Build → ArgoCD Sync → K8s Deploy
```

### Monitoring Stack
```
eBPF Monitor → Prometheus → Grafana Dashboards → Alertmanager → SOC Team
```

## Scaling Considerations

### Horizontal Scaling
- **eBPF Monitor**: DaemonSet (one per node)
- **ML Detector**: Deployment (multiple replicas)
- **Prometheus**: Federated setup for large clusters
- **Grafana**: HA configuration with shared storage

### Performance Optimization
- **eBPF**: Kernel-level capture with minimal overhead
- **Go**: Efficient aggregation and HTTP communication
- **Python**: Optimized ML inference with model caching
- **Metrics**: Efficient Prometheus exposition format

## Security Considerations

### Data Protection
- **No PII**: Only aggregated traffic patterns, no packet contents
- **Secure Communication**: TLS between components
- **Access Control**: RBAC for Kubernetes resources

### Model Security
- **Training Data Validation**: Clean data filtering prevents poisoning
- **Model Persistence**: Secure storage with version control
- **Consensus Mechanism**: Multiple models prevent single point of failure

## Troubleshooting

### Common Issues
1. **eBPF Attachment Failure**: Check privileges and interface availability
2. **ML Model Not Training**: Verify sufficient clean data samples
3. **High False Positives**: Tune thresholds in `constants.py`
4. **Missing Metrics**: Check Prometheus scraping configuration

### Debug Commands
```bash
# Check eBPF status
curl localhost:8800/health

# Check ML model status  
curl localhost:5000/stats

# View raw metrics
curl localhost:5000/metrics
curl localhost:8800/metrics
```

This architecture provides enterprise-grade security monitoring with the flexibility to adapt to new threats while maintaining high performance and reliability.