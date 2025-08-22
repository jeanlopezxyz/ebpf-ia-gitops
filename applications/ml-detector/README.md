# ML Detector - Production-Ready Threat Detection

## Overview

Advanced threat detection service that combines rule-based detection with machine learning models. Supports both network traffic analysis and authentication log analysis, implementing algorithms at Rakuten Symphony level.

## Architecture

```
ml-detector/
├── constants.py           # Centralized configuration
├── threat_detector.py     # Main orchestrator  
├── models/
│   ├── base.py           # Interfaces and abstractions
│   ├── spatial.py        # DBSCAN clustering
│   ├── temporal.py       # VAE sequence analysis
│   └── statistical.py    # ZMAD statistical detection
├── rules/
│   └── network_rules.py  # Rule-based detection
├── api.py                # REST API endpoints
└── app.py                # Flask application
```

## Detection Capabilities

### Network Traffic Analysis
- **Port Scanning**: Unusual port diversity + high packet rate
- **DDoS Attacks**: High packet/byte rates from multiple sources  
- **Data Exfiltration**: High outbound traffic with TCP dominance
- **SYN Flood**: Excessive SYN packets with high TCP ratio
- **QoS Degradation**: Latency, jitter, and packet loss anomalies

### Authentication Log Analysis  
- **Brute Force**: Excessive login attempts with high failure rate
- **Credential Stuffing**: High attempts from multiple IP addresses
- **Username Confusion**: Passwords/commands in username field
- **Service Account Abuse**: Elevated privilege accounts with anomalous usage

## ML Models (Rakuten Symphony Level)

1. **DBSCAN** - Spatial clustering for outlier detection
2. **VAE** - Temporal sequence analysis for time-series anomalies  
3. **ZMAD** - Statistical baseline using Modified Z-Score

## Quick Start

```bash
# Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start service
gunicorn -b 0.0.0.0:5000 app:app --workers 2 --threads 4

# Test network detection
curl -X POST :5000/detect -H 'Content-Type: application/json' \
  -d '{"packets_per_second": 1200, "unique_ports": 50}'

# Test authentication detection
curl -X POST :5000/detect -H 'Content-Type: application/json' \
  -d '{"username_type": "command", "total_attempts": 500}'
```

## Configuration

### Environment Variables
- `MODEL_PATH`: Model persistence directory (default: `/tmp/models`)
- `TRAINING_ENABLED`: Enable background training (default: `true`)
- `LOG_LEVEL`: Logging level (default: `INFO`)
- `PROMETHEUS_MULTIPROC_DIR`: Metrics directory (default: `/tmp/prometheus`)

### Tuning Parameters
Edit `constants.py` to adjust:
- Detection thresholds for each threat type
- ML model parameters (DBSCAN eps, VAE architecture)
- Consensus decision boundaries
- Window sizes for training data

## API Endpoints

- `POST /detect` - Main threat detection
- `POST /classify_username` - Username content classification  
- `GET /detect/prom` - Detection using Prometheus data
- `GET /health` - Service health and model status
- `GET /metrics` - Prometheus metrics export
- `POST /train` - Manual model retraining

## Monitoring

The service exports detailed Prometheus metrics for:
- Threat detection counts by type and source IP
- Model performance and training quality
- Processing latency and confidence scores
- Feature values and anomaly scores

See `metrics.py` for complete metrics list.
