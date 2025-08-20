from __future__ import annotations

import os
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from prometheus_client import CollectorRegistry

try:
    from prometheus_client import multiprocess
except Exception:  # pragma: no cover
    multiprocess = None  # type: ignore


# Core metrics
REQUESTS_TOTAL = Counter("ml_detector_requests_total", "Total ML detector requests")

# Comprehensive threat detection metrics
THREATS_DETECTED = Counter(
    "ml_detector_threats_total", 
    "Total threats detected", 
    ["threat_type", "confidence_level", "source_ip"]
)

THREAT_CONFIDENCE = Histogram(
    "ml_detector_threat_confidence",
    "Confidence scores of detected threats",
    ["threat_type"],
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
)

# Specific threat type metrics
PORT_SCAN_DETECTED = Counter(
    "ml_detector_port_scan_total", 
    "Port scanning attempts detected",
    ["severity"]
)

DDOS_DETECTED = Counter(
    "ml_detector_ddos_total",
    "DDoS attacks detected", 
    ["attack_type"]
)

DATA_EXFILTRATION_DETECTED = Counter(
    "ml_detector_data_exfiltration_total",
    "Data exfiltration attempts detected",
    ["direction"]
)

ANOMALY_DETECTED = Counter(
    "ml_detector_anomaly_total",
    "ML-based anomalies detected",
    ["model_type", "severity"]
)

# Model performance metrics
PROCESSING_TIME = Histogram(
    "ml_detector_processing_seconds", "Time spent processing"
)
MODEL_ACCURACY = Gauge(
    "ml_detector_model_accuracy", 
    "Current model accuracy",
    ["model_name"]
)
ANOMALY_SCORE = Gauge(
    "ml_detector_anomaly_score", 
    "Current anomaly score",
    ["feature_type"]
)

# Feature analysis metrics
FEATURE_VALUES = Gauge(
    "ml_detector_feature_values",
    "Current feature values from network data",
    ["feature_name"]
)

THREAT_SEVERITY = Gauge(
    "ml_detector_threat_severity",
    "Current threat severity level (0-1)",
    ["threat_category"]
)

# Model retraining metrics
MODEL_RETRAIN_COUNT = Counter(
    "ml_detector_model_retrain_total",
    "Number of model retraining events",
    ["model_name", "trigger_reason"]
)

MODEL_RETRAIN_DURATION = Histogram(
    "ml_detector_model_retrain_seconds",
    "Time spent retraining models",
    ["model_name"]
)


def generate_metrics_payload() -> bytes:
    """Return Prometheus metrics considering multiprocess mode if enabled."""
    if os.getenv("PROMETHEUS_MULTIPROC_DIR") and multiprocess is not None:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry)
    return generate_latest()

