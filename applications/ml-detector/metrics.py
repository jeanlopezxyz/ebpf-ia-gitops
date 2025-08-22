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
    ["severity", "source_ip"]
)

DDOS_DETECTED = Counter(
    "ml_detector_ddos_total",
    "DDoS attacks detected", 
    ["attack_type", "source_ip"]
)

DATA_EXFILTRATION_DETECTED = Counter(
    "ml_detector_data_exfiltration_total",
    "Data exfiltration attempts detected",
    ["direction", "source_ip"]
)

ANOMALY_DETECTED = Counter(
    "ml_detector_anomaly_total",
    "ML-based anomalies detected",
    ["model_type", "severity", "source_ip"]
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
    "Current anomaly score"
    # Removed labels to match usage in detector.py
)

# Feature analysis metrics
FEATURE_VALUES = Gauge(
    "ml_detector_feature_values",
    "Current feature values from network data",
    ["feature_name"]
)

# IP-specific metrics for Grafana dashboards
IP_PACKET_COUNT = Gauge(
    "ml_detector_ip_packet_count",
    "Packet count per source IP",
    ["source_ip"]
)

SUSPICIOUS_IP_ACTIVITY = Gauge(
    "ml_detector_suspicious_ip_activity",
    "Suspicious activity level per IP (0-1)",
    ["source_ip", "activity_type"]
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

# Training data quality metrics
TRAINING_DATA_QUALITY = Gauge(
    "ml_detector_training_data_quality",
    "Quality metrics for training data",
    ["metric_type"]
)

TRAINING_WINDOW_SIZE = Gauge(
    "ml_detector_training_window_size",
    "Current size of training windows",
    ["window_type"]
)

# Advanced ML model metrics (Rakuten-level)
DBSCAN_ANOMALY_SCORE = Gauge(
    "ml_detector_dbscan_anomaly_score",
    "DBSCAN-based anomaly detection score"
)

VAE_RECONSTRUCTION_ERROR = Gauge(
    "ml_detector_vae_reconstruction_error", 
    "VAE reconstruction error for sequential anomaly detection"
)

ADVANCED_MODEL_STATUS = Gauge(
    "ml_detector_advanced_model_status",
    "Status of advanced ML models (0=not ready, 1=ready)",
    ["model_name"]
)

SEQUENTIAL_ANOMALY_DETECTED = Counter(
    "ml_detector_sequential_anomaly_total",
    "Sequential anomalies detected by VAE",
    ["severity", "source_ip"] 
)

CLUSTER_ANOMALY_DETECTED = Counter(
    "ml_detector_cluster_anomaly_total", 
    "Cluster-based anomalies detected by DBSCAN",
    ["cluster_type", "source_ip"]
)


def generate_metrics_payload() -> bytes:
    """Return Prometheus metrics considering multiprocess mode if enabled."""
    if os.getenv("PROMETHEUS_MULTIPROC_DIR") and multiprocess is not None:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry)
    return generate_latest()

