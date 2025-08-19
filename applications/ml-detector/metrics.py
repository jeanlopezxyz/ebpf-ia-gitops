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
THREATS_DETECTED = Counter(
    "ml_detector_threats_total", "Total threats detected", ["threat_type"]
)
PROCESSING_TIME = Histogram(
    "ml_detector_processing_seconds", "Time spent processing"
)
MODEL_ACCURACY = Gauge("ml_detector_model_accuracy", "Current model accuracy")
ANOMALY_SCORE = Gauge("ml_detector_anomaly_score", "Current anomaly score")


def generate_metrics_payload() -> bytes:
    """Return Prometheus metrics considering multiprocess mode if enabled."""
    if os.getenv("PROMETHEUS_MULTIPROC_DIR") and multiprocess is not None:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry)
    return generate_latest()

