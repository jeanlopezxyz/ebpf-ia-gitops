from __future__ import annotations

import logging
from flask import Blueprint, jsonify, request, Response

from threat_detector import ThreatDetector
from pydantic import ValidationError
from metrics import (
    generate_metrics_payload,
    REQUESTS_TOTAL,
    PROCESSING_TIME,
    THREATS_DETECTED,
)
from schemas import DetectRequest
from prom_source import PrometheusSource

logger = logging.getLogger(__name__)


def create_api(detector: ThreatDetector) -> Blueprint:
    api = Blueprint("api", __name__)

    @api.route("/health")
    def health() -> Response:
        return jsonify(
            {
                "status": "healthy",
                "service": "ml-detector",
                "version": "2.0.0",
                "models_trained": {
                    "spatial": detector.spatial_detector.is_trained(),
                    "temporal": detector.temporal_detector.is_trained(),
                    "statistical": detector.statistical_detector.is_trained()
                },
            }
        )

    @api.route("/metrics")
    def metrics() -> Response:
        payload = generate_metrics_payload()
        return Response(payload, mimetype="text/plain; version=0.0.4; charset=utf-8")

    @api.route("/detect", methods=["POST"])
    def detect_threat() -> Response:
        if not request.is_json:
            return jsonify({"error": "Unsupported Media Type, expected application/json"}), 415
        try:
            with PROCESSING_TIME.time():
                REQUESTS_TOTAL.inc()
                try:
                    req = DetectRequest(**(request.get_json(force=True) or {}))
                except ValidationError as ve:
                    return jsonify({"error": ve.errors()}), 400
                detection_result = detector.detect(req.to_features_dict())
                result = detection_result.to_dict()
                # increment counters per threat (with required labels)
                for t in result.get("threat_types", []):
                    confidence = result.get("confidence", 0.0)
                    confidence_level = "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low"
                    THREATS_DETECTED.labels(
                        threat_type=t, 
                        confidence_level=confidence_level,
                        source_ip="api_request"
                    ).inc()
                return jsonify(result)
        except Exception as e:
            logger.error(f"Detection error: {e}")
            return (
                jsonify({"error": str(e), "threat_detected": False, "confidence": 0.0}),
                500,
            )

    @api.route("/train", methods=["POST"])
    def train() -> Response:
        try:
            detector.train_models()
            return jsonify({"status": "training completed"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @api.route("/stats")
    def stats() -> Response:
        return jsonify(
            {
                "models_trained": {
                    "spatial": detector.spatial_detector.is_trained(),
                    "temporal": detector.temporal_detector.is_trained(),
                    "statistical": detector.statistical_detector.is_trained()
                },
                "training_samples": len(detector.all_data_window),
                "high_confidence_samples": len(detector.high_confidence_window),
            }
        )

    @api.route("/detect/prom", methods=["POST", "GET"])
    def detect_from_prometheus() -> Response:
        """Build a feature snapshot from Prometheus and run detection.

        Optional JSON body can override query window and metric names:
        {
          "window": "1m", "metrics": {"packets": "...", "bytes": "..."}
        }
        """
        try:
            payload = request.get_json(silent=True) or {}
            src = PrometheusSource()
            # allow runtime override of window/metrics
            if isinstance(payload, dict):
                if "window" in payload and isinstance(payload["window"], str):
                    src.window = payload["window"]
                metrics = payload.get("metrics") or {}
                if isinstance(metrics, dict):
                    src.m_packets = metrics.get("packets", src.m_packets)
                    src.m_bytes = metrics.get("bytes", src.m_bytes)
                    src.m_syn = metrics.get("syn", src.m_syn)
                    src.m_unique_ips = metrics.get("unique_ips", src.m_unique_ips)
                    src.m_unique_ports = metrics.get("unique_ports", src.m_unique_ports)
            features = src.snapshot()
            with PROCESSING_TIME.time():
                REQUESTS_TOTAL.inc()
                detection_result = detector.detect(features)
                result = detection_result.to_dict()
                # increment counters per threat (with required labels)
                for t in result.get("threat_types", []):
                    confidence = result.get("confidence", 0.0)
                    confidence_level = "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low"
                    THREATS_DETECTED.labels(
                        threat_type=t, 
                        confidence_level=confidence_level,
                        source_ip="prometheus_query"
                    ).inc()
                return jsonify({"features": features, "result": result})
        except Exception as e:
            logger.error(f"Prometheus detection error: {e}")
            return jsonify({"error": str(e)}), 500

    @api.route("/")
    def root() -> Response:
        return jsonify(
            {
                "service": "ML Detector",
                "version": "2.0.0",
                "description": "Real-time threat detection using K-means, LOF, and One-Class SVM",
                "models": ["K-means", "Local Outlier Factor", "One-Class SVM"],
                "endpoints": {
                    "health": "/health",
                    "metrics": "/metrics",
                    "detect": "/detect (POST)",
                    "detect_from_prom": "/detect/prom (GET|POST)",
                    "train": "/train (POST)",
                    "stats": "/stats",
                },
            }
        )

    return api
