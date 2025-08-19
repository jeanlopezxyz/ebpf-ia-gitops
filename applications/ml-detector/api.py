from __future__ import annotations

import logging
from flask import Blueprint, jsonify, request, Response

from detector import ThreatDetector
from metrics import (
    generate_metrics_payload,
    REQUESTS_TOTAL,
    PROCESSING_TIME,
    THREATS_DETECTED,
)
from schemas import DetectRequest

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
                "models_trained": detector.is_trained,
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
                req = DetectRequest(**(request.get_json(force=True) or {}))
                result = detector.detect(req.to_features_dict())
                # increment counters per threat
                for t in result.get("threat_types", []):
                    THREATS_DETECTED.labels(threat_type=t).inc()
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
                "models_trained": detector.is_trained,
                "training_samples": len(detector.training_window),
                "kmeans_clusters": getattr(detector.kmeans, "n_clusters", 0),
                "thresholds": detector.thresholds,
            }
        )

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
                    "train": "/train (POST)",
                    "stats": "/stats",
                },
            }
        )

    return api
