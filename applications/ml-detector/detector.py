from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.cluster import MiniBatchKMeans
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from metrics import ANOMALY_SCORE, MODEL_ACCURACY

logger = logging.getLogger(__name__)


class ThreatDetector:
    def __init__(self) -> None:
        # Config
        self.model_path = os.getenv("MODEL_PATH", "/tmp/models")
        self.training_enabled = os.getenv("TRAINING_ENABLED", "true").lower() == "true"
        self.baseline_enabled = os.getenv("BASELINE_ENABLED", "true").lower() == "true"
        self.training_interval = int(os.getenv("TRAINING_INTERVAL_SECONDS", "30"))

        # Concurrency primitives
        self._lock = threading.RLock()

        # Data window
        self.training_window: Deque[np.ndarray] = deque(maxlen=1000)
        self.is_trained = False

        # Thresholds for rule-based checks
        self.thresholds: Dict[str, Dict[str, float]] = {
            "port_scan": {"unique_ports": 20, "packets_per_second": 100},
            "ddos": {"packets_per_second": 1000, "bytes_per_second": 1_000_000},
            "data_exfiltration": {"bytes_per_second": 5_000_000, "tcp_ratio": 0.9},
            "syn_flood": {"syn_packets": 500, "tcp_ratio": 0.95},
        }

        # Models
        self.scaler = StandardScaler()
        self.kmeans = MiniBatchKMeans(
            n_clusters=5, batch_size=32, max_iter=100, random_state=42
        )
        self.lof = LocalOutlierFactor(
            n_neighbors=20, contamination=0.1, novelty=True, n_jobs=-1
        )
        self.svm = OneClassSVM(kernel="linear", nu=0.05, gamma="auto")

        os.makedirs(self.model_path, exist_ok=True)

        # Try load models; otherwise optionally seed baseline
        self.load_models()
        if self.baseline_enabled and not self.is_trained:
            try:
                self._seed_baseline()
            except Exception as e:  # pragma: no cover
                logger.warning(f"Baseline seeding failed: {e}")

        # Background training thread
        if self.training_enabled:
            t = threading.Thread(target=self._background_training, daemon=True)
            t.start()

    def _seed_baseline(self) -> None:
        normal_data: List[Dict[str, float]] = []
        for _ in range(200):
            normal_data.append(
                {
                    "packets_per_second": float(np.random.normal(50, 10)),
                    "bytes_per_second": float(np.random.normal(50000, 10000)),
                    "unique_ips": int(np.random.randint(5, 20)),
                    "unique_ports": int(np.random.randint(3, 10)),
                    "tcp_ratio": float(np.random.uniform(0.6, 0.8)),
                    "syn_packets": int(np.random.randint(10, 50)),
                }
            )
        for d in normal_data:
            self.extract_features(d)
        self.train_models()

    def extract_features(self, data: Dict[str, float]) -> np.ndarray:
        features = np.array(
            [
                [
                    data.get("packets_per_second", 0),
                    data.get("bytes_per_second", 0),
                    data.get("unique_ips", 0),
                    data.get("unique_ports", 0),
                    data.get("tcp_ratio", 0.5),
                    data.get("syn_packets", 0),
                ]
            ]
        )
        with self._lock:
            self.training_window.append(features[0])
            if hasattr(self.scaler, "mean_"):
                features = self.scaler.transform(features)
        return features

    def detect_rule_based(self, data: Dict[str, float]) -> List[Tuple[str, float]]:
        threats: List[Tuple[str, float]] = []
        if data.get("unique_ports", 0) > self.thresholds["port_scan"]["unique_ports"]:
            if data.get("packets_per_second", 0) > self.thresholds["port_scan"][
                "packets_per_second"
            ]:
                threats.append(("port_scan", 0.9))
        if data.get("packets_per_second", 0) > self.thresholds["ddos"][
            "packets_per_second"
        ]:
            if data.get("bytes_per_second", 0) > self.thresholds["ddos"][
                "bytes_per_second"
            ]:
                threats.append(("ddos", 0.95))
        if data.get("bytes_per_second", 0) > self.thresholds["data_exfiltration"][
            "bytes_per_second"
        ]:
            if data.get("tcp_ratio", 0) > self.thresholds["data_exfiltration"][
                "tcp_ratio"
            ]:
                threats.append(("data_exfiltration", 0.85))
        if data.get("syn_packets", 0) > self.thresholds["syn_flood"]["syn_packets"]:
            if data.get("tcp_ratio", 0) > self.thresholds["syn_flood"]["tcp_ratio"]:
                threats.append(("syn_flood", 0.92))
        return threats

    def detect_ml_based(self, features: np.ndarray) -> List[Tuple[str, float]]:
        if not self.is_trained:
            return []
        anomaly_scores: List[float] = []
        try:
            with self._lock:
                if hasattr(self.kmeans, "cluster_centers_"):
                    distances = self.kmeans.transform(features)
                    min_distance = float(np.min(distances))
                    kmeans_score = min(min_distance / 10.0, 1.0)
                    anomaly_scores.append(kmeans_score)
                if hasattr(self.lof, "offset_"):
                    lof_decision = float(self.lof.decision_function(features)[0])
                    lof_score = max(0.0, min(1.0, -lof_decision))
                    anomaly_scores.append(lof_score)
                if hasattr(self.svm, "support_"):
                    svm_decision = float(self.svm.decision_function(features)[0])
                    svm_score = max(0.0, min(1.0, -svm_decision))
                    anomaly_scores.append(svm_score)
        except Exception as e:  # pragma: no cover
            logger.warning(f"ML detection error: {e}")
        if anomaly_scores:
            final_score = float(np.mean(anomaly_scores))
            ANOMALY_SCORE.set(final_score)
            if final_score > 0.7:
                return [("ml_high_risk", final_score)]
            if final_score > 0.5:
                return [("ml_medium_risk", final_score)]
            if final_score > 0.3:
                return [("ml_low_risk", final_score)]
        return []

    def detect(self, data: Dict[str, float]) -> Dict[str, object]:
        features = self.extract_features(data)
        rule_threats = self.detect_rule_based(data)
        ml_threats = self.detect_ml_based(features)
        all_threats = rule_threats + ml_threats
        if all_threats:
            max_conf = max(t[1] for t in all_threats)
            return {
                "threat_detected": True,
                "confidence": float(max_conf),
                "threat_types": [t[0] for t in all_threats],
                "scores": {"rule_based": len(rule_threats) > 0, "ml_based": len(ml_threats) > 0},
            }
        return {"threat_detected": False, "confidence": 0.0, "threat_types": [], "scores": {}}

    def _background_training(self) -> None:  # pragma: no cover
        while True:
            time.sleep(self.training_interval)
            try:
                self.train_models()
            except Exception as e:
                logger.error(f"Background training error: {e}")

    def train_models(self) -> None:
        with self._lock:
            if len(self.training_window) < 100:
                return
            X = np.array(list(self.training_window))
            if not hasattr(self.scaler, "mean_"):
                self.scaler.fit(X)
            else:
                # incremental update
                self.scaler.partial_fit(X)
            Xs = self.scaler.transform(X)
            self.kmeans.partial_fit(Xs)
            if len(Xs) >= 20:
                self.lof.fit(Xs)
            self.svm.fit(Xs)
            self.is_trained = True
            MODEL_ACCURACY.set(0.0)  # placeholder, not supervised
        self.save_models()

    def save_models(self) -> None:
        try:
            with self._lock:
                joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
                joblib.dump(self.kmeans, f"{self.model_path}/kmeans.pkl")
                joblib.dump(self.lof, f"{self.model_path}/lof.pkl")
                joblib.dump(self.svm, f"{self.model_path}/svm.pkl")
            logger.info("Models saved successfully")
        except Exception as e:  # pragma: no cover
            logger.error(f"Error saving models: {e}")

    def load_models(self) -> None:
        try:
            with self._lock:
                if os.path.exists(f"{self.model_path}/scaler.pkl"):
                    self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
                    self.kmeans = joblib.load(f"{self.model_path}/kmeans.pkl")
                    self.lof = joblib.load(f"{self.model_path}/lof.pkl")
                    self.svm = joblib.load(f"{self.model_path}/svm.pkl")
                    self.is_trained = True
                    logger.info("Models loaded successfully")
        except Exception as e:  # pragma: no cover
            logger.warning(f"Could not load models: {e}")
