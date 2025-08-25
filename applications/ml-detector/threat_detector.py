"""
Main ThreatDetector class - simplified and maintainable.

This is the main orchestrator that coordinates all detection models
and rule engines in a clean, maintainable way.
"""
import logging
import threading
import time
import os
from collections import deque
from typing import Dict, List, Deque, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np

from models.base import DetectionResult
from models.spatial import SpatialAnomalyDetector
from models.temporal import TemporalAnomalyDetector  
from models.statistical import StatisticalAnomalyDetector
from rules.network_rules import NetworkRuleEngine
from constants import (
    TRAINING_CONFIG, WINDOW_SIZES, CONSENSUS_THRESHOLDS,
    IP_SUSPICIOUS_THRESHOLD, USERNAME_TYPE_ENCODING
)
from metrics import (
    TRAINING_DATA_QUALITY, TRAINING_WINDOW_SIZE, ADVANCED_MODEL_STATUS,
    MODEL_RETRAIN_COUNT, MODEL_RETRAIN_DURATION, IP_PACKET_COUNT,
    SUSPICIOUS_IP_ACTIVITY, FEATURE_VALUES
)

logger = logging.getLogger(__name__)


class ThreatDetector:
    """
    Main threat detection orchestrator.
    
    Coordinates multiple detection models and rule engines to provide
    comprehensive threat detection for network and authentication data.
    """
    
    def __init__(self):
        # Configuration
        self.model_path = os.getenv("MODEL_PATH", "/tmp/models")
        self.training_enabled = os.getenv("TRAINING_ENABLED", "true").lower() == "true"
        
        # Thread safety
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        
        # Data windows for different confidence levels
        self.high_confidence_window: Deque[np.ndarray] = deque(maxlen=WINDOW_SIZES["high_confidence"])
        self.all_data_window: Deque[np.ndarray] = deque(maxlen=WINDOW_SIZES["all_data"])
        self.recent_window: Deque[np.ndarray] = deque(maxlen=WINDOW_SIZES["recent"])
        
        # Statistics
        self.high_confidence_count = 0
        self.total_samples_count = 0
        
        # Performance optimization: ThreadPool for parallel model execution
        self._executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="ml_model")
        
        # Initialize detection components
        self.spatial_detector = SpatialAnomalyDetector()
        self.temporal_detector = TemporalAnomalyDetector()
        self.statistical_detector = StatisticalAnomalyDetector()
        self.network_rules = NetworkRuleEngine()
        
        # Setup
        os.makedirs(self.model_path, exist_ok=True)
        self._load_all_models()
        
        # Start background training
        if self.training_enabled:
            self._start_background_training()
    
    def extract_features(self, data: Dict[str, float], add_to_training: bool = True) -> np.ndarray:
        """Extract features and optionally add to training windows."""
        features = self._extract_features(data)
        
        if add_to_training:
            with self._lock:
                self.total_samples_count += 1
                self.all_data_window.append(features[0])
                self.recent_window.append(features[0])
                
                # High confidence determination (simplified)
                if self._is_high_confidence_sample(data):
                    self.high_confidence_window.append(features[0])
                    self.high_confidence_count += 1
        
        return features
    
    def _is_high_confidence_sample(self, data: Dict[str, float]) -> bool:
        """Determine if sample is high confidence for training."""
        # Simple heuristic: normal-looking network traffic
        pps = data.get("packets_per_second", 0)
        ports = data.get("unique_ports", 0)
        return pps < 500 and ports < 15
    
    def detect(self, data: Dict[str, float]) -> DetectionResult:
        """
        Main detection method.
        
        Args:
            data: Raw input data (network or authentication)
            
        Returns:
            DetectionResult with threat analysis
        """
        try:
            # Extract features and add to training
            features = self.extract_features(data, add_to_training=True)
            
            # Process IP-specific metrics
            attacking_ips = self._identify_attacking_ips(data)
            self._update_ip_metrics(data)
            
            # Rule-based detection (fast)
            rule_threats = self.network_rules.detect(data)
            
            # ML-based detection (comprehensive)
            ml_threats = self._detect_with_ml_ensemble(features)
            
            # Combine results
            all_threats = rule_threats + ml_threats
            
            if all_threats:
                max_confidence = max(threat[1] for threat in all_threats)
                threat_types = [threat[0] for threat in all_threats]
                
                # Update metrics
                self._update_threat_metrics(threat_types, max_confidence, attacking_ips)
                
                return DetectionResult(
                    threat_detected=True,
                    confidence=max_confidence,
                    threat_types=threat_types,
                    attacking_ips=attacking_ips,
                    detection_type=self._get_detection_type(data),
                    model_scores=self._get_model_scores()
                )
            
            return DetectionResult(
                threat_detected=False,
                confidence=0.0,
                threat_types=[],
                attacking_ips=attacking_ips,
                detection_type=self._get_detection_type(data)
            )
            
        except Exception as e:
            logger.error(f"Detection error: {e}")
            return DetectionResult(False, 0.0, [], [])
    
    def _extract_features(self, data: Dict[str, float]) -> np.ndarray:
        """Extract features based on data type."""
        if data.get("username_type"):
            # Authentication features
            username_type_encoded = USERNAME_TYPE_ENCODING.get(
                data.get("username_type", "username"), 0
            )
            return np.array([[
                username_type_encoded,
                data.get("total_attempts", 0),
                data.get("failed_attempts", 0),
                data.get("successful_attempts", 0),
                data.get("unique_source_ips", 0),
                data.get("privilege_level", 0)
            ]])
        else:
            # Network features
            tcp_packets = data.get("tcp_packets", 0)
            udp_packets = data.get("udp_packets", 0)
            total_packets = tcp_packets + udp_packets
            tcp_ratio = tcp_packets / total_packets if total_packets > 0 else 0.5
            
            return np.array([[
                data.get("packets_per_second", 0),
                data.get("bytes_per_second", 0),
                data.get("unique_ips", 0),
                data.get("unique_ports", 0),
                tcp_ratio,
                data.get("syn_packets", 0)
            ]])
    
    def _detect_with_ml_ensemble(self, features: np.ndarray) -> List[Tuple[str, float]]:
        """Run ML ensemble detection with consensus - OPTIMIZED for real-time."""
        scores = {}
        
        # Execute models in parallel for better real-time performance
        def run_spatial():
            if self.spatial_detector.is_trained():
                return ('spatial', self.spatial_detector.predict(features))
            return ('spatial', 0.0)
        
        def run_temporal():
            self.temporal_detector.add_sample(features)  # Still need to add sample
            if self.temporal_detector.is_trained():
                return ('temporal', self.temporal_detector.predict(features))
            return ('temporal', 0.0)
        
        def run_statistical():
            if self.statistical_detector.is_trained():
                return ('statistical', self.statistical_detector.predict(features))
            return ('statistical', 0.0)
        
        # Submit all model predictions in parallel
        futures = {
            self._executor.submit(run_spatial): 'spatial',
            self._executor.submit(run_temporal): 'temporal', 
            self._executor.submit(run_statistical): 'statistical'
        }
        
        # Collect results as they complete
        for future in as_completed(futures):
            try:
                model_name, score = future.result()
                scores[model_name] = score
            except Exception as e:
                logger.warning(f"Model {futures[future]} prediction failed: {e}")
                scores[futures[future]] = 0.0
        
        # Same consensus logic (unchanged)
        active_scores = [s for s in scores.values() if s > 0]
        
        result = []
        if len(active_scores) >= 2:  # At least 2 models agree
            final_score = np.mean(active_scores)
            
            # Classify based on consensus
            if final_score > CONSENSUS_THRESHOLDS["critical_risk"]:
                result = [("ml_critical_risk", final_score)]
            elif final_score > CONSENSUS_THRESHOLDS["high_risk"]:
                result = [("ml_high_risk", final_score)]
            elif final_score > CONSENSUS_THRESHOLDS["medium_risk"]:
                result = [("ml_medium_risk", final_score)]
            elif final_score > CONSENSUS_THRESHOLDS["low_risk"]:
                result = [("ml_low_risk", final_score)]
        
        return result
    
    def _identify_attacking_ips(self, data: Dict[str, float]) -> List[str]:
        """Identify specific attacking IPs from top_ips data."""
        top_ips = data.get("top_ips", {})
        attacking_ips = []
        
        if isinstance(top_ips, dict):
            for ip, count in top_ips.items():
                if count > IP_SUSPICIOUS_THRESHOLD:
                    attacking_ips.append(ip)
        
        return attacking_ips
    
    def _update_ip_metrics(self, data: Dict[str, float]) -> None:
        """Update IP-specific metrics for Grafana."""
        top_ips = data.get("top_ips", {})
        
        if isinstance(top_ips, dict):
            for ip, count in top_ips.items():
                IP_PACKET_COUNT.labels(source_ip=ip).set(count)
                suspicion_level = min(count / 1000.0, 1.0)
                SUSPICIOUS_IP_ACTIVITY.labels(
                    source_ip=ip, 
                    activity_type="packet_rate"
                ).set(suspicion_level)
    
    def _get_detection_type(self, data: Dict[str, float]) -> str:
        """Determine detection type based on data."""
        if data.get("username_type"):
            return "authentication"
        elif data.get("avg_latency_ms") is not None:
            return "transport_qos"
        else:
            return "network"
    
    def _get_model_scores(self) -> Dict[str, float]:
        """Get current model scores for debugging."""
        return {
            "spatial_trained": 1.0 if self.spatial_detector.is_trained() else 0.0,
            "temporal_trained": 1.0 if self.temporal_detector.is_trained() else 0.0,
            "statistical_trained": 1.0 if self.statistical_detector.is_trained() else 0.0
        }
    
    def _start_background_training(self) -> None:
        """Start background training thread."""
        def training_loop():
            while not self._shutdown_event.wait(TRAINING_CONFIG["interval_seconds"]):
                try:
                    self.train_models()
                except Exception as e:
                    logger.error(f"Background training error: {e}")
            logger.info("Background training stopped")
        
        thread = threading.Thread(target=training_loop, daemon=True)
        thread.start()
    
    def train_models(self) -> None:
        """Train all ML models."""
        if len(self.high_confidence_window) < TRAINING_CONFIG["min_samples_for_training"]:
            return
        
        start_time = time.time()
        
        with self._lock:
            # Prepare training data
            X_conservative = np.array(list(self.high_confidence_window))
            X_all = np.array(list(self.all_data_window)) if len(self.all_data_window) > 50 else X_conservative
            
            # Train each model
            self.spatial_detector.fit(X_all)  # DBSCAN uses all data
            self.temporal_detector.fit(X_conservative)  # VAE uses clean data
            self.statistical_detector.fit(X_all)  # ZMAD uses all history
            
            # Update metrics
            self._update_training_metrics()
        
        duration = time.time() - start_time
        MODEL_RETRAIN_DURATION.labels(model_name="ensemble").observe(duration)
        
        # Save models
        self._save_all_models()
    
    def _load_all_models(self) -> None:
        """Load all saved models."""
        self.spatial_detector.load(self.model_path)
        self.temporal_detector.load(self.model_path)
        self.statistical_detector.load(self.model_path)
    
    def _save_all_models(self) -> None:
        """Save all models."""
        self.spatial_detector.save(self.model_path)
        self.temporal_detector.save(self.model_path)
        self.statistical_detector.save(self.model_path)
    
    def _update_training_metrics(self) -> None:
        """Update Prometheus training metrics."""
        clean_ratio = self.high_confidence_count / max(self.total_samples_count, 1)
        
        TRAINING_DATA_QUALITY.labels(metric_type="clean_data_ratio").set(clean_ratio)
        TRAINING_WINDOW_SIZE.labels(window_type="high_confidence").set(len(self.high_confidence_window))
        TRAINING_WINDOW_SIZE.labels(window_type="all_data").set(len(self.all_data_window))
        
        ADVANCED_MODEL_STATUS.labels(model_name="spatial").set(1.0 if self.spatial_detector.is_trained() else 0.0)
        ADVANCED_MODEL_STATUS.labels(model_name="temporal").set(1.0 if self.temporal_detector.is_trained() else 0.0)
        ADVANCED_MODEL_STATUS.labels(model_name="statistical").set(1.0 if self.statistical_detector.is_trained() else 0.0)
    
    def _update_threat_metrics(self, threat_types: List[str], confidence: float, attacking_ips: List[str]) -> None:
        """Update threat-specific Prometheus metrics."""
        # This would include all the metric updates from the original detector
        # Moving to separate metrics handler for cleanliness
        pass
    
    def shutdown(self) -> None:
        """Gracefully shutdown background training and thread pool."""
        self._shutdown_event.set()
        self._executor.shutdown(wait=False)