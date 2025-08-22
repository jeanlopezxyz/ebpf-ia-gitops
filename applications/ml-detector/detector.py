from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.cluster import MiniBatchKMeans, DBSCAN
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sklearn.decomposition import PCA
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import tensorflow as tf
from tensorflow import keras
from scipy import stats
import re

from metrics import (
    ANOMALY_SCORE, MODEL_ACCURACY, THREATS_DETECTED, THREAT_CONFIDENCE,
    PORT_SCAN_DETECTED, DDOS_DETECTED, DATA_EXFILTRATION_DETECTED, 
    ANOMALY_DETECTED, FEATURE_VALUES, THREAT_SEVERITY, MODEL_RETRAIN_COUNT,
    MODEL_RETRAIN_DURATION, IP_PACKET_COUNT, SUSPICIOUS_IP_ACTIVITY,
    TRAINING_DATA_QUALITY, TRAINING_WINDOW_SIZE, DBSCAN_ANOMALY_SCORE,
    VAE_RECONSTRUCTION_ERROR, ADVANCED_MODEL_STATUS, SEQUENTIAL_ANOMALY_DETECTED,
    CLUSTER_ANOMALY_DETECTED
)

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

        # Multi-window strategy for different confidence levels
        self.high_confidence_window: Deque[np.ndarray] = deque(maxlen=3000)  # Conservative training
        self.all_data_window: Deque[np.ndarray] = deque(maxlen=5000)         # All patterns including edge cases
        self.recent_window: Deque[np.ndarray] = deque(maxlen=300)            # Last 10 minutes
        self.is_trained = False
        
        # Statistics for model performance monitoring
        self.high_confidence_count = 0
        self.medium_confidence_count = 0
        self.total_samples_count = 0

        # Thresholds for rule-based checks
        self.thresholds: Dict[str, Dict[str, float]] = {
            # Network traffic thresholds
            "port_scan": {"unique_ports": 20, "packets_per_second": 100},
            "ddos": {"packets_per_second": 1000, "bytes_per_second": 1_000_000},
            "data_exfiltration": {"bytes_per_second": 5_000_000, "tcp_ratio": 0.9},
            "syn_flood": {"syn_packets": 500, "tcp_ratio": 0.95},
            
            # QoS/Transport layer thresholds (Rakuten-style)
            "latency_anomaly": {"max_latency_ms": 100, "avg_latency_ms": 50},
            "jitter_anomaly": {"jitter_ms": 10},
            "packet_loss": {"packet_loss_rate": 0.05, "retransmit_rate": 0.03},
            "qos_degradation": {"avg_latency_ms": 30, "jitter_ms": 5, "packet_loss_rate": 0.02},
            
            # Authentication/Security log thresholds (Rakuten-style)
            "brute_force_attack": {"total_attempts": 100, "failed_attempts": 50},
            "credential_stuffing": {"total_attempts": 500, "unique_source_ips": 10},
            "service_account_abuse": {"total_attempts": 1000, "privilege_level": 1},
            "username_confusion": {"username_type": "password"},  # Password in username field
            "command_injection": {"username_type": "command"},    # Commands in username field
        }

        # OPTIMIZED MODEL ENSEMBLE (3 complementary approaches)
        self.scaler = StandardScaler()
        
        # 1. DENSITY-BASED (Spatial anomalies) - Rakuten level
        self.dbscan = DBSCAN(eps=0.5, min_samples=5, n_jobs=-1)
        
        # 2. DEEP LEARNING (Sequential patterns) - Rakuten level  
        self.vae = None  # Built dynamically for temporal analysis
        self.is_vae_trained = False
        
        # 3. STATISTICAL (Baseline, no training bias) - Rakuten level
        # ZMAD implemented in _detect_with_zmad() method
        
        # 4. USERNAME CLASSIFICATION (Rakuten n-gram approach)
        self.username_classifier = self._build_username_classifier()
        self.username_classifier_trained = False
        
        # REMOVED: MiniBatchKMeans (redundant with DBSCAN)
        # REMOVED: LocalOutlierFactor (redundant with DBSCAN) 
        # REMOVED: OneClassSVM (redundant with DBSCAN)
        # REMOVED: PCA (not needed with only 6 features)
        
        # Time-series data for VAE (sequences)
        self.sequence_length = 10  # 20 seconds of data (10 * 2s intervals)
        self.time_series_window: Deque[np.ndarray] = deque(maxlen=1000)
        self.current_sequence: Deque[np.ndarray] = deque(maxlen=self.sequence_length)

        os.makedirs(self.model_path, exist_ok=True)

        # Try load models; otherwise optionally seed baseline
        self.load_models()
        if self.baseline_enabled and not self.is_trained:
            try:
                self._seed_baseline()
            except Exception as e:  # pragma: no cover
                logger.warning(f"Baseline seeding failed: {e}")

        # Background training thread with shutdown event
        self._shutdown_event = threading.Event()
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

    def extract_features(self, data: Dict[str, float], add_to_training: bool = True) -> np.ndarray:
        """Extract features for both network and authentication data types."""
        
        # Determine data type and extract appropriate features
        if data.get("username_type") or data.get("username_text"):
            # AUTHENTICATION FEATURES (Rakuten-style with n-gram classification)
            
            # If we have raw username text, classify it first
            if data.get("username_text"):
                predicted_type, classification_confidence = self._classify_username_content(data["username_text"])
                username_type = predicted_type
            else:
                username_type = data.get("username_type", "username")
                classification_confidence = 1.0  # Already classified
            
            username_type_encoded = {"username": 0, "password": 1, "command": 2, "service": 3}.get(
                username_type, 0
            )
            
            features = np.array(
                [
                    [
                        username_type_encoded,
                        data.get("total_attempts", 0),
                        data.get("failed_attempts", 0), 
                        data.get("successful_attempts", 0),
                        data.get("unique_source_ips", 0),
                        data.get("privilege_level", 0),
                    ]
                ]
            )
        else:
            # NETWORK FEATURES (original)
            tcp_packets = data.get("tcp_packets", 0)
            udp_packets = data.get("udp_packets", 0)
            total_packets = tcp_packets + udp_packets
            tcp_ratio = tcp_packets / total_packets if total_packets > 0 else 0.5
            
            features = np.array(
                [
                    [
                        data.get("packets_per_second", 0),
                        data.get("bytes_per_second", 0),
                        data.get("unique_ips", 0),
                        data.get("unique_ports", 0),
                        tcp_ratio,
                        data.get("syn_packets", 0),
                    ]
                ]
            )
        
        # Multi-window training strategy (addressing your concern)
        if add_to_training:
            with self._lock:
                self.total_samples_count += 1
                
                # ALWAYS add to recent and all-data windows (no filtering)
                self.recent_window.append(features[0])
                self.all_data_window.append(features[0])
                
                # Calculate confidence for high-confidence window
                confidence = self._get_training_confidence(data)
                
                if confidence > 0.8:  # High confidence = definitely clean
                    self.high_confidence_window.append(features[0])
                    self.high_confidence_count += 1
                elif confidence > 0.5:  # Medium confidence = might be edge case
                    self.medium_confidence_count += 1
                    # Add with probability (avoid complete exclusion)
                    if np.random.random() < confidence:
                        self.high_confidence_window.append(features[0])
                
                # Build sequences for VAE training (from all data)
                if len(self.current_sequence) == self.sequence_length:
                    self.time_series_window.append(np.array(list(self.current_sequence)))
                
        if hasattr(self.scaler, "mean_"):
            with self._lock:
                features = self.scaler.transform(features)
        return features
    
    def _get_training_confidence(self, data: Dict[str, float]) -> float:
        """Calculate confidence that data represents normal traffic (0-1).
        
        Instead of binary clean/dirty, we use confidence scores to avoid
        excluding legitimate edge cases that might appear suspicious.
        """
        confidence_factors = []
        
        pps = data.get("packets_per_second", 0)
        unique_ports = data.get("unique_ports", 0)
        syn_packets = data.get("syn_packets", 0)
        tcp_packets = data.get("tcp_packets", 0)
        
        # Factor 1: Packet rate confidence (sigmoid instead of hard threshold)
        pps_confidence = 1.0 / (1.0 + np.exp((pps - 300) / 50))  # Sigmoid curve
        confidence_factors.append(pps_confidence)
        
        # Factor 2: Port diversity confidence  
        port_confidence = 1.0 / (1.0 + np.exp((unique_ports - 10) / 3))
        confidence_factors.append(port_confidence)
        
        # Factor 3: SYN pattern confidence
        if tcp_packets > 0:
            syn_ratio = syn_packets / tcp_packets
            syn_confidence = 1.0 / (1.0 + np.exp((syn_ratio - 0.5) / 0.1))
            confidence_factors.append(syn_confidence)
        
        # Factor 4: Historical similarity (if we have history)
        if len(self.recent_window) > 10:
            similarity = self._calculate_similarity_to_recent(data)
            confidence_factors.append(similarity)
        
        # Factor 5: Time-based patterns (business hours, etc.)
        time_confidence = self._get_temporal_confidence(data)
        confidence_factors.append(time_confidence)
        
        return float(np.mean(confidence_factors))
    
    def _calculate_similarity_to_recent(self, data: Dict[str, float]) -> float:
        """Calculate how similar current data is to recent normal patterns."""
        try:
            recent_data = list(self.recent_window)[-50:]  # Last 50 samples
            if len(recent_data) < 10:
                return 0.5  # Neutral if insufficient history
                
            current_features = np.array([
                data.get("packets_per_second", 0),
                data.get("bytes_per_second", 0),
                data.get("unique_ips", 0),
                data.get("unique_ports", 0)
            ])
            
            # Calculate average feature values from recent history
            recent_avg = np.mean(recent_data, axis=0)[:4]  # First 4 features
            
            # Euclidean distance normalized to 0-1
            distance = np.linalg.norm(current_features - recent_avg)
            max_expected_distance = np.std(recent_data, axis=0)[:4].sum()
            
            # Higher similarity = higher confidence
            similarity = max(0.0, 1.0 - distance / max(max_expected_distance, 1.0))
            return similarity
            
        except Exception:
            return 0.5  # Neutral on error
    
    def _get_temporal_confidence(self, data: Dict[str, float]) -> float:
        """Get confidence based on temporal patterns."""
        # Simple heuristic: higher confidence during business hours
        import datetime
        current_hour = datetime.datetime.now().hour
        
        if 8 <= current_hour <= 18:  # Business hours
            return 0.8
        elif 6 <= current_hour <= 22:  # Extended hours  
            return 0.6
        else:  # Night hours - more suspicious
            return 0.3
    
    def _build_username_classifier(self) -> Pipeline:
        """Build character n-gram classifier for username content (Rakuten approach)."""
        # Character n-gram vectorizer (like Rakuten)
        vectorizer = CountVectorizer(
            analyzer='char',        # Character-level analysis
            ngram_range=(2, 4),     # 2-4 character n-grams
            max_features=1000,      # Limit feature space
            lowercase=True
        )
        
        # Multinomial Naive Bayes classifier
        classifier = MultinomialNB(alpha=0.1)
        
        # Pipeline combining vectorizer + classifier
        return Pipeline([
            ('vectorizer', vectorizer),
            ('classifier', classifier)
        ])
    
    def _train_username_classifier(self):
        """Train username classifier on synthetic data (like Rakuten)."""
        try:
            # Generate training data with patterns
            training_data = []
            training_labels = []
            
            # Username patterns
            usernames = ["john.doe", "alice.smith", "user123", "admin", "testuser"]
            for username in usernames * 20:
                training_data.append(username)
                training_labels.append("username")
            
            # Password patterns (common characteristics)
            passwords = ["password123", "mypassword", "123456789", "qwerty123", "admin123"]
            for pwd in passwords * 20:
                training_data.append(pwd)
                training_labels.append("password")
            
            # Command patterns
            commands = ["ls -la", "sudo rm", "cat /etc/passwd", "wget http://", "curl -X"]
            for cmd in commands * 20:
                training_data.append(cmd)
                training_labels.append("command")
            
            # Service account patterns
            services = ["svc_backup", "service_account", "app_service", "db_service"]
            for svc in services * 20:
                training_data.append(svc)
                training_labels.append("service")
            
            # Train the classifier
            self.username_classifier.fit(training_data, training_labels)
            self.username_classifier_trained = True
            logger.info("Username classifier trained with n-gram features")
            
        except Exception as e:
            logger.warning(f"Username classifier training failed: {e}")
    
    def _classify_username_content(self, username_text: str) -> Tuple[str, float]:
        """Classify username content using n-gram analysis."""
        if not self.username_classifier_trained:
            self._train_username_classifier()
        
        if not self.username_classifier_trained:
            return "unknown", 0.5
            
        try:
            # Predict type
            predicted_type = self.username_classifier.predict([username_text])[0]
            
            # Get confidence probabilities
            probabilities = self.username_classifier.predict_proba([username_text])[0]
            confidence = max(probabilities)
            
            return predicted_type, float(confidence)
            
        except Exception as e:
            logger.warning(f"Username classification error: {e}")
            return "unknown", 0.5
    
    def _build_vae(self, input_dim: int) -> keras.Model:
        """Build Variational Autoencoder for sequential anomaly detection."""
        # Encoder
        encoder_inputs = keras.Input(shape=(self.sequence_length, input_dim))
        x = keras.layers.LSTM(32, return_sequences=True)(encoder_inputs)
        x = keras.layers.LSTM(16, return_sequences=False)(x)
        z_mean = keras.layers.Dense(8)(x)
        z_log_var = keras.layers.Dense(8)(x)
        
        # Sampling layer
        def sampling(args):
            z_mean, z_log_var = args
            batch = tf.shape(z_mean)[0]
            dim = tf.shape(z_mean)[1]
            epsilon = tf.random.normal(shape=(batch, dim))
            return z_mean + tf.exp(0.5 * z_log_var) * epsilon
        
        z = keras.layers.Lambda(sampling, output_shape=(8,))([z_mean, z_log_var])
        
        # Decoder
        decoder_input = keras.layers.RepeatVector(self.sequence_length)(z)
        x = keras.layers.LSTM(16, return_sequences=True)(decoder_input)
        x = keras.layers.LSTM(32, return_sequences=True)(x)
        decoder_outputs = keras.layers.TimeDistributed(
            keras.layers.Dense(input_dim, activation='linear')
        )(x)
        
        # VAE model
        vae = keras.Model(encoder_inputs, decoder_outputs, name='vae')
        
        # VAE loss
        reconstruction_loss = keras.losses.mse(encoder_inputs, decoder_outputs)
        reconstruction_loss *= input_dim * self.sequence_length
        
        kl_loss = 1 + z_log_var - tf.square(z_mean) - tf.exp(z_log_var)
        kl_loss = tf.reduce_mean(kl_loss, axis=-1)
        kl_loss *= -0.5
        
        vae_loss = tf.reduce_mean(reconstruction_loss + kl_loss)
        vae.add_loss(vae_loss)
        vae.compile(optimizer='adam')
        
        return vae

    def detect_rule_based(self, data: Dict[str, float]) -> List[Tuple[str, float]]:
        threats: List[Tuple[str, float]] = []
        
        # Determine detection type
        detection_type = "authentication" if data.get("username_type") else "network"
        
        if detection_type == "network":
            # NETWORK TRAFFIC RULES
            tcp_packets = data.get("tcp_packets", 0)
            udp_packets = data.get("udp_packets", 0)
            total_packets = tcp_packets + udp_packets
            tcp_ratio = tcp_packets / total_packets if total_packets > 0 else 0
            
            if data.get("unique_ports", 0) > self.thresholds["port_scan"]["unique_ports"]:
                if data.get("packets_per_second", 0) > self.thresholds["port_scan"]["packets_per_second"]:
                    threats.append(("port_scan", 0.9))
            if data.get("packets_per_second", 0) > self.thresholds["ddos"]["packets_per_second"]:
                if data.get("bytes_per_second", 0) > self.thresholds["ddos"]["bytes_per_second"]:
                    threats.append(("ddos", 0.95))
            if data.get("bytes_per_second", 0) > self.thresholds["data_exfiltration"]["bytes_per_second"]:
                if tcp_ratio > self.thresholds["data_exfiltration"]["tcp_ratio"]:
                    threats.append(("data_exfiltration", 0.85))
            if data.get("syn_packets", 0) > self.thresholds["syn_flood"]["syn_packets"]:
                if tcp_ratio > self.thresholds["syn_flood"]["tcp_ratio"]:
                    threats.append(("syn_flood", 0.92))
            
            # QoS/Transport anomaly detection (Rakuten use cases)
            if data.get("max_latency_ms", 0) > self.thresholds["latency_anomaly"]["max_latency_ms"]:
                if data.get("avg_latency_ms", 0) > self.thresholds["latency_anomaly"]["avg_latency_ms"]:
                    threats.append(("latency_anomaly", 0.85))
            
            if data.get("jitter_ms", 0) > self.thresholds["jitter_anomaly"]["jitter_ms"]:
                threats.append(("jitter_anomaly", 0.80))
            
            if data.get("packet_loss_rate", 0) > self.thresholds["packet_loss"]["packet_loss_rate"]:
                threats.append(("packet_loss", 0.88))
            
            # Combined QoS degradation (multiple factors)
            qos_factors = 0
            if data.get("avg_latency_ms", 0) > self.thresholds["qos_degradation"]["avg_latency_ms"]:
                qos_factors += 1
            if data.get("jitter_ms", 0) > self.thresholds["qos_degradation"]["jitter_ms"]:
                qos_factors += 1  
            if data.get("packet_loss_rate", 0) > self.thresholds["qos_degradation"]["packet_loss_rate"]:
                qos_factors += 1
            
            if qos_factors >= 2:  # Multiple QoS issues = degradation
                threats.append(("qos_degradation", 0.90))
                    
        else:
            # AUTHENTICATION LOG RULES (Rakuten-style patterns)
            username_type = data.get("username_type", "")
            total_attempts = data.get("total_attempts", 0)
            failed_attempts = data.get("failed_attempts", 0)
            unique_ips = data.get("unique_source_ips", 0)
            privilege = data.get("privilege_level", 0)
            
            # Rule 1: Username confusion (like Rakuten detected)
            if username_type in ["password", "command"]:
                confidence = 0.95 if username_type == "command" else 0.85
                threats.append(("username_confusion", confidence))
            
            # Rule 2: Brute force (like 136963 attempts case)
            if total_attempts > self.thresholds["brute_force_attack"]["total_attempts"]:
                if failed_attempts > self.thresholds["brute_force_attack"]["failed_attempts"]:
                    threats.append(("brute_force_attack", 0.9))
            
            # Rule 3: Credential stuffing (multiple IPs)
            if total_attempts > self.thresholds["credential_stuffing"]["total_attempts"]:
                if unique_ips > self.thresholds["credential_stuffing"]["unique_source_ips"]:
                    threats.append(("credential_stuffing", 0.85))
            
            # Rule 4: Service account abuse (elevated privileges + high attempts)
            if privilege == 1 and total_attempts > self.thresholds["service_account_abuse"]["total_attempts"]:
                threats.append(("service_account_abuse", 0.88))
                
        return threats

    def detect_ml_based(self, features: np.ndarray) -> List[Tuple[str, float]]:
        """Optimized 3-model ensemble: DBSCAN + VAE + ZMAD."""
        if not self.is_trained:
            return []
        
        try:
            # THREE COMPLEMENTARY APPROACHES (no overlap):
            
            # 1. SPATIAL: DBSCAN clustering (density-based outliers)
            dbscan_score = self._detect_with_dbscan(features)
            DBSCAN_ANOMALY_SCORE.set(dbscan_score)
            
            # 2. TEMPORAL: VAE sequential analysis (time-based patterns)  
            vae_score = self._detect_with_vae(features)
            
            # 3. STATISTICAL: ZMAD baseline (robust, no training bias)
            zmad_score = self._detect_with_zmad(features)
            
            # CONSENSUS DECISION (weighted by model strengths):
            scores = {
                'spatial': dbscan_score,     # Weight: 0.4 (strong for clustering)
                'temporal': vae_score,       # Weight: 0.3 (good for sequences) 
                'statistical': zmad_score    # Weight: 0.3 (robust baseline)
            }
            
            # Remove zero scores for consensus
            active_scores = [s for s in scores.values() if s > 0]
            
            if len(active_scores) >= 2:  # At least 2 models agree
                final_score = np.mean(active_scores)
                ANOMALY_SCORE.set(final_score)
                
                # Consensus-based classification
                if final_score > 0.8:
                    return [("ml_critical_risk", final_score)]
                if final_score > 0.7:
                    return [("ml_high_risk", final_score)]
                if final_score > 0.5:
                    return [("ml_medium_risk", final_score)]
                if final_score > 0.3:
                    return [("ml_low_risk", final_score)]
            
        except Exception as e:  # pragma: no cover
            logger.warning(f"Optimized ML detection error: {e}")
            
        return []
    
    def _detect_with_dbscan(self, features: np.ndarray) -> float:
        """DBSCAN-based anomaly detection (Rakuten Symphony approach)."""
        try:
            if len(self.training_window) < 50:
                return 0.0
                
            # Get recent training data for DBSCAN clustering
            recent_data = list(self.training_window)[-100:]  # Last 100 clean samples
            X = np.array(recent_data + features.tolist())
            
            # Apply DBSCAN clustering
            clusters = self.dbscan.fit_predict(X)
            
            # Check if current sample is an outlier (cluster = -1)
            current_cluster = clusters[-1]  # Last point is our current sample
            
            if current_cluster == -1:  # Outlier detected
                return 0.9  # High anomaly score
            
            # Calculate cluster density-based score
            cluster_size = np.sum(clusters == current_cluster)
            cluster_ratio = cluster_size / len(X)
            
            # Smaller clusters = higher anomaly score
            dbscan_score = max(0.0, 1.0 - cluster_ratio * 2)
            DBSCAN_ANOMALY_SCORE.set(dbscan_score)
            return dbscan_score
            
        except Exception as e:
            logger.warning(f"DBSCAN detection error: {e}")
            return 0.0
    
    def _detect_with_vae(self, features: np.ndarray) -> float:
        """VAE-based sequential anomaly detection (Rakuten Symphony approach)."""
        try:
            # Add current features to sequence
            self.current_sequence.append(features[0])
            
            # Need full sequence for VAE detection
            if len(self.current_sequence) < self.sequence_length:
                return 0.0
                
            # Build VAE if not exists
            if self.vae is None and len(self.time_series_window) >= 100:
                input_dim = len(features[0])
                self.vae = self._build_vae(input_dim)
                logger.info("VAE model built for sequential anomaly detection")
            
            # Train VAE if enough sequences
            if self.vae is not None and not self.is_vae_trained and len(self.time_series_window) >= 50:
                self._train_vae()
                
            # Perform VAE-based detection
            if self.vae is not None and self.is_vae_trained:
                sequence = np.array([list(self.current_sequence)])  # Shape: (1, seq_len, features)
                
                # Get reconstruction
                reconstruction = self.vae.predict(sequence, verbose=0)
                
                # Calculate reconstruction error
                mse = np.mean(np.square(sequence - reconstruction))
                
                # Normalize to 0-1 range (higher MSE = higher anomaly score)
                anomaly_score = min(mse / 0.1, 1.0)  # 0.1 is threshold for normalization
                
                # Update VAE metrics
                VAE_RECONSTRUCTION_ERROR.set(float(mse))
                
                return float(anomaly_score)
                
        except Exception as e:
            logger.warning(f"VAE detection error: {e}")
            
        return 0.0
    
    def _train_vae(self):
        """Train VAE on clean sequential data."""
        try:
            if len(self.time_series_window) < 50:
                return
                
            # Prepare training sequences
            sequences = list(self.time_series_window)[-200:]  # Last 200 sequences
            X_train = np.array(sequences)
            
            # Train VAE
            self.vae.fit(X_train, X_train, epochs=10, batch_size=16, verbose=0)
            self.is_vae_trained = True
            logger.info("VAE trained on sequential data")
            
        except Exception as e:
            logger.warning(f"VAE training error: {e}")
    
    def _detect_with_zmad(self, features: np.ndarray) -> float:
        """Statistical anomaly detection using Modified Z-Score (Rakuten approach)."""
        try:
            if len(self.training_window) < 30:
                return 0.0
                
            # Get historical data for statistical analysis
            historical_data = np.array(list(self.training_window))
            current_features = features[0]
            
            anomaly_scores = []
            
            # Apply ZMAD to each feature dimension
            for i in range(len(current_features)):
                feature_history = historical_data[:, i]
                median_val = np.median(feature_history)
                mad = np.median(np.abs(feature_history - median_val))
                
                if mad == 0:  # Avoid division by zero
                    mad = 0.001
                    
                # Calculate Modified Z-Score (ZMAD) 
                zmad = 0.6745 * (current_features[i] - median_val) / mad
                
                # Convert to anomaly score (higher = more anomalous)
                feature_anomaly_score = min(abs(zmad) / 3.5, 1.0)  # 3.5 is typical threshold
                anomaly_scores.append(feature_anomaly_score)
            
            # Return average ZMAD-based anomaly score
            return float(np.mean(anomaly_scores))
            
        except Exception as e:
            logger.warning(f"ZMAD detection error: {e}")
            return 0.0

    def detect(self, data: Dict[str, float]) -> Dict[str, object]:
        features = self.extract_features(data)
        rule_threats = self.detect_rule_based(data)
        ml_threats = self.detect_ml_based(features)
        all_threats = rule_threats + ml_threats
        
        # Process top attacking IPs
        top_ips = data.get("top_ips", {})
        attacking_ips = []
        if isinstance(top_ips, dict):
            # Find IPs with high packet rates (potential attackers)
            for ip, count in top_ips.items():
                if count > 100:  # Threshold for suspicious activity
                    attacking_ips.append(ip)
        
        # Update feature metrics (use original data dict, not numpy features array)
        FEATURE_VALUES.labels(feature_name="packets_per_second").set(data.get("packets_per_second", 0))
        FEATURE_VALUES.labels(feature_name="bytes_per_second").set(data.get("bytes_per_second", 0))
        FEATURE_VALUES.labels(feature_name="unique_ips").set(data.get("unique_ips", 0))
        FEATURE_VALUES.labels(feature_name="unique_ports").set(data.get("unique_ports", 0))
        
        # Update IP-specific metrics for Grafana visualization
        if isinstance(top_ips, dict):
            for ip, count in top_ips.items():
                IP_PACKET_COUNT.labels(source_ip=ip).set(count)
                # Calculate suspicious activity level (0-1)
                suspicion_level = min(count / 1000.0, 1.0)  # Normalize to 0-1
                SUSPICIOUS_IP_ACTIVITY.labels(source_ip=ip, activity_type="packet_rate").set(suspicion_level)
        
        if all_threats:
            max_conf = max(t[1] for t in all_threats)
            threat_types = [t[0] for t in all_threats]
            
            # Record threat detection metrics per attacking IP
            confidence_level = "high" if max_conf > 0.7 else "medium" if max_conf > 0.4 else "low"
            
            # If we have attacking IPs, create metrics for each one
            source_ips_to_record = attacking_ips if attacking_ips else ["aggregated"]
            
            for source_ip in source_ips_to_record:
                for threat_type in threat_types:
                    # General threat counter per IP
                    THREATS_DETECTED.labels(
                        threat_type=threat_type, 
                        confidence_level=confidence_level,
                        source_ip=source_ip
                    ).inc()
                
                # Confidence histogram
                THREAT_CONFIDENCE.labels(threat_type=threat_type).observe(max_conf)
                
                # Specific threat type counters with source IP
                if threat_type == "port_scan":
                    severity = "high" if max_conf > 0.8 else "medium" if max_conf > 0.5 else "low"
                    PORT_SCAN_DETECTED.labels(severity=severity, source_ip=source_ip).inc()
                elif threat_type in ["ddos", "high_traffic"]:
                    attack_type = "volumetric" if data.get("bytes_per_second", 0) > data.get("packets_per_second", 0) * 1000 else "packet_flood"
                    DDOS_DETECTED.labels(attack_type=attack_type, source_ip=source_ip).inc()
                elif threat_type == "data_exfiltration":
                    direction = "outbound" if data.get("direction") == "out" else "inbound"
                    DATA_EXFILTRATION_DETECTED.labels(direction=direction, source_ip=source_ip).inc()
                elif threat_type.startswith("ml_"):
                    model_type = "ensemble" if len(ml_threats) > 1 else "single"
                    severity = "critical" if max_conf > 0.9 else "high" if max_conf > 0.7 else "medium"
                    ANOMALY_DETECTED.labels(model_type=model_type, severity=severity, source_ip=source_ip).inc()
            
            # Update threat severity gauge
            for threat_type in threat_types:
                THREAT_SEVERITY.labels(threat_category=threat_type).set(max_conf)
            
            logger.warning(f"🚨 THREAT DETECTED: {threat_types} (confidence: {max_conf:.2f})")
            
            return {
                "threat_detected": True,
                "confidence": float(max_conf),
                "threat_types": threat_types,
                "attacking_ips": attacking_ips,
                "top_ips": top_ips,
                "scores": {"rule_based": len(rule_threats) > 0, "ml_based": len(ml_threats) > 0},
            }
        return {
            "threat_detected": False, 
            "confidence": 0.0, 
            "threat_types": [], 
            "attacking_ips": [],
            "top_ips": top_ips,
            "scores": {}
        }

    def _background_training(self) -> None:  # pragma: no cover
        while not self._shutdown_event.wait(self.training_interval):
            try:
                self.train_models()
            except Exception as e:
                logger.error(f"Background training error: {e}")
        logger.info("Background training thread shutting down")
    
    def shutdown(self) -> None:
        """Gracefully shutdown background training."""
        self._shutdown_event.set()

    def train_models(self) -> None:
        """Optimized training for 3-model ensemble."""
        start_time = time.time()
        
        with self._lock:
            # Need sufficient data for reliable training
            if len(self.high_confidence_window) < 100:
                return
                
            # Prepare training data from high-confidence window
            X_conservative = np.array(list(self.high_confidence_window))
            X_all = np.array(list(self.all_data_window)) if len(self.all_data_window) > 50 else X_conservative
            
            trigger_reason = "initial" if not hasattr(self.scaler, "mean_") else "incremental"
            
            # 1. Scale features (needed for DBSCAN)
            if not hasattr(self.scaler, "mean_"):
                self.scaler.fit(X_conservative)
                MODEL_RETRAIN_COUNT.labels(model_name="scaler", trigger_reason=trigger_reason).inc()
            else:
                self.scaler.partial_fit(X_conservative)
                MODEL_RETRAIN_COUNT.labels(model_name="scaler", trigger_reason=trigger_reason).inc()
                
            # 2. Train DBSCAN on all data (handles outliers naturally)
            Xs_all = self.scaler.transform(X_all)
            self.dbscan.fit(Xs_all)  # DBSCAN trained on all patterns
            MODEL_RETRAIN_COUNT.labels(model_name="dbscan", trigger_reason=trigger_reason).inc()
            
            # 3. VAE trains separately in _train_vae() when sequences are ready
            # 4. ZMAD is statistical - no training needed
            
            self.is_trained = True
            MODEL_ACCURACY.labels(model_name="optimized_ensemble").set(0.0)  # placeholder
            
        # Record training duration and quality metrics
        duration = time.time() - start_time
        MODEL_RETRAIN_DURATION.labels(model_name="ensemble").observe(duration)
        
        # Update training quality metrics
        clean_ratio = self.clean_samples_count / max(self.total_samples_count, 1)
        TRAINING_DATA_QUALITY.labels(metric_type="clean_data_ratio").set(clean_ratio)
        TRAINING_DATA_QUALITY.labels(metric_type="total_samples").set(self.total_samples_count)
        TRAINING_WINDOW_SIZE.labels(window_type="training").set(len(self.training_window))
        TRAINING_WINDOW_SIZE.labels(window_type="recent").set(len(self.recent_window))
        TRAINING_WINDOW_SIZE.labels(window_type="timeseries").set(len(self.time_series_window))
        
        # Update advanced model status
        ADVANCED_MODEL_STATUS.labels(model_name="dbscan").set(1.0)
        ADVANCED_MODEL_STATUS.labels(model_name="vae").set(1.0 if self.is_vae_trained else 0.0)
        
        self.save_models()

    def save_models(self) -> None:
        """Save optimized 3-model ensemble."""
        try:
            with self._lock:
                joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
                joblib.dump(self.dbscan, f"{self.model_path}/dbscan.pkl")
                if self.vae is not None:
                    self.vae.save(f"{self.model_path}/vae_model")
            logger.info("Optimized ensemble models saved successfully")
        except Exception as e:  # pragma: no cover
            logger.error(f"Error saving optimized models: {e}")

    def load_models(self) -> None:
        """Load optimized 3-model ensemble."""
        try:
            with self._lock:
                if os.path.exists(f"{self.model_path}/scaler.pkl"):
                    self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
                    self.dbscan = joblib.load(f"{self.model_path}/dbscan.pkl")
                    if os.path.exists(f"{self.model_path}/vae_model"):
                        self.vae = keras.models.load_model(f"{self.model_path}/vae_model")
                        self.is_vae_trained = True
                    self.is_trained = True
                    logger.info("Optimized ensemble models loaded successfully")
        except Exception as e:  # pragma: no cover
            logger.warning(f"Could not load optimized models: {e}")
