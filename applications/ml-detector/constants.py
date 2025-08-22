"""
Constants and configuration for ML Detector.

Centralized location for all thresholds, parameters, and configuration
to make the system maintainable and tunable.
"""
from typing import Dict

# ==========================================
# DETECTION THRESHOLDS
# ==========================================

# Network traffic detection thresholds
NETWORK_THRESHOLDS = {
    "port_scan": {
        "unique_ports": 20,
        "packets_per_second": 100
    },
    "ddos": {
        "packets_per_second": 1000,
        "bytes_per_second": 1_000_000
    },
    "data_exfiltration": {
        "bytes_per_second": 5_000_000,
        "tcp_ratio": 0.9
    },
    "syn_flood": {
        "syn_packets": 500,
        "tcp_ratio": 0.95
    }
}

# QoS/Transport layer thresholds (Rakuten-style)
QOS_THRESHOLDS = {
    "latency_anomaly": {
        "max_latency_ms": 100,
        "avg_latency_ms": 50
    },
    "jitter_anomaly": {
        "jitter_ms": 10
    },
    "packet_loss": {
        "packet_loss_rate": 0.05,
        "retransmit_rate": 0.03
    },
    "qos_degradation": {
        "avg_latency_ms": 30,
        "jitter_ms": 5,
        "packet_loss_rate": 0.02
    }
}

# Authentication/Security log thresholds
AUTH_THRESHOLDS = {
    "brute_force_attack": {
        "total_attempts": 100,
        "failed_attempts": 50
    },
    "credential_stuffing": {
        "total_attempts": 500,
        "unique_source_ips": 10
    },
    "service_account_abuse": {
        "total_attempts": 1000,
        "privilege_level": 1
    }
}

# ==========================================
# ML MODEL PARAMETERS
# ==========================================

# DBSCAN parameters
DBSCAN_CONFIG = {
    "eps": 0.5,
    "min_samples": 5,
    "n_jobs": -1
}

# VAE parameters
VAE_CONFIG = {
    "sequence_length": 10,
    "latent_dim": 8,
    "lstm_units": [32, 16],
    "epochs": 10,
    "batch_size": 16
}

# Username classifier parameters
USERNAME_CLASSIFIER_CONFIG = {
    "ngram_range": (2, 4),
    "max_features": 1000,
    "alpha": 0.1
}

# ==========================================
# SYSTEM PARAMETERS
# ==========================================

# Window sizes
WINDOW_SIZES = {
    "high_confidence": 3000,   # Conservative training data
    "all_data": 5000,          # All patterns including edge cases  
    "recent": 300,             # Last 10 minutes
    "time_series": 1000        # For VAE sequence training
}

# Training parameters
TRAINING_CONFIG = {
    "interval_seconds": 30,
    "min_samples_for_training": 100,
    "confidence_threshold_high": 0.8,
    "confidence_threshold_medium": 0.5
}

# Consensus decision thresholds
CONSENSUS_THRESHOLDS = {
    "critical_risk": 0.8,
    "high_risk": 0.7,
    "medium_risk": 0.5,
    "low_risk": 0.3
}

# Suspicious activity threshold for IP tracking
IP_SUSPICIOUS_THRESHOLD = 100  # Packets per window

# ==========================================
# THREAT TYPE MAPPINGS
# ==========================================

USERNAME_TYPE_ENCODING = {
    "username": 0,
    "password": 1, 
    "command": 2,
    "service": 3
}

THREAT_CONFIDENCE_MAPPING = {
    "port_scan": 0.9,
    "ddos": 0.95,
    "data_exfiltration": 0.85,
    "syn_flood": 0.92,
    "brute_force_attack": 0.9,
    "credential_stuffing": 0.85,
    "service_account_abuse": 0.88,
    "username_confusion": 0.85,
    "command_injection": 0.95,
    "latency_anomaly": 0.85,
    "jitter_anomaly": 0.80,
    "packet_loss": 0.88,
    "qos_degradation": 0.90
}