"""
Base interfaces and abstract classes for ML models.

This module defines the contracts that all detection models must follow,
making the system extensible and maintainable.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple
import numpy as np


class BaseDetectionModel(ABC):
    """Base interface for all detection models."""
    
    @abstractmethod
    def fit(self, data: np.ndarray) -> None:
        """Train the model on provided data."""
        pass
    
    @abstractmethod
    def predict(self, features: np.ndarray) -> float:
        """Predict anomaly score (0-1) for given features."""
        pass
    
    @abstractmethod
    def is_trained(self) -> bool:
        """Check if model is trained and ready."""
        pass
    
    @abstractmethod
    def save(self, path: str) -> None:
        """Save model to disk."""
        pass
    
    @abstractmethod
    def load(self, path: str) -> bool:
        """Load model from disk. Returns True if successful."""
        pass


class BaseRuleEngine(ABC):
    """Base interface for rule-based detection."""
    
    @abstractmethod
    def detect(self, data: Dict[str, float]) -> List[Tuple[str, float]]:
        """Apply rules and return list of (threat_type, confidence) tuples."""
        pass
    
    @abstractmethod
    def get_supported_data_types(self) -> List[str]:
        """Return list of supported data types: ['network', 'authentication', 'qos']."""
        pass


class BaseFeatureExtractor(ABC):
    """Base interface for feature extraction."""
    
    @abstractmethod
    def extract(self, data: Dict[str, float]) -> np.ndarray:
        """Extract features from raw data."""
        pass
    
    @abstractmethod
    def get_feature_names(self) -> List[str]:
        """Return list of feature names in order."""
        pass


class DetectionResult:
    """Standardized detection result."""
    
    def __init__(
        self,
        threat_detected: bool,
        confidence: float,
        threat_types: List[str],
        attacking_ips: List[str] = None,
        detection_type: str = "network",
        model_scores: Dict[str, float] = None
    ):
        self.threat_detected = threat_detected
        self.confidence = confidence
        self.threat_types = threat_types
        self.attacking_ips = attacking_ips or []
        self.detection_type = detection_type
        self.model_scores = model_scores or {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "threat_detected": self.threat_detected,
            "confidence": self.confidence,
            "threat_types": self.threat_types,
            "attacking_ips": self.attacking_ips,
            "detection_type": self.detection_type,
            "model_scores": self.model_scores
        }