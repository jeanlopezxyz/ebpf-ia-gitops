"""
Statistical anomaly detection using Modified Z-Score (ZMAD).

This module implements robust statistical outlier detection based on
median absolute deviation, as used by Rakuten Symphony.
"""
import logging
import numpy as np
from collections import deque
from typing import Deque

from .base import BaseDetectionModel
from constants import WINDOW_SIZES

logger = logging.getLogger(__name__)


class StatisticalAnomalyDetector(BaseDetectionModel):
    """ZMAD-based statistical anomaly detection (Rakuten Symphony approach)."""
    
    def __init__(self):
        self.historical_data: Deque[np.ndarray] = deque(maxlen=WINDOW_SIZES["all_data"])
        self._is_trained = False
    
    def fit(self, data: np.ndarray) -> None:
        """Add data to historical window (no actual training needed)."""
        try:
            for sample in data:
                self.historical_data.append(sample)
            
            # Mark as trained when we have sufficient history
            if len(self.historical_data) >= 30:
                self._is_trained = True
                logger.info(f"Statistical detector ready with {len(self.historical_data)} samples")
                
        except Exception as e:
            logger.error(f"Statistical model update error: {e}")
    
    def predict(self, features: np.ndarray) -> float:
        """Predict anomaly score using Modified Z-Score (ZMAD)."""
        if not self._is_trained:
            return 0.0
        
        try:
            current_features = features[0]
            historical_array = np.array(list(self.historical_data))
            anomaly_scores = []
            
            # Apply ZMAD to each feature dimension
            for i in range(len(current_features)):
                feature_history = historical_array[:, i]
                median_val = np.median(feature_history)
                mad = np.median(np.abs(feature_history - median_val))
                
                # Avoid division by zero
                if mad == 0:
                    mad = 0.001
                
                # Calculate Modified Z-Score (ZMAD)
                zmad = 0.6745 * (current_features[i] - median_val) / mad
                
                # Convert to anomaly score (0-1)
                feature_anomaly_score = min(abs(zmad) / 3.5, 1.0)
                anomaly_scores.append(feature_anomaly_score)
            
            # Return average ZMAD-based anomaly score
            return float(np.mean(anomaly_scores))
            
        except Exception as e:
            logger.warning(f"ZMAD prediction error: {e}")
            return 0.0
    
    def is_trained(self) -> bool:
        """Check if statistical detector has sufficient history."""
        return self._is_trained
    
    def save(self, path: str) -> None:
        """Save historical data (statistical model doesn't need training artifacts)."""
        try:
            import joblib
            joblib.dump({
                'historical_data': list(self.historical_data),
                'is_trained': self._is_trained
            }, f"{path}/statistical_model.pkl")
            logger.info("Statistical model data saved successfully")
        except Exception as e:
            logger.error(f"Error saving statistical model: {e}")
    
    def load(self, path: str) -> bool:
        """Load historical data."""
        try:
            import os
            import joblib
            
            if not os.path.exists(f"{path}/statistical_model.pkl"):
                return False
                
            saved_data = joblib.load(f"{path}/statistical_model.pkl")
            
            # Restore historical data
            self.historical_data = deque(saved_data['historical_data'], 
                                       maxlen=WINDOW_SIZES["all_data"])
            self._is_trained = saved_data['is_trained']
            
            logger.info("Statistical model data loaded successfully")
            return True
            
        except Exception as e:
            logger.warning(f"Could not load statistical model: {e}")
            return False