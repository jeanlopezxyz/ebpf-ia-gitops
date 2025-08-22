"""
Spatial anomaly detection using DBSCAN clustering.

This module implements density-based spatial clustering for identifying
outliers in network traffic patterns.
"""
import logging
import numpy as np
import joblib
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from typing import Optional

from .base import BaseDetectionModel
from constants import DBSCAN_CONFIG

logger = logging.getLogger(__name__)


class SpatialAnomalyDetector(BaseDetectionModel):
    """DBSCAN-based spatial anomaly detection (Rakuten Symphony approach)."""
    
    def __init__(self):
        self.dbscan = DBSCAN(
            eps=DBSCAN_CONFIG["eps"],
            min_samples=DBSCAN_CONFIG["min_samples"],
            n_jobs=DBSCAN_CONFIG["n_jobs"]
        )
        self.scaler = StandardScaler()
        self._is_trained = False
        self._training_data: Optional[np.ndarray] = None
    
    def fit(self, data: np.ndarray) -> None:
        """Train DBSCAN on provided data."""
        try:
            if len(data) < 50:
                logger.warning("Insufficient data for DBSCAN training")
                return
            
            # Scale features
            self.scaler.fit(data)
            scaled_data = self.scaler.transform(data)
            
            # Fit DBSCAN
            self.dbscan.fit(scaled_data)
            self._training_data = scaled_data
            self._is_trained = True
            
            logger.info(f"DBSCAN trained on {len(data)} samples")
            
        except Exception as e:
            logger.error(f"DBSCAN training error: {e}")
    
    def predict(self, features: np.ndarray) -> float:
        """Predict anomaly score using DBSCAN clustering."""
        if not self._is_trained or self._training_data is None:
            return 0.0
        
        try:
            # Scale input features
            scaled_features = self.scaler.transform(features)
            
            # Combine with training data for clustering
            combined_data = np.vstack([self._training_data[-100:], scaled_features])
            
            # Apply DBSCAN clustering
            clusters = self.dbscan.fit_predict(combined_data)
            
            # Current sample is the last point
            current_cluster = clusters[-1]
            
            if current_cluster == -1:  # Outlier detected
                return 0.9
            
            # Calculate cluster density score
            cluster_size = np.sum(clusters == current_cluster)
            cluster_ratio = cluster_size / len(combined_data)
            
            # Smaller clusters = higher anomaly score
            anomaly_score = max(0.0, 1.0 - cluster_ratio * 2)
            return float(anomaly_score)
            
        except Exception as e:
            logger.warning(f"DBSCAN prediction error: {e}")
            return 0.0
    
    def is_trained(self) -> bool:
        """Check if DBSCAN is trained and ready."""
        return self._is_trained
    
    def save(self, path: str) -> None:
        """Save DBSCAN model and scaler."""
        try:
            joblib.dump({
                'dbscan': self.dbscan,
                'scaler': self.scaler,
                'training_data': self._training_data,
                'is_trained': self._is_trained
            }, f"{path}/spatial_model.pkl")
            logger.info("Spatial model saved successfully")
        except Exception as e:
            logger.error(f"Error saving spatial model: {e}")
    
    def load(self, path: str) -> bool:
        """Load DBSCAN model and scaler."""
        try:
            import os
            if not os.path.exists(f"{path}/spatial_model.pkl"):
                return False
                
            saved_data = joblib.load(f"{path}/spatial_model.pkl")
            self.dbscan = saved_data['dbscan']
            self.scaler = saved_data['scaler']
            self._training_data = saved_data['training_data']
            self._is_trained = saved_data['is_trained']
            
            logger.info("Spatial model loaded successfully")
            return True
            
        except Exception as e:
            logger.warning(f"Could not load spatial model: {e}")
            return False