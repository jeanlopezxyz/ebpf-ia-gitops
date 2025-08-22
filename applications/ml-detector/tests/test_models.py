"""
Tests for ML detection models.

Organized tests for each model component to ensure reliability.
"""
import pytest
import numpy as np

from models.spatial import SpatialAnomalyDetector
from models.temporal import TemporalAnomalyDetector
from models.statistical import StatisticalAnomalyDetector


class TestSpatialDetector:
    """Tests for DBSCAN spatial anomaly detection."""
    
    def test_spatial_detector_training(self):
        detector = SpatialAnomalyDetector()
        
        # Normal traffic data
        normal_data = np.array([
            [100, 50000, 5, 3, 0.8, 20],   # Typical traffic
            [120, 60000, 6, 4, 0.75, 25],
            [80, 40000, 4, 2, 0.85, 15]
        ])
        
        detector.fit(normal_data)
        assert detector.is_trained()
    
    def test_spatial_detector_prediction(self):
        detector = SpatialAnomalyDetector()
        
        # Train on normal data
        normal_data = np.array([[100, 50000, 5, 3, 0.8, 20] for _ in range(60)])
        detector.fit(normal_data)
        
        # Test anomalous data (port scan pattern)
        anomalous_data = np.array([[2000, 100000, 50, 100, 0.95, 1900]])
        score = detector.predict(anomalous_data)
        
        assert score > 0.5  # Should detect as anomaly


class TestTemporalDetector:
    """Tests for VAE temporal anomaly detection."""
    
    def test_temporal_detector_sequence_handling(self):
        detector = TemporalAnomalyDetector()
        
        # Add sequence of normal data
        for i in range(15):
            features = np.array([[100 + i, 50000, 5, 3, 0.8, 20]])
            detector.add_sample(features)
        
        # Should have built sequences
        assert len(detector.time_series_window) > 0


class TestStatisticalDetector:
    """Tests for ZMAD statistical detection."""
    
    def test_statistical_detector_zmad_calculation(self):
        detector = StatisticalAnomalyDetector()
        
        # Create normal distribution
        normal_data = np.array([[100 + np.random.normal(0, 10), 50000, 5, 3, 0.8, 20] 
                               for _ in range(100)])
        detector.fit(normal_data)
        
        # Test clear outlier
        outlier = np.array([[500, 50000, 5, 3, 0.8, 20]])  # 5x normal PPS
        score = detector.predict(outlier)
        
        assert score > 0.7  # Should detect as strong anomaly


def test_model_integration():
    """Test that all models work together."""
    spatial = SpatialAnomalyDetector()
    temporal = TemporalAnomalyDetector()
    statistical = StatisticalAnomalyDetector()
    
    # Generate training data
    training_data = np.array([[100, 50000, 5, 3, 0.8, 20] for _ in range(120)])
    
    # Train all models
    spatial.fit(training_data)
    statistical.fit(training_data)
    
    # All should be trained
    assert spatial.is_trained()
    assert statistical.is_trained()