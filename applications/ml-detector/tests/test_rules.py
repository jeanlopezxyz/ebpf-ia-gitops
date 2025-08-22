"""
Tests for rule-based detection engines.

Tests to ensure rule engines correctly identify known threat patterns.
"""
import pytest
from rules.network_rules import NetworkRuleEngine


class TestNetworkRules:
    """Tests for network traffic rule detection."""
    
    def setUp(self):
        self.rule_engine = NetworkRuleEngine()
    
    def test_port_scan_detection(self):
        rule_engine = NetworkRuleEngine()
        
        # Port scan pattern
        data = {
            "unique_ports": 50,        # High port diversity
            "packets_per_second": 1200, # High packet rate
            "tcp_packets": 1100,
            "udp_packets": 100
        }
        
        threats = rule_engine.detect(data)
        threat_types = [t[0] for t in threats]
        
        assert "port_scan" in threat_types
    
    def test_ddos_detection(self):
        rule_engine = NetworkRuleEngine()
        
        # DDoS pattern
        data = {
            "packets_per_second": 15000,  # Very high PPS
            "bytes_per_second": 10000000,  # High bandwidth
            "unique_ips": 100
        }
        
        threats = rule_engine.detect(data)
        threat_types = [t[0] for t in threats]
        
        assert "ddos" in threat_types
    
    def test_qos_degradation_detection(self):
        rule_engine = NetworkRuleEngine()
        
        # QoS degradation pattern
        data = {
            "avg_latency_ms": 75,      # High latency
            "jitter_ms": 15,          # High jitter
            "packet_loss_rate": 0.08   # High packet loss
        }
        
        threats = rule_engine.detect(data)
        threat_types = [t[0] for t in threats]
        
        assert "qos_degradation" in threat_types
    
    def test_authentication_anomaly_detection(self):
        rule_engine = NetworkRuleEngine()
        
        # Service account abuse
        data = {
            "username_type": "service",
            "total_attempts": 5000,    # Very high attempts
            "privilege_level": 1       # Elevated privileges
        }
        
        threats = rule_engine.detect(data)
        threat_types = [t[0] for t in threats]
        
        assert "service_account_abuse" in threat_types
    
    def test_normal_traffic_no_detection(self):
        rule_engine = NetworkRuleEngine()
        
        # Normal traffic pattern
        data = {
            "packets_per_second": 150,
            "bytes_per_second": 75000,
            "unique_ports": 5,
            "tcp_packets": 140,
            "udp_packets": 10
        }
        
        threats = rule_engine.detect(data)
        
        assert len(threats) == 0  # Should not trigger any rules