"""
Network traffic rule-based detection.

This module contains all rule-based detection logic for network traffic
patterns like port scans, DDoS, data exfiltration, etc.
"""
import logging
from typing import Dict, List, Tuple

from models.base import BaseRuleEngine
from constants import NETWORK_THRESHOLDS, QOS_THRESHOLDS, THREAT_CONFIDENCE_MAPPING

logger = logging.getLogger(__name__)


class NetworkRuleEngine(BaseRuleEngine):
    """Rule-based detection for network traffic anomalies."""
    
    def detect(self, data: Dict[str, float]) -> List[Tuple[str, float]]:
        """Apply network traffic rules and return detected threats."""
        threats: List[Tuple[str, float]] = []
        
        # Calculate derived metrics
        tcp_packets = data.get("tcp_packets", 0)
        udp_packets = data.get("udp_packets", 0)
        total_packets = tcp_packets + udp_packets
        tcp_ratio = tcp_packets / total_packets if total_packets > 0 else 0
        
        # Network attack detection
        threats.extend(self._detect_port_scan(data))
        threats.extend(self._detect_ddos(data))
        threats.extend(self._detect_data_exfiltration(data, tcp_ratio))
        threats.extend(self._detect_syn_flood(data, tcp_ratio))
        
        # QoS/Transport layer detection
        threats.extend(self._detect_qos_anomalies(data))
        
        return threats
    
    def get_supported_data_types(self) -> List[str]:
        """Return supported data types."""
        return ["network", "qos", "transport"]
    
    def _detect_port_scan(self, data: Dict[str, float]) -> List[Tuple[str, float]]:
        """Detect port scanning attempts."""
        unique_ports = data.get("unique_ports", 0)
        pps = data.get("packets_per_second", 0)
        
        if (unique_ports > NETWORK_THRESHOLDS["port_scan"]["unique_ports"] and
            pps > NETWORK_THRESHOLDS["port_scan"]["packets_per_second"]):
            return [("port_scan", THREAT_CONFIDENCE_MAPPING["port_scan"])]
        return []
    
    def _detect_ddos(self, data: Dict[str, float]) -> List[Tuple[str, float]]:
        """Detect DDoS attacks."""
        pps = data.get("packets_per_second", 0)
        bps = data.get("bytes_per_second", 0)
        
        if (pps > NETWORK_THRESHOLDS["ddos"]["packets_per_second"] and
            bps > NETWORK_THRESHOLDS["ddos"]["bytes_per_second"]):
            return [("ddos", THREAT_CONFIDENCE_MAPPING["ddos"])]
        return []
    
    def _detect_data_exfiltration(self, data: Dict[str, float], tcp_ratio: float) -> List[Tuple[str, float]]:
        """Detect data exfiltration attempts."""
        bps = data.get("bytes_per_second", 0)
        
        if (bps > NETWORK_THRESHOLDS["data_exfiltration"]["bytes_per_second"] and
            tcp_ratio > NETWORK_THRESHOLDS["data_exfiltration"]["tcp_ratio"]):
            return [("data_exfiltration", THREAT_CONFIDENCE_MAPPING["data_exfiltration"])]
        return []
    
    def _detect_syn_flood(self, data: Dict[str, float], tcp_ratio: float) -> List[Tuple[str, float]]:
        """Detect SYN flood attacks."""
        syn_packets = data.get("syn_packets", 0)
        
        if (syn_packets > NETWORK_THRESHOLDS["syn_flood"]["syn_packets"] and
            tcp_ratio > NETWORK_THRESHOLDS["syn_flood"]["tcp_ratio"]):
            return [("syn_flood", THREAT_CONFIDENCE_MAPPING["syn_flood"])]
        return []
    
    def _detect_qos_anomalies(self, data: Dict[str, float]) -> List[Tuple[str, float]]:
        """Detect QoS and transport layer anomalies."""
        threats = []
        
        # Latency anomalies
        max_latency = data.get("max_latency_ms", 0)
        avg_latency = data.get("avg_latency_ms", 0)
        if (max_latency > QOS_THRESHOLDS["latency_anomaly"]["max_latency_ms"] and
            avg_latency > QOS_THRESHOLDS["latency_anomaly"]["avg_latency_ms"]):
            threats.append(("latency_anomaly", THREAT_CONFIDENCE_MAPPING["latency_anomaly"]))
        
        # Jitter anomalies
        jitter = data.get("jitter_ms", 0)
        if jitter > QOS_THRESHOLDS["jitter_anomaly"]["jitter_ms"]:
            threats.append(("jitter_anomaly", THREAT_CONFIDENCE_MAPPING["jitter_anomaly"]))
        
        # Packet loss
        packet_loss = data.get("packet_loss_rate", 0)
        if packet_loss > QOS_THRESHOLDS["packet_loss"]["packet_loss_rate"]:
            threats.append(("packet_loss", THREAT_CONFIDENCE_MAPPING["packet_loss"]))
        
        # Combined QoS degradation
        qos_factors = 0
        if avg_latency > QOS_THRESHOLDS["qos_degradation"]["avg_latency_ms"]:
            qos_factors += 1
        if jitter > QOS_THRESHOLDS["qos_degradation"]["jitter_ms"]:
            qos_factors += 1
        if packet_loss > QOS_THRESHOLDS["qos_degradation"]["packet_loss_rate"]:
            qos_factors += 1
        
        if qos_factors >= 2:
            threats.append(("qos_degradation", THREAT_CONFIDENCE_MAPPING["qos_degradation"]))
        
        return threats