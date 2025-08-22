from __future__ import annotations

from pydantic import BaseModel, confloat, conint


class DetectRequest(BaseModel):
    # Network traffic features (original)
    packets_per_second: confloat(ge=0) = 0
    bytes_per_second: confloat(ge=0) = 0
    unique_ips: conint(ge=0) = 0
    unique_ports: conint(ge=0) = 0
    tcp_packets: conint(ge=0) = 0
    udp_packets: conint(ge=0) = 0 
    syn_packets: conint(ge=0) = 0
    
    # Authentication/Security logs features (Rakuten-style)
    username_type: str = None                    # "service", "password", "command", "username"
    confidence_score: confloat(ge=0, le=1) = None
    privilege_level: conint(ge=0, le=1) = None   # 0=normal, 1=elevated
    total_attempts: conint(ge=0) = None
    failed_attempts: conint(ge=0) = None  
    successful_attempts: conint(ge=0) = None
    unique_source_ips: conint(ge=0) = None
    
    # For backward compatibility - deprecated
    tcp_ratio: confloat(ge=0, le=1) = None

    def to_features_dict(self) -> dict:
        data = self.dict()
        # Remove None values for backward compatibility
        return {k: v for k, v in data.items() if v is not None}
    
    def get_detection_type(self) -> str:
        """Determine if this is network or authentication data."""
        if self.username_type is not None:
            return "authentication"
        else:
            return "network"

