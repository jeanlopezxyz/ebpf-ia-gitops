from __future__ import annotations

from pydantic import BaseModel, confloat, conint


class DetectRequest(BaseModel):
    packets_per_second: confloat(ge=0) = 0
    bytes_per_second: confloat(ge=0) = 0
    unique_ips: conint(ge=0) = 0
    unique_ports: conint(ge=0) = 0
    tcp_ratio: confloat(ge=0, le=1) = 0.5
    syn_packets: conint(ge=0) = 0

    def to_features_dict(self) -> dict:
        return self.dict()

