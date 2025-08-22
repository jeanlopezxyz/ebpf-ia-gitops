from __future__ import annotations

import os
import time
from typing import Dict, Optional

import requests


class PrometheusSource:
    """Thin Prometheus HTTP API client to build feature snapshots.

    It queries Prometheus for rates over a short window to approximate
    packets_per_second, bytes_per_second, and tcp_ratio. Unique IPs/ports
    and syn_packets can be sourced from optional metrics if available.
    """

    def __init__(self, base_url: Optional[str] = None, timeout: float = 5.0) -> None:
        self.base_url = base_url or os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
        self.timeout = timeout
        # Metric names (override with env if your Prom deploy differs)
        self.m_packets = os.getenv("PROM_METRIC_PACKETS", "ebpf_packets_processed_total")
        self.m_bytes = os.getenv("PROM_METRIC_BYTES", "ebpf_bytes_processed_total")
        self.m_syn = os.getenv("PROM_METRIC_SYN", "")  # optional
        self.m_unique_ips = os.getenv("PROM_METRIC_UNIQUE_IPS", "")  # optional
        self.m_unique_ports = os.getenv("PROM_METRIC_UNIQUE_PORTS", "")  # optional
        self.window = os.getenv("PROM_QUERY_WINDOW", "1m")

    def _query(self, promql: str) -> float:
        url = f"{self.base_url}/api/v1/query"
        resp = requests.get(url, params={"query": promql, "time": str(time.time())}, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return 0.0
        result = data.get("data", {}).get("result", [])
        if not result:
            return 0.0
        # Use the first vector result (already aggregated)
        val = result[0].get("value", [None, "0"])[1]
        try:
            return float(val)
        except Exception:
            return 0.0

    def snapshot(self) -> Dict[str, float]:
        # Rates per second
        pps = self._query(f"sum(rate({self.m_packets}[{self.window}]))")
        bps = self._query(f"sum(rate({self.m_bytes}[{self.window}]))")
        tcp_packets = self._query(f"sum(rate({self.m_packets}{{protocol=\"tcp\"}}[{self.window}]))")
        udp_packets = self._query(f"sum(rate({self.m_packets}{{protocol=\"udp\"}}[{self.window}]))")

        # Optional metrics (best-effort)
        syn = 0.0
        if self.m_syn:
            syn = self._query(f"sum(rate({self.m_syn}[{self.window}]))")
        uniq_ips = 0.0
        if self.m_unique_ips:
            uniq_ips = self._query(f"avg_over_time({self.m_unique_ips}[{self.window}])")
        uniq_ports = 0.0
        if self.m_unique_ports:
            uniq_ports = self._query(f"avg_over_time({self.m_unique_ports}[{self.window}])")

        return {
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "unique_ips": uniq_ips,
            "unique_ports": uniq_ports,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "syn_packets": syn,
        }

