package mlclient

import (
    "bytes"
    "encoding/json"
    "log"
    "net/http"
    "time"

    c "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/config"
    m "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/metrics"
    p "github.com/jeanlopezxyz/ebpf-ia-gitops/applications/ebpf-monitor/pkg/processor"
)

type Client struct {
    cfg    c.Config
    statsF func() p.NetworkStats
}

func New(cfg c.Config, stats func() p.NetworkStats) *Client {
    return &Client{cfg: cfg, statsF: stats}
}

func (cl *Client) Start() {
    ticker := time.NewTicker(cl.cfg.PostInterval)
    go func() {
        backoff := time.Second
        for range ticker.C {
            st := cl.statsF()
            features := map[string]any{
                "packets_per_second": st.PacketsPerSecond,
                "bytes_per_second":   st.BytesPerSecond,
                "unique_ips":         st.UniqueIPs,
                "unique_ports":       st.UniquePorts,
                "tcp_ratio":          ratio(st.TCPPackets, st.UDPPackets),
                "syn_packets":        st.SYNPackets,
            }
            b, _ := json.Marshal(features)
            client := &http.Client{Timeout: cl.cfg.HTTPClientTimeout}
            resp, err := client.Post(cl.cfg.MLDetectorURL+"/detect", "application/json", bytes.NewBuffer(b))
            if err != nil {
                log.Printf("ml post error: %v", err)
                m.MLPostFailuresTotal.Inc()
                time.Sleep(backoff)
                if backoff < 10*time.Second { backoff *= 2 }
                continue
            }
            if resp.Body != nil { resp.Body.Close() }
            backoff = time.Second
        }
    }()
}

func ratio(tcp, udp int64) float64 {
    total := float64(tcp + udp)
    if total <= 0 { return 0 }
    return float64(tcp) / total
}

