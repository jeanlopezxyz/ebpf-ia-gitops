package config

import (
    "os"
    "strconv"
    "time"
)

type Config struct {
    Interface          string
    Mode               string // auto|xdp|tc|sim (tc not yet implemented)
    HTTPAddr           string
    ReadHeaderTimeout  time.Duration
    ReadTimeout        time.Duration
    WriteTimeout       time.Duration
    IdleTimeout        time.Duration
    StatsWindow        time.Duration
    PostInterval       time.Duration
    MLDetectorURL      string
    HTTPClientTimeout  time.Duration
    LogLevel           string
}

func getenv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}

func parseDuration(env, def string) time.Duration {
    s := getenv(env, def)
    d, err := time.ParseDuration(s)
    if err != nil {
        return mustDuration(def)
    }
    return d
}

func mustDuration(s string) time.Duration { d, _ := time.ParseDuration(s); return d }

func New() Config {
    return Config{
        Interface:         getenv("INTERFACE", "eth0"),
        Mode:              getenv("MODE", "auto"),
        HTTPAddr:          getenv("HTTP_ADDR", ":8800"),
        ReadHeaderTimeout: parseDuration("HTTP_READ_HEADER_TIMEOUT", "5s"),
        ReadTimeout:       parseDuration("HTTP_READ_TIMEOUT", "10s"),
        WriteTimeout:      parseDuration("HTTP_WRITE_TIMEOUT", "10s"),
        IdleTimeout:       parseDuration("HTTP_IDLE_TIMEOUT", "60s"),
        StatsWindow:       parseDuration("STATS_WINDOW", "1s"),
        PostInterval:      parseDuration("POST_INTERVAL", "2s"),
        MLDetectorURL:     getenv("ML_DETECTOR_URL", "http://ml-detector:5000"),
        HTTPClientTimeout: parseDuration("HTTP_CLIENT_TIMEOUT", "2s"),
        LogLevel:          getenv("LOG_LEVEL", "info"),
    }
}

func GetenvBool(key string, def bool) bool {
    v := os.Getenv(key)
    if v == "" { return def }
    b, err := strconv.ParseBool(v)
    if err != nil { return def }
    return b
}

