package config

import (
	"os"
	"time"
)

type Config struct {
	Interface         string
	HTTPAddr          string
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	StatsWindow       time.Duration
	PostInterval      time.Duration
	MLDetectorURL     string
	HTTPClientTimeout time.Duration
	LogLevel          string
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
		HTTPAddr:          getenv("HTTP_ADDR", ":8800"),
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

