package config

import (
	"os"
	"time"
)

type Config struct {
	ListenAddr    string
	DatabaseURL   string
	AdminAPIKey   string
	GatewayAPIKey string

	DBPingTimeout time.Duration
}

func Load() Config {
	cfg := Config{
		ListenAddr:    getenv("BEDEMWAF_CONTROL_API_ADDR", ":8081"),
		DatabaseURL:   os.Getenv("BEDEMWAF_DATABASE_URL"),
		AdminAPIKey:   os.Getenv("BEDEMWAF_ADMIN_API_KEY"),
		GatewayAPIKey: os.Getenv("BEDEMWAF_GATEWAY_API_KEY"),
		DBPingTimeout: 2 * time.Second,
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	}
	return cfg
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
