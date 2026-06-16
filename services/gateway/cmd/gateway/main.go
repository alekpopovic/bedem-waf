package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/audit"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policy"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policyclient"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/proxy"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/ratelimit"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/waf"
	corazawaf "github.com/bedemwaf/bedemwaf/services/gateway/internal/waf/coraza"
)

const (
	serviceName = "bedemwaf-gateway"
	version     = "dev"
)

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to gateway YAML config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *showVersion {
		fmt.Fprintf(os.Stdout, "%s %s\n", serviceName, version)
		return
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		logger.Error("load_config_failed", "error", err, "path", *configPath)
		os.Exit(1)
	}

	provider, store, err := buildPolicyProvider(cfg, logger)
	if err != nil {
		logger.Error("build_policy_provider_failed", "error", err)
		os.Exit(1)
	}

	limiter, err := ratelimit.FromConfig(cfg.Redis, logger)
	if err != nil {
		logger.Error("build_rate_limiter_failed", "error", err)
		os.Exit(1)
	}
	wafEngine, err := buildWAF(cfg)
	if err != nil {
		logger.Error("build_waf_failed", "error", err)
		os.Exit(1)
	}
	auditDispatcher, err := audit.NewDispatcher(1024, logger, audit.NewJSONStdoutSink(os.Stdout))
	if err != nil {
		logger.Error("build_audit_dispatcher_failed", "error", err)
		os.Exit(1)
	}

	handler, err := proxy.NewGateway(proxy.Options{
		Config:      cfg,
		Policies:    store,
		Provider:    provider,
		RateLimiter: limiter,
		Auditor:     auditDispatcher,
		WAF:         wafEngine,
		Logger:      logger,
	})
	if err != nil {
		logger.Error("build_gateway_failed", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("gateway_starting", "service", serviceName, "version", version, "listen_addr", cfg.Server.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("gateway_server_failed", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("gateway_shutdown_failed", "error", err)
		os.Exit(1)
	}
	if err := auditDispatcher.Shutdown(shutdownCtx); err != nil {
		logger.Error("audit_dispatcher_shutdown_failed", "error", err)
		os.Exit(1)
	}
	logger.Info("gateway_stopped")
}

func buildPolicyProvider(cfg config.Config, logger *slog.Logger) (policy.Provider, *policy.Store, error) {
	if cfg.ControlAPI.Enabled {
		client, err := policyclient.NewClient(cfg.ControlAPI, nil)
		if err != nil {
			return nil, nil, err
		}
		return policyclient.NewProvider(client, cfg.ControlAPI, logger), nil, nil
	}
	store, err := policy.NewStore(cfg.Apps)
	if err != nil {
		return nil, nil, err
	}
	return store, store, nil
}

func defaultConfigPath() string {
	if value := os.Getenv("BEDEMWAF_GATEWAY_CONFIG"); value != "" {
		return value
	}
	return "config.example.yaml"
}

func buildWAF(cfg config.Config) (waf.Engine, error) {
	if !cfg.WAF.Enabled {
		return waf.AllowEngine{}, nil
	}
	switch cfg.WAF.Engine {
	case "coraza":
		return corazawaf.New(cfg.WAF)
	default:
		return nil, fmt.Errorf("unsupported waf engine %q", cfg.WAF.Engine)
	}
}
