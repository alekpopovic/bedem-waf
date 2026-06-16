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

	"github.com/bedemwaf/bedemwaf/services/control-api/internal/auth"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/config"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/db"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/httpapi"
)

const (
	serviceName = "bedemwaf-control-api"
	version     = "dev"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *showVersion {
		fmt.Fprintf(os.Stdout, "%s %s\n", serviceName, version)
		return
	}

	cfg := config.Load()
	if cfg.AdminAPIKey == "" {
		logger.Error("admin_api_key_required", "env", "BEDEMWAF_ADMIN_API_KEY")
		os.Exit(1)
	}
	if cfg.GatewayAPIKey == "" {
		logger.Error("gateway_api_key_required", "env", "BEDEMWAF_GATEWAY_API_KEY")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.DBPingTimeout)
	defer cancel()
	pool, err := db.OpenPool(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database_connect_failed", "error", err)
		os.Exit(1)
	}
	repo := db.NewPostgresRepository(pool)
	defer repo.Close()

	api := httpapi.NewServer(repo, auth.NewStaticBearer(cfg.AdminAPIKey), auth.NewStaticBearer(cfg.GatewayAPIKey), logger)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("control_api_starting", "service", serviceName, "version", version, "listen_addr", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("control_api_server_failed", "error", err)
			os.Exit(1)
		}
	}()

	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-stopCtx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("control_api_shutdown_failed", "error", err)
		os.Exit(1)
	}
	logger.Info("control_api_stopped")
}
