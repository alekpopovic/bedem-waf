package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bedemwaf/bedemwaf/services/worker/internal/metrics"
	"github.com/bedemwaf/bedemwaf/services/worker/internal/rules"
)

const (
	serviceName = "bedemwaf-worker"
	version     = "dev"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fmt.Fprintf(os.Stdout, "%s %s\n", serviceName, version)
	logger.Info("worker_started", "service", serviceName, "version", version)
	metricsServer := startMetricsServer(logger)
	if rulesDir := os.Getenv("BEDEMWAF_RULES_DIR"); rulesDir != "" {
		if err := scanManagedRules(context.Background(), rulesDir, logger); err != nil {
			logger.Error("managed_rules_scan_failed", "error", err, "rules_dir", rulesDir)
			os.Exit(1)
		}
	}
	logger.Info("worker_placeholder", "todo", "start async job runner for event enrichment and retention cleanup")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("worker_metrics_shutdown_failed", "error", err)
		os.Exit(1)
	}
	logger.Info("worker_stopped")
}

func scanManagedRules(ctx context.Context, rulesDir string, logger *slog.Logger) error {
	const job = "managed_rules_scan"
	metrics.IncJob(job)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var recorder rules.Recorder
	if databaseURL := os.Getenv("BEDEMWAF_DATABASE_URL"); databaseURL != "" {
		pool, err := pgxpool.New(ctx, databaseURL)
		if err != nil {
			return err
		}
		defer pool.Close()
		if err := pool.Ping(ctx); err != nil {
			return err
		}
		recorder = rules.NewPostgresRecorder(pool)
	}
	sets, err := rules.ScanAndRecord(ctx, rulesDir, recorder)
	if err != nil {
		metrics.IncJobError(job)
		return err
	}
	logger.Info("managed_rules_scan_completed", "rules_dir", rulesDir, "sets", len(sets), "recorded", recorder != nil)
	return nil
}

func startMetricsServer(logger *slog.Logger) *http.Server {
	addr := os.Getenv("BEDEMWAF_WORKER_METRICS_ADDR")
	if addr == "" {
		addr = ":9092"
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		logger.Info("worker_metrics_starting", "listen_addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("worker_metrics_server_failed", "error", err)
			os.Exit(1)
		}
	}()
	return server
}
