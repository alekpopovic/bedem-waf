package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const (
	serviceName = "bedemwaf-worker"
	version     = "dev"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fmt.Fprintf(os.Stdout, "%s %s\n", serviceName, version)
	logger.Info("worker_started", "service", serviceName, "version", version)
	logger.Info("worker_placeholder", "todo", "start async job runner for rule updates, event enrichment, and retention cleanup")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	logger.Info("worker_stopped")
}
