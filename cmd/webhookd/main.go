package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/huangjie666777-ux/webhook-gateway-012/internal/httpapi"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

func main() {
	addr := flag.String("addr", envOr("WEBHOOK_ADDR", ":8080"), "HTTP listen address")
	dbPath := flag.String("db", envOr("WEBHOOK_DB", "webhook.db"), "SQLite database path")
	timeout := flag.Duration("delivery-timeout", 10*time.Second, "outbound HTTP timeout")
	workerInterval := flag.Duration("worker-interval", time.Second, "delivery polling interval")
	flag.Parse()

	logger := log.New(os.Stderr, "webhookd ", log.LstdFlags|log.Lmsgprefix)
	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := webhook.NewSQLiteStore(rootCtx, webhook.SQLiteConfig{Path: *dbPath, Now: time.Now})
	if err != nil {
		logger.Fatal(err)
	}
	defer store.Close()
	if err := store.RecoverInFlight(rootCtx); err != nil {
		logger.Fatal(err)
	}

	client := &http.Client{Timeout: *timeout}
	worker := webhook.NewWorker(store, webhook.WorkerConfig{Client: client, Logger: logger, Interval: *workerInterval, BatchSize: 8})
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		if err := worker.Run(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("worker stopped: %v", err)
		}
	}()

	handler := httpapi.NewRouterWithConfig(store, httpapi.Config{Now: time.Now, Logger: logger, MaxSkew: 5 * time.Minute, MaxBody: 1 << 20})
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	serverErr := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s", *addr)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(err)
		}
	case <-rootCtx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Printf("http shutdown failed: %v", err)
	}
	<-workerDone
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
