package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/huangjie666777-ux/webhook-gateway-012/internal/httpapi"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/worker"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dbPath := flag.String("db", "webhookd.db", "SQLite database path")
	allowPrivate := flag.Bool("allow-private-url", false, "allow loopback/private endpoint URLs (local development only)")
	shutdownTimeout := flag.Duration("shutdown-timeout", 15*time.Second, "graceful shutdown timeout")
	flag.Parse()

	logger := log.New(os.Stderr, "webhookd ", log.LstdFlags|log.Lmsgprefix)

	opts := webhook.StoreOptions{AllowPrivateURL: *allowPrivate}
	store, err := webhook.OpenSQLiteStore(context.Background(), *dbPath, opts)
	if err != nil {
		logger.Fatalf("open store: %v", err)
	}
	defer store.Close()

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	w := worker.New(store, worker.Options{
		Client: client,
		Logger: logger,
	})

	workerCtx, stopWorker := context.WithCancel(context.Background())
	go w.Run(workerCtx)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           httpapi.NewRouterWithStore(store, httpapi.Config{}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("listen: %v", err)
		}
	}()
	logger.Printf("listening on %s db=%s", *addr, *dbPath)
	<-sigCh
	logger.Printf("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("http shutdown: %v", err)
	}
	stopWorker()
	logger.Printf("stopped")
}
