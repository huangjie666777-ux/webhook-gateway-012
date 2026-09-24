package webhook

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

type Claimer interface {
	ClaimEvents(context.Context, string, int) ([]EventRecord, error)
}

type Completer interface {
	CompleteAttempt(context.Context, int64, int, int, string, bool) error
}

type DeliveryStore interface {
	Claimer
	Completer
}

type WorkerConfig struct {
	Client    *http.Client
	Logger    *log.Logger
	Interval  time.Duration
	BatchSize int
}

type Worker struct {
	store     DeliveryStore
	client    *http.Client
	logger    *log.Logger
	interval  time.Duration
	batchSize int
}

func NewWorker(store DeliveryStore, cfg WorkerConfig) *Worker {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 8
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(discardWriter{}, "", 0)
	}
	return &Worker{store: store, client: cfg.Client, logger: cfg.Logger, interval: cfg.Interval, batchSize: cfg.BatchSize}
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	records, err := w.store.ClaimEvents(ctx, "", w.batchSize)
	if err != nil {
		w.logger.Printf("delivery claim failed: %v", err)
		return
	}
	for _, record := range records {
		w.deliver(record)
	}
}

func (w *Worker) deliver(record EventRecord) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, record.Destination, bytes.NewReader(record.Payload))
	if err != nil {
		_ = w.store.CompleteAttempt(context.Background(), record.RowID, record.Delivery.Attempt, 0, "invalid destination", false)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-Id", record.ID)
	req.Header.Set("X-Webhook-Attempt", strconv.Itoa(record.Delivery.Attempt+1))
	resp, err := w.client.Do(req)
	if err != nil {
		retryable := errors.Is(err, context.DeadlineExceeded) || isNetworkTimeout(err)
		_ = w.store.CompleteAttempt(context.Background(), record.RowID, record.Delivery.Attempt, 0, "delivery request failed", retryable)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	code := resp.StatusCode
	if code >= 200 && code < 300 {
		_ = w.store.CompleteAttempt(context.Background(), record.RowID, record.Delivery.Attempt, code, "", false)
		return
	}
	_ = w.store.CompleteAttempt(context.Background(), record.RowID, record.Delivery.Attempt, code, "unexpected response status", code >= 500)
}

type timeoutError interface{ Timeout() bool }

func isNetworkTimeout(err error) bool {
	var timeoutErr timeoutError
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}

type discardWriter struct{}

func (discardWriter) Write([]byte) (int, error) { return 0, nil }
