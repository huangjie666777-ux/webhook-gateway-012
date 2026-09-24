// Package worker performs durable, ordered outbound webhook delivery.
package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

// Clock allows injecting time in tests.
type Clock func() time.Time

// Options configures the delivery worker.
type Options struct {
	Client         *http.Client
	Interval       time.Duration
	BatchSize      int
	RequestTimeout time.Duration
	Now            Clock
	Logger         *log.Logger
}

// Worker claims due deliveries and POSTs the original raw payloads.
type Worker struct {
	store  webhook.FullStore
	client *http.Client
	opts   Options
}

// New builds a worker with safe defaults.
func New(store webhook.FullStore, opts Options) *Worker {
	if opts.Client == nil {
		opts.Client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if opts.Interval == 0 {
		opts.Interval = 500 * time.Millisecond
	}
	if opts.BatchSize == 0 {
		opts.BatchSize = 16
	}
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = 10 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	return &Worker{store: store, client: opts.Client, opts: opts}
}

// Run polls until ctx is cancelled, then waits for in-flight deliveries to
// finish and durably record their outcomes before returning.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.opts.Interval)
	defer ticker.Stop()
	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-ticker.C:
			items, err := w.store.ClaimBatch(ctx, w.opts.Now(), w.opts.BatchSize)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					w.opts.Logger.Printf("worker claim failed: %v", err)
				}
				continue
			}
			for _, item := range items {
				wg.Add(1)
				go func(it webhook.OutboundItem) {
					defer wg.Done()
					w.deliver(ctx, it)
				}(item)
			}
		}
	}
}

// deliver performs one attempt and records the result. The per-request
// context is bounded by RequestTimeout and is not tied to shutdown
// cancellation, so a claimed attempt is always recorded exactly once.
func (w *Worker) deliver(shutdownCtx context.Context, item webhook.OutboundItem) {
	reqCtx, cancel := context.WithTimeout(context.Background(), w.opts.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, item.URL, bytes.NewReader(item.Payload))
	if err != nil {
		w.record(item, 0, "build_request_failed")
		return
	}
	req.Header.Set("Content-Type", item.ContentType)
	req.Header.Set("X-Webhook-Event-Id", item.EventID)
	req.Header.Set("X-Webhook-Attempt", strconv.Itoa(item.Attempt))

	resp, err := w.client.Do(req)
	if err != nil {
		// Never log the URL or payload; identify the failure category only.
		w.opts.Logger.Printf("delivery network error endpoint=%s event=%s attempt=%d", item.EndpointID, item.EventID, item.Attempt)
		w.record(item, 0, "network_error")
		return
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()
	w.opts.Logger.Printf("delivery result endpoint=%s event=%s attempt=%d status=%d", item.EndpointID, item.EventID, item.Attempt, resp.StatusCode)
	w.record(item, resp.StatusCode, "")
}

func (w *Worker) record(item webhook.OutboundItem, code int, errMsg string) {
	// Record with a fresh context so shutdown still persists the final outcome.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.store.RecordResult(ctx, item, code, errMsg, w.opts.Now()); err != nil {
		w.opts.Logger.Printf("delivery record failed endpoint=%s event=%s: %v", item.EndpointID, item.EventID, err)
	}
}
