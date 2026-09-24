package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huangjie666777-ux/webhook-gateway-012/internal/httpapi"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/worker"
)

type createResp struct {
	Endpoint struct {
		ID string `json:"id"`
	} `json:"endpoint"`
	Key struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"key"`
}

func TestEndToEndSignedIngestAndDelivery(t *testing.T) {
	var attempts int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if r.Header.Get("X-Webhook-Event-Id") != "evt-1" {
			t.Errorf("missing event id header")
		}
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()

	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	store, err := webhook.OpenSQLiteStore(context.Background(), filepath.Join(dir, "e.db"), webhook.StoreOptions{
		AllowPrivateURL: true,
		InitialBackoff:  20 * time.Millisecond,
		MaxBackoff:      20 * time.Millisecond,
		InflightTTL:     5 * time.Second,
		TimestampSkew:   time.Hour,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	h := httpapi.NewRouterWithStore(store, httpapi.Config{
		TimestampSkew: time.Hour,
		Now:           func() time.Time { return now },
	})
	server := httptest.NewServer(h)
	defer server.Close()

	// Create endpoint.
	body := []byte(`{"url":"` + destination.URL + `"}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/endpoints", bytes.NewReader(body))
	req.Header.Set("X-Tenant-Id", "t1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d", resp.StatusCode)
	}
	var created createResp
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Signed ingest.
	payload := []byte(`{"x":1}`)
	ts := strconv.FormatInt(now.Unix(), 10)
	sig, err := webhook.ComputeSignature(created.Key.Secret, ts, payload)
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/v1/endpoints/"+created.Endpoint.ID+"/events", bytes.NewReader(payload))
	req.Header.Set("X-Webhook-Id", "evt-1")
	req.Header.Set("X-Webhook-Timestamp", ts)
	req.Header.Set("X-Webhook-Key-Id", created.Key.ID)
	req.Header.Set("X-Webhook-Signature", sig)
	req.Header.Set("X-Webhook-Ordering-Key", "k1")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("ingest status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// Bad signature rejected and returns stable error envelope.
	bad, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/endpoints/"+created.Endpoint.ID+"/events", bytes.NewReader(payload))
	bad.Header.Set("X-Webhook-Id", "evt-bad")
	bad.Header.Set("X-Webhook-Timestamp", ts)
	bad.Header.Set("X-Webhook-Key-Id", created.Key.ID)
	bad.Header.Set("X-Webhook-Signature", "deadbeef")
	bresp, _ := http.DefaultClient.Do(bad)
	if bresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad sig status=%d", bresp.StatusCode)
	}
	var env map[string]string
	json.NewDecoder(bresp.Body).Decode(&env)
	bresp.Body.Close()
	if env["code"] != "invalid_signature" || env["request_id"] == "" {
		t.Fatalf("unexpected error envelope: %v", env)
	}

	// Worker delivers with one retry.
	w := worker.New(store, worker.Options{
		Client:         server.Client(),
		Interval:       10 * time.Millisecond,
		Now:            func() time.Time { return now },
		RequestTimeout: 2 * time.Second,
	})
	wctx, cancel := context.WithCancel(context.Background())
	go w.Run(wctx)
	defer cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&attempts) < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	ev, err := store.GetEvent(context.Background(), "t1", created.Endpoint.ID, "evt-1")
	if err != nil || ev.Status != webhook.StatusSucceeded {
		t.Fatalf("event status=%s err=%v", ev.Status, err)
	}

	// Idempotent resubmit returns 200 duplicate=true.
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/v1/endpoints/"+created.Endpoint.ID+"/events", bytes.NewReader(payload))
	req.Header.Set("X-Webhook-Id", "evt-1")
	req.Header.Set("X-Webhook-Timestamp", ts)
	req.Header.Set("X-Webhook-Key-Id", created.Key.ID)
	req.Header.Set("X-Webhook-Signature", sig)
	dresp, _ := http.DefaultClient.Do(req)
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("dup status=%d", dresp.StatusCode)
	}
	dresp.Body.Close()
}

func TestHealthz(t *testing.T) {
	dir := t.TempDir()
	store, err := webhook.OpenSQLiteStore(context.Background(), filepath.Join(dir, "h.db"), webhook.StoreOptions{AllowPrivateURL: true})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := httptest.NewServer(httpapi.NewRouter(store))
	defer server.Close()
	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz=%d", resp.StatusCode)
	}
}
