package webhook_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

func TestSQLiteSignedReceiveAndDelivery(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	store, err := webhook.NewSQLiteStore(ctx, webhook.SQLiteConfig{Path: filepath.Join(t.TempDir(), "webhook.db"), Now: func() time.Time { return now }, MaxAttempts: 2, BaseBackoff: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, _, err := store.CreateEndpoint(ctx, webhook.EndpointInput{Tenant: "tenant-a", ID: "ep-1", URL: "http://127.0.0.1:1/destination"}, webhook.KeyInput{KeyID: "k-1", Secret: "secret"}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"type":"demo"}`)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))
	input := webhook.EventInput{ID: "evt-1", Tenant: "tenant-a", EndpointID: "ep-1", OrderingKey: "order-1", Payload: body, KeyID: "k-1", Signature: signature, Timestamp: now.Unix()}
	event, deduped, err := store.ReceiveEvent(ctx, input)
	if err != nil || deduped || event.Status != webhook.StatusPending {
		t.Fatalf(`ReceiveEvent() = %+v, %v, %v`, event, deduped, err)
	}
	if _, deduped, err := store.ReceiveEvent(ctx, input); err != nil || !deduped {
		t.Fatalf(`duplicate ReceiveEvent() deduped=%v err=%v`, deduped, err)
	}
	conflict := input
	conflict.Payload = []byte(`{"type":"changed"}`)
	if _, _, err := store.ReceiveEvent(ctx, conflict); err != webhook.ErrConflict {
		t.Fatalf(`conflict error = %v, want %v`, err, webhook.ErrConflict)
	}

	var mu sync.Mutex
	var gotBody []byte
	var gotEvent string
	var gotAttempt string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotBody, _ = io.ReadAll(r.Body)
		gotEvent = r.Header.Get("X-Event-Id")
		gotAttempt = r.Header.Get("X-Webhook-Attempt")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	if _, _, err := store.CreateEndpoint(ctx, webhook.EndpointInput{Tenant: "tenant-a", ID: "ep-2", URL: target.URL}, webhook.KeyInput{KeyID: "k-1", Secret: "secret"}); err != nil {
		t.Fatal(err)
	}
	input.EndpointID = "ep-2"
	if _, _, err := store.ReceiveEvent(ctx, input); err != nil {
		t.Fatal(err)
	}
	worker := webhook.NewWorker(store, webhook.WorkerConfig{Client: target.Client(), Interval: time.Millisecond, BatchSize: 1})
	runCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	_ = worker.Run(runCtx)
	mu.Lock()
	if !bytes.Equal(gotBody, body) || gotEvent != "evt-1" || gotAttempt != "1" {
		t.Fatalf(`delivery = body %q event %q attempt %q`, gotBody, gotEvent, gotAttempt)
	}
	mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events, err := store.ListEvents(ctx, "tenant-a", "ep-2", 10)
		if err == nil && len(events) == 1 && events[0].Delivery.Status == webhook.StatusSucceeded {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("delivery did not reach succeeded state")
}

func TestVerifySignatureRejectsSkew(t *testing.T) {
	body := []byte("body")
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(fmt.Sprintf("%s.", timestamp)))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))
	if !webhook.VerifySignature("secret", timestamp, body, signature, time.Now(), time.Minute) {
		t.Fatal("valid signature rejected")
	}
	old := strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10)
	if webhook.VerifySignature("secret", old, body, signature, time.Now(), time.Minute) {
		t.Fatal("stale signature accepted")
	}
}
