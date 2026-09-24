package webhook_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

func newTestStore(t *testing.T, opts webhook.StoreOptions) (*webhook.SQLiteStore, func()) {
	t.Helper()
	dir := t.TempDir()
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = 3
	}
	if opts.InitialBackoff == 0 {
		opts.InitialBackoff = time.Second
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = time.Minute
	}
	if opts.InflightTTL == 0 {
		opts.InflightTTL = time.Second
	}
	opts.AllowPrivateURL = true
	store, err := webhook.OpenSQLiteStore(context.Background(), filepath.Join(dir, "t.db"), opts)
	if err != nil {
		t.Fatal(err)
	}
	return store, func() { store.Close() }
}

func sign(t *testing.T, secret, ts string, body []byte) string {
	t.Helper()
	sig, err := webhook.ComputeSignature(secret, ts, body)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestAcceptVerifyIdempotencyAndConflict(t *testing.T) {
	fixed := time.Unix(1_700_000_010, 0)
	store, cleanup := newTestStore(t, webhook.StoreOptions{
		TimestampSkew: time.Hour,
		Now:           func() time.Time { return fixed },
	})
	defer cleanup()
	ctx := context.Background()

	ep, key, err := store.CreateEndpoint(ctx, "tenant-a", "http://127.0.0.1:9/hook")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"hello":"world"}`)
	ts := "1700000000"
	in := webhook.InboundEvent{
		EndpointID: ep.ID, EventID: "evt-1", KeyID: key.ID, Timestamp: 1700000000,
		OrderingKey: "user-1", ContentType: "application/json", Payload: body,
		Signature: sign(t, key.Secret, ts, body),
	}
	ev, dup, err := store.AcceptEvent(ctx, in)
	if err != nil || dup {
		t.Fatalf("first accept dup=%v err=%v", dup, err)
	}
	if ev.Status != webhook.StatusPending {
		t.Fatalf("status=%s", ev.Status)
	}

	// Identical resubmission is idempotent and performs no new delivery row.
	ev2, dup, err := store.AcceptEvent(ctx, in)
	if err != nil || !dup || ev2.ID != "evt-1" {
		t.Fatalf("duplicate accept dup=%v err=%v ev=%+v", dup, err, ev2)
	}

	// Different payload with same event id conflicts.
	conflict := in
	conflict.Payload = []byte(`{"hello":"other"}`)
	conflict.Signature = sign(t, key.Secret, ts, conflict.Payload)
	if _, _, err := store.AcceptEvent(ctx, conflict); err != webhook.ErrConflict {
		t.Fatalf("want conflict, got %v", err)
	}

	// Invalid signature must not write anything.
	bad := in
	bad.EventID = "evt-bad"
	bad.Signature = sign(t, key.Secret, ts, []byte("tampered"))
	if _, _, err := store.AcceptEvent(ctx, bad); err != webhook.ErrInvalidSignature {
		t.Fatalf("want invalid signature, got %v", err)
	}
	if _, err := store.GetEvent(ctx, "tenant-a", ep.ID, "evt-bad"); err != webhook.ErrNotFound {
		t.Fatalf("invalid event was persisted: %v", err)
	}

	// Rotation retires the old key.
	newKey, err := store.CreateKey(ctx, "tenant-a", ep.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AcceptEvent(ctx, in); err != webhook.ErrInactiveKey {
		t.Fatalf("old key should be inactive, got %v", err)
	}
	rotated := in
	rotated.EventID = "evt-2"
	rotated.KeyID = newKey.ID
	rotated.Signature = sign(t, newKey.Secret, ts, body)
	if _, _, err := store.AcceptEvent(ctx, rotated); err != nil {
		t.Fatalf("rotated key accept: %v", err)
	}

	// Tenant isolation: another tenant cannot read the endpoint/events.
	if _, err := store.GetEvent(ctx, "tenant-b", ep.ID, "evt-1"); err != webhook.ErrNotFound {
		t.Fatalf("cross-tenant read should be not found, got %v", err)
	}
}

func TestDeliveryOrderBackoffDeadAndReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	store, cleanup := newTestStore(t, webhook.StoreOptions{Now: clock, InitialBackoff: time.Second, MaxAttempts: 3})
	defer cleanup()
	ctx := context.Background()

	ep, key, err := store.CreateEndpoint(ctx, "tenant", "http://127.0.0.1:9/hook")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		body := []byte("body-" + id)
		in := webhook.InboundEvent{
			EndpointID: ep.ID, EventID: id, KeyID: key.ID, Timestamp: now.Unix(),
			OrderingKey: "k", ContentType: "application/json", Payload: body,
			Signature: sign(t, key.Secret, "1700000000", body),
		}
		in.Timestamp = 1700000000
		if _, _, err := store.AcceptEvent(ctx, in); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Millisecond)
	}

	items, err := store.ClaimBatch(ctx, now, 10)
	if err != nil || len(items) != 1 || items[0].EventID != "a" {
		t.Fatalf("claim head: %+v err=%v", items, err)
	}
	first := items[0]

	// While a is delivering, b must remain blocked.
	more, err := store.ClaimBatch(ctx, now, 10)
	if err != nil || len(more) != 0 {
		t.Fatalf("b must wait behind a: %+v err=%v", more, err)
	}

	// 5xx schedules deterministic backoff: attempt 1 -> +1s.
	if err := store.RecordResult(ctx, first, 500, "", now); err != nil {
		t.Fatal(err)
	}
	if items, _ = store.ClaimBatch(ctx, now, 10); len(items) != 0 {
		t.Fatalf("retry not due yet: %+v", items)
	}
	now = now.Add(time.Second + time.Millisecond)
	items, _ = store.ClaimBatch(ctx, now, 10)
	if len(items) != 1 || items[0].EventID != "a" || items[0].Attempt != 2 {
		t.Fatalf("retry claim: %+v", items)
	}

	// Success unblocks b.
	if err := store.RecordResult(ctx, items[0], 200, "", now); err != nil {
		t.Fatal(err)
	}
	items, _ = store.ClaimBatch(ctx, now, 10)
	if len(items) != 1 || items[0].EventID != "b" {
		t.Fatalf("b should now be head: %+v", items)
	}

	// Exhaust retries on b -> dead.
	b := items[0]
	for attempt := b.Attempt; attempt <= 3; attempt++ {
		if err := store.RecordResult(ctx, b, 503, "", now); err != nil {
			t.Fatal(err)
		}
		if attempt < 3 {
			now = now.Add(time.Duration(attempt)*time.Second + time.Millisecond)
			next, err := store.ClaimBatch(ctx, now, 10)
			if err != nil || len(next) != 1 {
				t.Fatalf("attempt %d claim: %+v err=%v", attempt+1, next, err)
			}
			b = next[0]
		}
	}
	ev, err := store.GetEvent(ctx, "tenant", ep.ID, "b")
	if err != nil || ev.Status != webhook.StatusDead {
		t.Fatalf("b should be dead: status=%s err=%v", ev.Status, err)
	}

	// Replay brings it back for delivery.
	if err := store.ReplayEvent(ctx, "tenant", ep.ID, "b"); err != nil {
		t.Fatal(err)
	}
	items, _ = store.ClaimBatch(ctx, now, 10)
	if len(items) != 1 || items[0].EventID != "b" {
		t.Fatalf("replayed b should claim: %+v", items)
	}
}

func TestRecoverStaleInflight(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	store, cleanup := newTestStore(t, webhook.StoreOptions{Now: clock})
	defer cleanup()
	ctx := context.Background()

	ep, key, err := store.CreateEndpoint(ctx, "tenant", "http://127.0.0.1:9/hook")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("x")
	in := webhook.InboundEvent{
		EndpointID: ep.ID, EventID: "a", KeyID: key.ID, Timestamp: 1700000000,
		ContentType: "application/json", Payload: body,
		Signature: sign(t, key.Secret, "1700000000", body),
	}
	if _, _, err := store.AcceptEvent(ctx, in); err != nil {
		t.Fatal(err)
	}
	items, _ := store.ClaimBatch(ctx, now, 10)
	if len(items) != 1 {
		t.Fatalf("claim: %+v", items)
	}
	// Fresh inflight is not re-claimed.
	if items, _ := store.ClaimBatch(ctx, now, 10); len(items) != 0 {
		t.Fatalf("fresh inflight reclaimed: %+v", items)
	}
	// After TTL (simulating crash/restart) it becomes claimable again.
	now = now.Add(2 * time.Second)
	items, _ = store.ClaimBatch(ctx, now, 10)
	if len(items) != 1 || items[0].Attempt != 2 {
		t.Fatalf("stale recovery: %+v", items)
	}
}

func TestURLValidation(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1/x", "http://localhost/x", "ftp://example.com", "http://10.0.0.1/", "http://169.254.169.254/latest/meta-data"} {
		if err := webhook.ValidateEndpointURL(u, false); err == nil {
			t.Errorf("expected %q rejected", u)
		}
	}
	if err := webhook.ValidateEndpointURL("https://example.com/hook", false); err != nil {
		t.Errorf("public url: %v", err)
	}
}

func TestNetworkErrorRetriesUntilDead(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	store, cleanup := newTestStore(t, webhook.StoreOptions{
		Now: clock, InitialBackoff: time.Second, MaxBackoff: 10 * time.Second, MaxAttempts: 2,
	})
	defer cleanup()
	ctx := context.Background()
	ep, key, err := store.CreateEndpoint(ctx, "tenant", "http://127.0.0.1:9/hook")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("x")
	in := webhook.InboundEvent{
		EndpointID: ep.ID, EventID: "n", KeyID: key.ID, Timestamp: 1700000000,
		ContentType: "application/json", Payload: body,
		Signature: sign(t, key.Secret, "1700000000", body),
	}
	if _, _, err := store.AcceptEvent(ctx, in); err != nil {
		t.Fatal(err)
	}
	items, _ := store.ClaimBatch(ctx, now, 10)
	if len(items) != 1 {
		t.Fatalf("claim %+v", items)
	}
	if err := store.RecordResult(ctx, items[0], 0, "network_error", now); err != nil {
		t.Fatal(err)
	}
	// Not due immediately; deterministic 1s backoff after attempt 1.
	if due, _ := store.ClaimBatch(ctx, now, 10); len(due) != 0 {
		t.Fatalf("network failure should be backing off: %+v", due)
	}
	now = now.Add(time.Second + time.Millisecond)
	items, _ = store.ClaimBatch(ctx, now, 10)
	if len(items) != 1 {
		t.Fatalf("retry claim %+v", items)
	}
	if err := store.RecordResult(ctx, items[0], 0, "network_error", now); err != nil {
		t.Fatal(err)
	}
	ev, err := store.GetEvent(ctx, "tenant", ep.ID, "n")
	if err != nil || ev.Status != webhook.StatusDead {
		t.Fatalf("network exhaustion status=%s err=%v", ev.Status, err)
	}
}
