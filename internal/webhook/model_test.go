package webhook_test

import (
    "context"
    "testing"

    "github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

func TestPublicStoreBoundaryExists(t *testing.T) {
    var store webhook.WebhookStore = webhook.NewMemoryStore()
    _, _, err := store.Accept(context.Background(), "tenant", "endpoint", []byte(`{"id":1}`), "sig", "key-1")
    if err == nil {
        t.Fatal("initial skeleton must make unimplemented behavior explicit")
    }
}
