package httpapi

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

// Config injects time and body limits into the HTTP layer.
type Config struct {
	MaxBodyBytes  int64
	TimestampSkew time.Duration
	Now           func() time.Time
}

// Router keeps the original NewRouter entry point working while exposing the
// durable store used by the full API when available.
type Router struct {
	store webhook.WebhookStore
	full  webhook.FullStore
	cfg   Config
}

// NewRouter preserves the skeleton entry point. Management and ingest routes
// activate automatically when store implements FullStore.
func NewRouter(store webhook.WebhookStore) http.Handler {
	return NewRouterWithStore(store, Config{})
}

// NewRouterWithStore builds the complete API against a durable store.
func NewRouterWithStore(store webhook.WebhookStore, cfg Config) http.Handler {
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.TimestampSkew == 0 {
		cfg.TimestampSkew = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	rt := &Router{store: store, cfg: cfg}
	rt.full, _ = store.(webhook.FullStore)

	r := chi.NewRouter()
	r.Use(rt.requestID)
	r.Get("/healthz", rt.healthz)
	r.Route("/v1", func(r chi.Router) {
		r.Post("/endpoints", rt.createEndpoint)
		r.Get("/endpoints", rt.listEndpoints)
		r.Get("/endpoints/{endpoint}", rt.getEndpoint)
		r.Post("/endpoints/{endpoint}/keys", rt.createKey)
		r.Delete("/endpoints/{endpoint}/keys/{key}", rt.deactivateKey)
		r.Post("/endpoints/{endpoint}/events", rt.receiveEvent)
		r.Get("/endpoints/{endpoint}/events", rt.listEvents)
		r.Get("/endpoints/{endpoint}/events/{event}", rt.getEvent)
		r.Post("/endpoints/{endpoint}/events/{event}/replay", rt.replayEvent)
	})
	return r
}

type requestIDKey struct{}

func (rt *Router) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-Id", rid)
		ctx := context.WithValue(r.Context(), requestIDKey{}, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey{}).(string)
	return v
}

func (rt *Router) requireStore(w http.ResponseWriter, r *http.Request) (webhook.FullStore, bool) {
	if rt.full == nil {
		writeError(w, http.StatusServiceUnavailable, "not_configured", "durable store is not configured", requestIDFrom(r.Context()))
		return nil, false
	}
	return rt.full, true
}

func (rt *Router) requireTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenant := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	if tenant == "" {
		writeError(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-Id header is required", requestIDFrom(r.Context()))
		return "", false
	}
	return tenant, true
}

func (rt *Router) healthz(w http.ResponseWriter, r *http.Request) {
	if rt.full != nil {
		if err := rt.full.Ping(r.Context()); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "ok")
}

func parseLimit(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	if n > 500 {
		n = 500
	}
	return n
}
