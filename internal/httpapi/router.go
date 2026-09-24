package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

type contextKey string

const requestIDKey contextKey = "request_id"

type ServiceStore interface {
	webhook.WebhookStore
	CreateEndpoint(context.Context, webhook.EndpointInput, webhook.KeyInput) (webhook.Endpoint, webhook.SigningKey, error)
	RotateKey(context.Context, string, string, webhook.KeyInput) (webhook.SigningKey, error)
	Endpoint(context.Context, string, string) (webhook.Endpoint, error)
	ActiveKey(context.Context, string, string, string) (webhook.SigningKey, error)
	ReceiveEvent(context.Context, webhook.EventInput) (webhook.Event, bool, error)
	ListEvents(context.Context, string, string, int) ([]webhook.EventRecord, error)
	ReplayEvent(context.Context, string, string, string) (webhook.Delivery, error)
}

type Config struct {
	Now     func() time.Time
	MaxSkew time.Duration
	MaxBody int64
	Logger  *log.Logger
}

type API struct {
	store   ServiceStore
	now     func() time.Time
	maxSkew time.Duration
	maxBody int64
	logger  *log.Logger
}

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type createEndpointRequest struct {
	Tenant string `json:"tenant"`
	ID     string `json:"id"`
	URL    string `json:"url"`
	KeyID  string `json:"key_id"`
	Secret string `json:"secret"`
}

type rotateKeyRequest struct {
	Tenant string `json:"tenant"`
	KeyID  string `json:"key_id"`
	Secret string `json:"secret"`
}

type endpointResponse struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

type keyResponse struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
}

type eventResponse struct {
	ID          string           `json:"id"`
	EndpointID  string           `json:"endpoint_id"`
	OrderingKey string           `json:"ordering_key"`
	KeyID       string           `json:"key_id"`
	SignedAt    int64            `json:"signed_at"`
	ReceivedAt  int64            `json:"received_at"`
	Status      webhook.Status   `json:"status"`
	Delivery    deliveryResponse `json:"delivery"`
}

type deliveryResponse struct {
	Attempt     int    `json:"attempt"`
	NextAttempt int64  `json:"next_attempt_at"`
	Status      string `json:"status"`
	LastCode    int    `json:"last_code"`
}

type acceptResponse struct {
	ID     string         `json:"id"`
	Dedupe bool           `json:"deduplicated"`
	Status webhook.Status `json:"status"`
}

func NewRouter(store webhook.WebhookStore) http.Handler {
	return NewRouterWithConfig(store, Config{})
}

func NewRouterWithConfig(store webhook.WebhookStore, cfg Config) http.Handler {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxSkew <= 0 {
		cfg.MaxSkew = 5 * time.Minute
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 1 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	api := &API{now: cfg.Now, maxSkew: cfg.MaxSkew, maxBody: cfg.MaxBody, logger: cfg.Logger}
	if full, ok := store.(ServiceStore); ok {
		api.store = full
	}
	r := chi.NewRouter()
	r.Use(api.requestID)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Post("/v1/endpoints", api.createEndpoint)
	r.Post("/v1/endpoints/{endpoint}/keys", api.rotateKey)
	r.Get("/v1/endpoints/{endpoint}/events", api.listEvents)
	r.Post("/v1/endpoints/{endpoint}/events/{eventID}/replay", api.replayEvent)
	r.Post("/v1/endpoints/{endpoint}/events", api.receiveEvent)
	return r
}

func (a *API) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			http.Error(w, "request id failure", http.StatusInternalServerError)
			return
		}
		id := hex.EncodeToString(raw)
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func (a *API) requireStore(w http.ResponseWriter, r *http.Request) ServiceStore {
	if a.store == nil {
		a.writeError(w, r, http.StatusServiceUnavailable, "unsupported_store", "persistent store is required")
		return nil
	}
	return a.store
}

func (a *API) createEndpoint(w http.ResponseWriter, r *http.Request) {
	store := a.requireStore(w, r)
	if store == nil {
		return
	}
	var req createEndpointRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	endpoint, _, err := store.CreateEndpoint(r.Context(), webhook.EndpointInput{ID: req.ID, Tenant: req.Tenant, URL: req.URL}, webhook.KeyInput{KeyID: req.KeyID, Secret: req.Secret})
	if err != nil {
		a.handleStoreError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusCreated, endpointResponse{ID: endpoint.ID, Tenant: endpoint.Tenant, URL: endpoint.URL, Active: endpoint.Active})
}

func (a *API) rotateKey(w http.ResponseWriter, r *http.Request) {
	store := a.requireStore(w, r)
	if store == nil {
		return
	}
	var req rotateKeyRequest
	if !a.decodeJSON(w, r, &req) {
		return
	}
	key, err := store.RotateKey(r.Context(), req.Tenant, chi.URLParam(r, "endpoint"), webhook.KeyInput{KeyID: req.KeyID, Secret: req.Secret})
	if err != nil {
		a.handleStoreError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusOK, keyResponse{ID: key.ID, Active: key.Active})
}

func (a *API) receiveEvent(w http.ResponseWriter, r *http.Request) {
	store := a.requireStore(w, r)
	if store == nil {
		return
	}
	tenant := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	endpointID := chi.URLParam(r, "endpoint")
	eventID := strings.TrimSpace(r.Header.Get("X-Webhook-Id"))
	timestampText := strings.TrimSpace(r.Header.Get("X-Webhook-Timestamp"))
	keyID := strings.TrimSpace(r.Header.Get("X-Webhook-Key-Id"))
	signature := strings.TrimSpace(r.Header.Get("X-Webhook-Signature"))
	orderingKey := strings.TrimSpace(r.Header.Get("X-Webhook-Ordering-Key"))
	if tenant == "" || eventID == "" || timestampText == "" || keyID == "" || signature == "" {
		a.writeError(w, r, http.StatusUnauthorized, "invalid_signature", "missing required webhook headers")
		return
	}
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || absDuration(a.now().Sub(time.Unix(timestamp, 0))) > a.maxSkew {
		a.writeError(w, r, http.StatusUnauthorized, "invalid_timestamp", "webhook timestamp is outside accepted window")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.maxBody))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			a.writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "request body is too large")
		} else {
			a.writeError(w, r, http.StatusBadRequest, "invalid_body", "request body could not be read")
		}
		return
	}
	endpoint, err := store.Endpoint(r.Context(), tenant, endpointID)
	if err != nil {
		a.handleStoreError(w, r, err)
		return
	}
	if !endpoint.Active {
		a.writeError(w, r, http.StatusNotFound, "endpoint_inactive", "endpoint is not active")
		return
	}
	key, err := store.ActiveKey(r.Context(), tenant, endpointID, keyID)
	if err != nil || !webhook.VerifySignature(key.Secret, timestampText, body, signature, a.now(), a.maxSkew) {
		a.writeError(w, r, http.StatusUnauthorized, "invalid_signature", "webhook signature verification failed")
		return
	}
	event, deduped, err := store.ReceiveEvent(r.Context(), webhook.EventInput{ID: eventID, Tenant: tenant, EndpointID: endpointID, OrderingKey: orderingKey, Payload: body, Signature: signature, KeyID: keyID, Timestamp: timestamp})
	if err != nil {
		a.handleStoreError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusAccepted, acceptResponse{ID: event.ID, Dedupe: deduped, Status: event.Status})
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	store := a.requireStore(w, r)
	if store == nil {
		return
	}
	tenant := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	if tenant == "" {
		a.writeError(w, r, http.StatusUnauthorized, "missing_tenant", "X-Tenant-Id is required")
		return
	}
	events, err := store.ListEvents(r.Context(), tenant, chi.URLParam(r, "endpoint"), 100)
	if err != nil {
		a.handleStoreError(w, r, err)
		return
	}
	out := make([]eventResponse, 0, len(events))
	for _, event := range events {
		out = append(out, toEventResponse(event))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

func (a *API) replayEvent(w http.ResponseWriter, r *http.Request) {
	store := a.requireStore(w, r)
	if store == nil {
		return
	}
	tenant := strings.TrimSpace(r.Header.Get("X-Tenant-Id"))
	if tenant == "" {
		a.writeError(w, r, http.StatusUnauthorized, "missing_tenant", "X-Tenant-Id is required")
		return
	}
	delivery, err := store.ReplayEvent(r.Context(), tenant, chi.URLParam(r, "endpoint"), chi.URLParam(r, "eventID"))
	if err != nil {
		a.handleStoreError(w, r, err)
		return
	}
	a.writeJSON(w, http.StatusAccepted, deliveryResponse{Attempt: delivery.Attempt, NextAttempt: delivery.NextAttempt, Status: string(delivery.Status)})
}

func toEventResponse(event webhook.EventRecord) eventResponse {
	return eventResponse{ID: event.ID, EndpointID: event.EndpointID, OrderingKey: event.OrderingKey, KeyID: event.KeyID, SignedAt: event.SignedAt, ReceivedAt: event.ReceivedAt, Status: event.Status, Delivery: deliveryResponse{Attempt: event.Delivery.Attempt, NextAttempt: event.Delivery.NextAttempt, Status: string(event.Delivery.Status), LastCode: event.Delivery.LastCode}}
}

func (a *API) decodeJSON(w http.ResponseWriter, r *http.Request, req any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, a.maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		a.writeError(w, r, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return false
	}
	return true
}

func (a *API) handleStoreError(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.Printf("request failed request_id=%s", requestID(r))
	switch {
	case errors.Is(err, webhook.ErrNotFound):
		a.writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, webhook.ErrConflict):
		a.writeError(w, r, http.StatusConflict, "conflict", "same event id was already submitted with different content")
	case errors.Is(err, webhook.ErrLimitExceeded):
		a.writeError(w, r, http.StatusTooManyRequests, "unfinished_limit", "too many unfinished events")
	case errors.Is(err, webhook.ErrInvalidEndpoint):
		a.writeError(w, r, http.StatusBadRequest, "invalid_endpoint", "endpoint is invalid")
	default:
		a.writeError(w, r, http.StatusInternalServerError, "internal_error", "request failed")
	}
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func (a *API) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	a.writeJSON(w, status, errorResponse{Code: code, Message: message, RequestID: requestID(r)})
}

func (a *API) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
