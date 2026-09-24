package httpapi

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

type eventResponse struct {
	ID          string `json:"id"`
	EndpointID  string `json:"endpoint_id"`
	OrderingKey string `json:"ordering_key"`
	Payload     string `json:"payload_base64"`
	KeyID       string `json:"key_id"`
	ReceivedAt  int64  `json:"received_at"`
	Status      string `json:"status"`
}

func toEventResponse(ev webhook.Event) eventResponse {
	return eventResponse{
		ID:          ev.ID,
		EndpointID:  ev.EndpointID,
		OrderingKey: ev.EventKey,
		Payload:     base64.StdEncoding.EncodeToString(ev.Payload),
		KeyID:       ev.KeyID,
		ReceivedAt:  ev.ReceivedAt,
		Status:      string(ev.Status),
	}
}

func (rt *Router) receiveEvent(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	rid := requestIDFrom(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, rt.cfg.MaxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the limit", rid)
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_body", "could not read request body", rid)
		return
	}
	eventID := strings.TrimSpace(r.Header.Get("X-Webhook-Id"))
	timestampRaw := strings.TrimSpace(r.Header.Get("X-Webhook-Timestamp"))
	keyID := strings.TrimSpace(r.Header.Get("X-Webhook-Key-Id"))
	signature := strings.TrimSpace(r.Header.Get("X-Webhook-Signature"))
	if eventID == "" || timestampRaw == "" || keyID == "" || signature == "" {
		writeError(w, http.StatusBadRequest, "missing_headers", "X-Webhook-Id, X-Webhook-Timestamp, X-Webhook-Key-Id and X-Webhook-Signature are required", rid)
		return
	}
	ts, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil || ts <= 0 {
		writeError(w, http.StatusUnauthorized, "invalid_timestamp", "timestamp must be unix seconds", rid)
		return
	}
	diff := rt.cfg.Now().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > rt.cfg.TimestampSkew {
		writeError(w, http.StatusUnauthorized, "invalid_timestamp", "timestamp outside accepted window", rid)
		return
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	ev, duplicate, err := store.AcceptEvent(r.Context(), webhook.InboundEvent{
		EndpointID:  chi.URLParam(r, "endpoint"),
		EventID:     eventID,
		KeyID:       keyID,
		Timestamp:   ts,
		OrderingKey: r.Header.Get("X-Webhook-Ordering-Key"),
		ContentType: ct,
		Payload:     raw,
		Signature:   signature,
	})
	if err != nil {
		mapStoreError(w, err, rid)
		return
	}
	if duplicate {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
	writeJSON(w, map[string]any{"event": toEventResponse(ev), "duplicate": duplicate})
}

func (rt *Router) listEvents(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	limit := parseLimit(r.URL.Query().Get("limit"), 100)
	events, err := store.ListEvents(r.Context(), tenant, chi.URLParam(r, "endpoint"), limit)
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	out := make([]eventResponse, 0, len(events))
	for _, ev := range events {
		out = append(out, toEventResponse(ev))
	}
	writeJSON(w, map[string]any{"events": out})
}

func (rt *Router) getEvent(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	ev, err := store.GetEvent(r.Context(), tenant, chi.URLParam(r, "endpoint"), chi.URLParam(r, "event"))
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	writeJSON(w, map[string]any{"event": toEventResponse(ev)})
}

func (rt *Router) replayEvent(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	err := store.ReplayEvent(r.Context(), tenant, chi.URLParam(r, "endpoint"), chi.URLParam(r, "event"))
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]any{"status": "queued"})
}
