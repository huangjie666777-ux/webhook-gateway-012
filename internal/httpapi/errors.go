package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "req-unknown"
	}
	return "req_" + hex.EncodeToString(b)
}

func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSON(w, errorBody{Code: code, Message: message, RequestID: requestID})
}

func mapStoreError(w http.ResponseWriter, err error, requestID string) {
	status, code, message := http.StatusInternalServerError, "internal_error", "internal server error"
	switch {
	case errors.Is(err, webhook.ErrNotFound):
		status, code, message = http.StatusNotFound, "not_found", "resource not found"
	case errors.Is(err, webhook.ErrConflict):
		status, code, message = http.StatusConflict, "event_conflict", "event id was already used with different content"
	case errors.Is(err, webhook.ErrInvalidSignature):
		status, code, message = http.StatusUnauthorized, "invalid_signature", "signature verification failed"
	case errors.Is(err, webhook.ErrInactiveKey):
		status, code, message = http.StatusUnauthorized, "inactive_key", "signing key is not active"
	case errors.Is(err, webhook.ErrTimestampSkew):
		status, code, message = http.StatusUnauthorized, "invalid_timestamp", "timestamp outside accepted window"
	case errors.Is(err, webhook.ErrIncompleteHeaders):
		status, code, message = http.StatusBadRequest, "missing_headers", "required signed headers are missing"
	case errors.Is(err, webhook.ErrTooManyPending):
		status, code, message = http.StatusServiceUnavailable, "too_many_pending", "endpoint has too many unfinished events"
	case errors.Is(err, webhook.ErrInvalidURL):
		status, code, message = http.StatusBadRequest, "invalid_url", "endpoint url is not allowed"
	}
	writeError(w, status, code, message, requestID)
}
