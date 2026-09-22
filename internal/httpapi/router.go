package httpapi

import (
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

func NewRouter(store webhook.WebhookStore) http.Handler {
    r := chi.NewRouter()
    r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
    r.Post("/v1/endpoints/{endpoint}/events", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "not implemented", http.StatusNotImplemented) })
    return r
}
