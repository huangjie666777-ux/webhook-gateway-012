package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/huangjie666777-ux/webhook-gateway-012/internal/webhook"
)

type endpointRequest struct {
	URL string `json:"url"`
}

type endpointResponse struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

type keyResponse struct {
	ID         string `json:"id"`
	EndpointID string `json:"endpoint_id"`
	Secret     string `json:"secret,omitempty"`
	Active     bool   `json:"active"`
	CreatedAt  int64  `json:"created_at"`
}

func toEndpointResponse(ep webhook.Endpoint) endpointResponse {
	return endpointResponse{ID: ep.ID, Tenant: ep.Tenant, URL: ep.URL, Active: ep.Active}
}

func toKeyResponse(k webhook.SigningKey, includeSecret bool) keyResponse {
	resp := keyResponse{ID: k.ID, EndpointID: k.EndpointID, Active: k.Active, CreatedAt: k.CreatedAt}
	if includeSecret {
		resp.Secret = k.Secret
	}
	return resp
}

func (rt *Router) createEndpoint(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	var req endpointRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be JSON with a url", requestIDFrom(r.Context()))
		return
	}
	ep, key, err := store.CreateEndpoint(r.Context(), tenant, req.URL)
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"endpoint": toEndpointResponse(ep), "key": toKeyResponse(key, true)})
}

func (rt *Router) listEndpoints(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	eps, err := store.ListEndpoints(r.Context(), tenant)
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	out := make([]endpointResponse, 0, len(eps))
	for _, ep := range eps {
		out = append(out, toEndpointResponse(ep))
	}
	writeJSON(w, map[string]any{"endpoints": out})
}

func (rt *Router) getEndpoint(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	ep, err := store.GetEndpoint(r.Context(), tenant, chi.URLParam(r, "endpoint"))
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	writeJSON(w, map[string]any{"endpoint": toEndpointResponse(ep)})
}

type createKeyRequest struct {
	Rotate bool `json:"rotate"`
}

func (rt *Router) createKey(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	var req createKeyRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body must be JSON", requestIDFrom(r.Context()))
			return
		}
	}
	key, err := store.CreateKey(r.Context(), tenant, chi.URLParam(r, "endpoint"), req.Rotate)
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"key": toKeyResponse(key, true)})
}

func (rt *Router) deactivateKey(w http.ResponseWriter, r *http.Request) {
	store, ok := rt.requireStore(w, r)
	if !ok {
		return
	}
	tenant, ok := rt.requireTenant(w, r)
	if !ok {
		return
	}
	err := store.DeactivateKey(r.Context(), tenant, chi.URLParam(r, "endpoint"), chi.URLParam(r, "key"))
	if err != nil {
		mapStoreError(w, err, requestIDFrom(r.Context()))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
