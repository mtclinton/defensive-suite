package respond

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// Handler is the HTTP surface served on the agentd response socket. It exposes
// POST /respond (bearer-authed) → Responder.Respond → Result JSON, and an
// unauthenticated GET /healthz. The token gates /respond; an empty token fails
// closed (responses are rejected). maxBody bounds the request body.
type Handler struct {
	resp    *Responder
	token   string
	maxBody int64
	mux     *http.ServeMux
}

// NewHandler wires resp behind bearer auth. token is the response-socket bearer
// token; maxBody bounds the request body (<=0 → a 64 KiB default).
func NewHandler(resp *Responder, token string, maxBody int64) *Handler {
	if maxBody <= 0 {
		maxBody = 64 << 10
	}
	h := &Handler{resp: resp, token: token, maxBody: maxBody, mux: http.NewServeMux()}
	h.mux.HandleFunc("/respond", h.handleRespond)
	h.mux.HandleFunc("/healthz", h.handleHealth)
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

func (h *Handler) handleRespond(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.token == "" {
		http.Error(w, "respond disabled: response token not configured", http.StatusServiceUnavailable)
		return
	}
	if !authOK(r, h.token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBody)
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Action == "" || req.Target == "" {
		http.Error(w, "request missing action/target", http.StatusBadRequest)
		return
	}
	res := h.resp.Respond(req)
	writeJSON(w, http.StatusOK, res)
}

// authOK does a constant-time comparison of the bearer token, matching the
// collector's scheme.
func authOK(r *http.Request, token string) bool {
	got := r.Header.Get("Authorization")
	want := "Bearer " + token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
