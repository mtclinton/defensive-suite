// Package server is the collector's HTTP surface: a bearer-authed /ingest
// endpoint for the tools to POST their Report JSON, read-only /api/* endpoints
// the dashboard consumes, and the embedded dashboard itself.
package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/mtclinton/defensive-suite/collector/internal/store"
)

// Server wires the store and config into an http.Handler.
type Server struct {
	store     *store.Store
	token     string
	maxBody   int64
	dashboard []byte
	mux       *http.ServeMux
}

// New builds the handler. token gates /ingest (empty = ingest disabled).
// dashboard is the embedded index.html served at "/".
func New(st *store.Store, token string, maxBody int64, dashboard []byte) *Server {
	s := &Server{store: st, token: token, maxBody: maxBody, dashboard: dashboard, mux: http.NewServeMux()}
	s.mux.HandleFunc("/ingest", s.handleIngest)
	s.mux.HandleFunc("/api/findings", s.handleFindings)
	s.mux.HandleFunc("/api/summary", s.handleSummary)
	s.mux.HandleFunc("/api/reports", s.handleReports)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("/", s.handleRoot)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// authOK does a constant-time comparison of the bearer token.
func authOK(r *http.Request, token string) bool {
	got := r.Header.Get("Authorization")
	want := "Bearer " + token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.token == "" {
		http.Error(w, "ingest disabled: collector token not configured", http.StatusServiceUnavailable)
		return
	}
	if !authOK(r, s.token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	var rep store.Report
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		http.Error(w, "bad report: "+err.Error(), http.StatusBadRequest)
		return
	}
	if rep.Tool == "" {
		http.Error(w, "report missing \"tool\"", http.StatusBadRequest)
		return
	}
	s.store.AddReport(rep)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted", "tool": rep.Tool, "findings": len(rep.Findings)})
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	f := store.Filter{Tool: q.Get("tool"), Severity: q.Get("severity"), Host: q.Get("host")}
	findings := s.store.LatestFindings(f)
	if findings == nil {
		findings = []store.Finding{}
	}
	writeJSON(w, http.StatusOK, findings)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.store.Summary())
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			limit = n
		}
	}
	reports := s.store.Recent(limit)
	if reports == nil {
		reports = []store.Report{}
	}
	writeJSON(w, http.StatusOK, reports)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	if len(s.dashboard) == 0 {
		http.Error(w, "dashboard not embedded", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(s.dashboard))
}
