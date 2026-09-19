// Package api exposes the public v1 HTTP adapter over the scanner library.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/itsmangooo/weedout-engine/pkg/model"
	"github.com/itsmangooo/weedout-engine/pkg/scanner"
)

type Server struct {
	scanner scanner.Scanner
	version string
	maxBody int64
	logger  *slog.Logger
}

func New(engine scanner.Scanner, version string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{scanner: engine, version: version, maxBody: 10 << 20, logger: logger}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /version", s.build)
	mux.HandleFunc("POST /v1/scan", s.scan)
	return securityHeaders(mux)
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.version})
}
func (s *Server) build(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"engine": "weedout-engine", "version": s.version, "schema_version": model.SchemaVersion})
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request model.ScanRequest
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scan request: " + err.Error()})
		return
	}
	if request.SchemaVersion != "" && request.SchemaVersion != model.SchemaVersion {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported schema_version"})
		return
	}
	if len(request.Manifests) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one manifest is required"})
		return
	}
	result, err := s.scanner.Scan(r.Context(), request)
	if err != nil {
		s.logger.Error("scan failed", "error", err)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/v1/") && r.Method != "POST" {
			w.Header().Set("Allow", "POST")
		}
		next.ServeHTTP(w, r)
	})
}
