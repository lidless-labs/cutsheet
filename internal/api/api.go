// Package api serves the Cutsheet REST API over net/http. It is a thin,
// stdlib-only layer (Go 1.22 method patterns on http.ServeMux, no router
// dependency) over internal/store; collection and analysis stay in the serve
// command and are reached through the injected SnapshotNow callback.
//
// Authentication is bearer-token based with a deliberate first-run mode:
// while zero API tokens exist, requests from loopback addresses are allowed
// unauthenticated so a fresh single-host install works without ceremony. The
// moment the first token is created (cutsheet token create), every request
// from anywhere must present a valid token. /healthz is always open.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/solomonneas/cutsheet/internal/secrets"
	"github.com/solomonneas/cutsheet/internal/store"
)

// SnapshotNow triggers an immediate collect+save+analyze for one device and
// returns the recorded change. changed is false (with a nil change) when the
// fetched config was identical to the latest snapshot. The serve command owns
// the collector/snapshot/pipeline wiring and injects this.
type SnapshotNow func(ctx context.Context, deviceID string) (*store.Change, bool, error)

// Config wires a Server. Store is required; everything else is optional.
type Config struct {
	Store *store.Store
	// SnapshotNow handles POST /devices/{id}/snapshot. Nil returns 501.
	SnapshotNow SnapshotNow
	// Secrets encrypts credential fields on device create/update. Nil is fine
	// until a credential-bearing collector type is registered via the API.
	Secrets *secrets.Box
	// DevicesChanged is invoked after any successful device create, update,
	// or delete so the serve loop can reconcile the scheduler.
	DevicesChanged func()
	// CORSOrigin, when non-empty, is the single allowed cross-origin Origin
	// value (for a UI dev server). Same-origin requests never need it.
	CORSOrigin string
	Version    string
	Logger     *slog.Logger
}

// Server is the REST API handler set.
type Server struct {
	cfg Config
}

// New builds the API http.Handler: routes plus recovery, logging, CORS, and
// auth middleware.
func New(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	s := &Server{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/v1/healthz", s.handleHealthz)

	mux.HandleFunc("GET /api/v1/devices", s.handleDeviceList)
	mux.HandleFunc("POST /api/v1/devices", s.handleDeviceCreate)
	mux.HandleFunc("GET /api/v1/devices/{id}", s.handleDeviceGet)
	mux.HandleFunc("PATCH /api/v1/devices/{id}", s.handleDevicePatch)
	mux.HandleFunc("DELETE /api/v1/devices/{id}", s.handleDeviceDelete)
	mux.HandleFunc("POST /api/v1/devices/{id}/snapshot", s.handleSnapshotNow)

	mux.HandleFunc("GET /api/v1/changes", s.handleChangeList)
	mux.HandleFunc("GET /api/v1/changes/{id}", s.handleChangeGet)
	mux.HandleFunc("GET /api/v1/changes/{id}/reports", s.handleReportList)
	mux.HandleFunc("GET /api/v1/changes/{id}/reports/{name}", s.handleReportFile)

	var h http.Handler = mux
	h = s.auth(h)
	h = s.cors(h)
	h = s.logging(h)
	h = s.recovery(h)
	return h
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.cfg.Version})
}

// errorBody is the consistent error envelope:
// {"error": {"code": "...", "message": "..."}}.
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// writeStoreError maps store errors onto the envelope: ErrNotFound becomes
// 404, anything else a 500 with a generic message (details go to the log via
// the caller, not the wire).
func (s *Server) writeStoreError(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	s.cfg.Logger.Error("store operation failed", "op", op, "error", err)
	writeError(w, http.StatusInternalServerError, "internal", op+" failed")
}

// decodeBody strictly decodes a JSON request body into v.
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// queryInt parses an integer query parameter, returning def when absent.
func queryInt(r *http.Request, name string, def int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, errors.New("invalid " + name + ": not an integer")
	}
	return n, nil
}

func validSeverity(s string) bool {
	switch s {
	case "none", "low", "medium", "high":
		return true
	}
	return false
}

// bearerToken extracts the token from an Authorization: Bearer header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}
