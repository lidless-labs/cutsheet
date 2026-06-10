package api

import (
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

// recovery converts handler panics into a 500 envelope instead of a dropped
// connection, logging the stack.
func (s *Server) recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.cfg.Logger.Error("handler panic",
					"method", r.Method, "path", r.URL.Path,
					"panic", rec, "stack", string(debug.Stack()))
				// Best effort: if the handler already wrote headers this is a
				// no-op write on a broken response, which is all we can do.
				writeError(w, http.StatusInternalServerError, "internal", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response status for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// logging emits one slog line per request.
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.cfg.Logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(start).Milliseconds())
	})
}

// cors handles cross-origin requests for the configured UI dev-server origin.
// Same-origin traffic is unaffected (browsers do not gate it on these
// headers). Preflight OPTIONS requests are answered here, before auth,
// because preflights never carry Authorization headers.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.cfg.CORSOrigin != "" && origin == s.cfg.CORSOrigin {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "300")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auth enforces bearer-token authentication on everything except /healthz.
//
// First-run mode: while zero tokens exist, unauthenticated requests are
// allowed from loopback addresses only, so `cutsheet serve` is immediately
// usable on the box it runs on. Creating the first token (cutsheet token
// create) closes that door for every route at the next request.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/api/v1/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		n, err := s.cfg.Store.CountTokens(r.Context())
		if err != nil {
			s.cfg.Logger.Error("token count failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "auth check failed")
			return
		}
		if n == 0 {
			if remoteIsLoopback(r.RemoteAddr) {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusUnauthorized, "unauthorized",
				"no API tokens exist; only localhost may connect until one is created (cutsheet token create)")
			return
		}

		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		ok, err := s.cfg.Store.ValidateToken(r.Context(), token)
		if err != nil {
			s.cfg.Logger.Error("token validation failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "auth check failed")
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// remoteIsLoopback reports whether addr (an http.Request.RemoteAddr,
// host:port) is a loopback IP. Unparsable addresses are not loopback.
func remoteIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
