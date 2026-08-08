// Package webui serves the embedded single-page UI built from web/. It owns
// the SPA serving rules: real files from the embedded dist/ are served as-is,
// client-route paths fall back to index.html, and the API and health
// endpoints are never shadowed.
package webui

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/lidless-labs/cutsheet/web"
)

// Root composes the full server handler: /api/ and /healthz go to the REST
// API handler (with all of its middleware), everything else is the SPA. The
// API routes are matched by prefix here, before the SPA fallback can ever see
// them, so a client route can never shadow an API path or vice versa.
func Root(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.Handle("/healthz", api)
	mux.Handle("/", Handler())
	return mux
}

// Handler serves the embedded UI with index.html fallback for client routes.
func Handler() http.Handler {
	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		// The embed is resolved at compile time; a missing dist subdirectory
		// means the binary was built from a broken tree.
		panic("webui: embedded dist missing: " + err.Error())
	}
	fileServer := http.FileServerFS(dist)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(dist, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Not a real file. Paths that look like assets (have an extension)
		// get a real 404; everything else is a client route and gets the SPA
		// shell so deep links and refreshes work.
		if base := path[strings.LastIndex(path, "/")+1:]; strings.Contains(base, ".") {
			http.NotFound(w, r)
			return
		}
		index, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			http.Error(w, "ui not built", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(index)
		}
	})
}
