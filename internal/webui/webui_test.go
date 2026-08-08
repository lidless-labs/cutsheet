package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidless-labs/cutsheet/web"
)

func TestHandlerServesIndex(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET / Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), `<div id="root">`) {
		t.Errorf("GET / body does not look like the SPA shell")
	}
}

func TestHandlerClientRouteFallback(t *testing.T) {
	for _, path := range []string{"/devices", "/settings", "/changes/42"} {
		rec := httptest.NewRecorder()
		Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200 (index fallback)", path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), `<div id="root">`) {
			t.Errorf("GET %s did not serve the SPA shell", path)
		}
	}
}

func TestHandlerMissingAssetIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/nope.js", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /assets/nope.js status = %d, want 404", rec.Code)
	}
}

func TestHandlerServesStaticAssetWithContentType(t *testing.T) {
	// Find a real built asset inside the embedded dist so the test does not
	// depend on hashed file names.
	var jsAsset, cssAsset string
	err := fs.WalkDir(web.Dist, "dist/assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case strings.HasSuffix(path, ".js") && jsAsset == "":
			jsAsset = strings.TrimPrefix(path, "dist")
		case strings.HasSuffix(path, ".css") && cssAsset == "":
			cssAsset = strings.TrimPrefix(path, "dist")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded dist: %v", err)
	}
	if jsAsset == "" || cssAsset == "" {
		t.Fatalf("embedded dist has no js/css assets (js=%q css=%q)", jsAsset, cssAsset)
	}

	cases := []struct {
		path   string
		wantCT string
	}{
		{jsAsset, "text/javascript"},
		{cssAsset, "text/css"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", tc.path, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, tc.wantCT) {
			t.Errorf("GET %s Content-Type = %q, want prefix %q", tc.path, ct, tc.wantCT)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s returned an empty body", tc.path)
		}
	}
}

func TestRootDoesNotShadowAPI(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"api":true}`))
	})
	root := Root(api)

	for _, path := range []string{"/api/v1/devices", "/api/v1/changes/1/reports/report.html", "/healthz"} {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusTeapot {
			t.Errorf("GET %s status = %d, want %d (API handler)", path, rec.Code, http.StatusTeapot)
		}
		if !strings.Contains(rec.Body.String(), `"api":true`) {
			t.Errorf("GET %s was not handled by the API handler", path)
		}
	}
}

func TestRootServesSPAForNonAPIPaths(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("API handler should not see %s", r.URL.Path)
	})
	root := Root(api)

	for _, path := range []string{"/", "/devices", "/changes/7"} {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `<div id="root">`) {
			t.Errorf("GET %s did not serve the SPA shell", path)
		}
	}
}
