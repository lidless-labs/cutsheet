package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solomonneas/cutsheet/internal/secrets"
	"github.com/solomonneas/cutsheet/internal/store"
)

// newTestStore opens a fresh store in a temp dir.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "cutsheet.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newTestServer(t *testing.T, mutate func(*Config)) (http.Handler, *store.Store) {
	t.Helper()
	st := newTestStore(t)
	cfg := Config{Store: st, Version: "test", Logger: discardLogger()}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg), st
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// do issues a request against the handler. The remote address defaults to
// loopback so the zero-token first-run mode applies; override via opts.
func do(t *testing.T, h http.Handler, method, target, body string, opts ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.RemoteAddr = "127.0.0.1:54321"
	for _, opt := range opts {
		opt(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func fromAddr(addr string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

func withBearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return v
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, want, rec.Body.String())
	}
}

func wantErrorCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	wantStatus(t, rec, status)
	body := decode[errorBody](t, rec)
	if body.Error.Code != code {
		t.Fatalf("error code = %q, want %q (body: %s)", body.Error.Code, code, rec.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	h, _ := newTestServer(t, nil)
	for _, path := range []string{"/healthz", "/api/v1/healthz"} {
		// Healthz needs no auth even from non-loopback with zero tokens.
		rec := do(t, h, "GET", path, "", fromAddr("192.0.2.7:9999"))
		wantStatus(t, rec, http.StatusOK)
		got := decode[map[string]string](t, rec)
		if got["status"] != "ok" || got["version"] != "test" {
			t.Fatalf("%s body: %v", path, got)
		}
	}
}

const fileDeviceBody = `{"id":"gw1","name":"Gateway","vendor":"edgeos","address":"198.18.0.1","collector_type":"file","collector_config":{"path":"/var/lib/cutsheet/fixtures/gw1.cfg"},"poll_interval_seconds":600}`

func TestDeviceCRUD(t *testing.T) {
	refreshed := 0
	h, _ := newTestServer(t, func(c *Config) {
		c.DevicesChanged = func() { refreshed++ }
	})

	// Create.
	rec := do(t, h, "POST", "/api/v1/devices", fileDeviceBody)
	wantStatus(t, rec, http.StatusCreated)
	created := decode[deviceJSON](t, rec)
	if created.ID != "gw1" || created.Name != "Gateway" || created.Vendor != "edgeos" ||
		created.PollIntervalSeconds != 600 || !created.Enabled {
		t.Fatalf("created device: %+v", created)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("timestamps not set: %+v", created)
	}

	// Duplicate id conflicts.
	rec = do(t, h, "POST", "/api/v1/devices", fileDeviceBody)
	wantErrorCode(t, rec, http.StatusConflict, "conflict")

	// Get.
	rec = do(t, h, "GET", "/api/v1/devices/gw1", "")
	wantStatus(t, rec, http.StatusOK)
	got := decode[deviceJSON](t, rec)
	if got.ID != "gw1" || string(got.CollectorConfig) == "" {
		t.Fatalf("get device: %+v", got)
	}

	// List.
	rec = do(t, h, "GET", "/api/v1/devices", "")
	wantStatus(t, rec, http.StatusOK)
	list := decode[map[string][]deviceJSON](t, rec)
	if len(list["devices"]) != 1 {
		t.Fatalf("list devices: %+v", list)
	}

	// Patch a subset of fields.
	rec = do(t, h, "PATCH", "/api/v1/devices/gw1", `{"name":"Edge GW","poll_interval_seconds":120,"enabled":false}`)
	wantStatus(t, rec, http.StatusOK)
	patched := decode[deviceJSON](t, rec)
	if patched.Name != "Edge GW" || patched.PollIntervalSeconds != 120 || patched.Enabled {
		t.Fatalf("patched device: %+v", patched)
	}
	if patched.Vendor != "edgeos" || patched.Address != "198.18.0.1" {
		t.Fatalf("patch clobbered untouched fields: %+v", patched)
	}

	// Delete.
	rec = do(t, h, "DELETE", "/api/v1/devices/gw1", "")
	wantStatus(t, rec, http.StatusNoContent)
	rec = do(t, h, "GET", "/api/v1/devices/gw1", "")
	wantErrorCode(t, rec, http.StatusNotFound, "not_found")
	rec = do(t, h, "DELETE", "/api/v1/devices/gw1", "")
	wantErrorCode(t, rec, http.StatusNotFound, "not_found")

	if refreshed != 3 { // create + patch + delete
		t.Fatalf("DevicesChanged fired %d times, want 3", refreshed)
	}
}

func TestDeviceCreateDefaults(t *testing.T) {
	h, _ := newTestServer(t, nil)
	rec := do(t, h, "POST", "/api/v1/devices", `{"id":"sw1","collector_config":{"path":"/tmp/sw1.cfg"}}`)
	wantStatus(t, rec, http.StatusCreated)
	d := decode[deviceJSON](t, rec)
	if d.Name != "sw1" || d.Vendor != "auto" || d.CollectorType != "file" ||
		d.PollIntervalSeconds != 300 || !d.Enabled {
		t.Fatalf("defaults: %+v", d)
	}
}

func TestDeviceCreateValidation(t *testing.T) {
	h, _ := newTestServer(t, nil)
	tests := []struct {
		name string
		body string
	}{
		{"missing id", `{"collector_config":{"path":"/tmp/x.cfg"}}`},
		{"bad id", `{"id":"bad id!","collector_config":{"path":"/tmp/x.cfg"}}`},
		{"unknown collector", `{"id":"x1","collector_type":"carrier-pigeon"}`},
		{"invalid collector config", `{"id":"x1","collector_type":"file","collector_config":{"path":""}}`},
		{"negative interval", `{"id":"x1","collector_config":{"path":"/tmp/x.cfg"},"poll_interval_seconds":-5}`},
		{"not json", `{{{`},
		{"unknown field", `{"id":"x1","collector_config":{"path":"/tmp/x.cfg"},"bogus":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, h, "POST", "/api/v1/devices", tt.body)
			wantErrorCode(t, rec, http.StatusBadRequest, "bad_request")
		})
	}
}

func TestDeviceSecretRedaction(t *testing.T) {
	dataDir := t.TempDir()
	box, err := secrets.Open(dataDir)
	if err != nil {
		t.Fatalf("open secrets: %v", err)
	}
	h, st := newTestServer(t, func(c *Config) { c.Secrets = box })

	body := `{"id":"edge1","collector_type":"ssh","collector_config":{"host":"192.0.2.10","username":"admin","password":"hunter2","preset":"edgeos","insecure_ignore_host_key":true}}`
	rec := do(t, h, "POST", "/api/v1/devices", body)
	wantStatus(t, rec, http.StatusCreated)
	created := decode[deviceJSON](t, rec)

	var cfg map[string]any
	if err := json.Unmarshal(created.CollectorConfig, &cfg); err != nil {
		t.Fatalf("parse returned config: %v", err)
	}
	if cfg["password"] != "***" {
		t.Fatalf("password in response = %v, want ***", cfg["password"])
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatal("plaintext password leaked in create response")
	}

	// Stored config is encrypted, not plaintext and not the redaction marker.
	stored, err := st.GetDevice(context.Background(), "edge1")
	if err != nil {
		t.Fatalf("get stored device: %v", err)
	}
	var storedCfg map[string]any
	if err := json.Unmarshal([]byte(stored.CollectorConfig), &storedCfg); err != nil {
		t.Fatalf("parse stored config: %v", err)
	}
	encPassword, _ := storedCfg["password"].(string)
	if !strings.HasPrefix(encPassword, "enc:v1:") {
		t.Fatalf("stored password not encrypted: %q", encPassword)
	}

	// GET also redacts.
	rec = do(t, h, "GET", "/api/v1/devices/edge1", "")
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "enc:v1:") {
		t.Fatalf("GET leaked credentials: %s", rec.Body.String())
	}

	// PATCH that round-trips the redacted config keeps the stored credential.
	patchBody := fmt.Sprintf(`{"collector_config":%s}`, created.CollectorConfig)
	rec = do(t, h, "PATCH", "/api/v1/devices/edge1", patchBody)
	wantStatus(t, rec, http.StatusOK)
	after, err := st.GetDevice(context.Background(), "edge1")
	if err != nil {
		t.Fatalf("get device after patch: %v", err)
	}
	var afterCfg map[string]any
	if err := json.Unmarshal([]byte(after.CollectorConfig), &afterCfg); err != nil {
		t.Fatalf("parse config after patch: %v", err)
	}
	if afterCfg["password"] != encPassword {
		t.Fatalf("redacted PATCH replaced stored credential: %v", afterCfg["password"])
	}

	// PATCH with a new plaintext password re-encrypts it.
	rec = do(t, h, "PATCH", "/api/v1/devices/edge1", `{"collector_config":{"host":"192.0.2.10","username":"admin","password":"newpass","preset":"edgeos","insecure_ignore_host_key":true}}`)
	wantStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "newpass") {
		t.Fatal("new plaintext password leaked in PATCH response")
	}
	final, err := st.GetDevice(context.Background(), "edge1")
	if err != nil {
		t.Fatalf("get device after credential change: %v", err)
	}
	var finalCfg map[string]any
	if err := json.Unmarshal([]byte(final.CollectorConfig), &finalCfg); err != nil {
		t.Fatalf("parse final config: %v", err)
	}
	newEnc, _ := finalCfg["password"].(string)
	if !strings.HasPrefix(newEnc, "enc:v1:") || newEnc == encPassword {
		t.Fatalf("new password not re-encrypted: %q", newEnc)
	}
	plain, err := box.Decrypt(newEnc)
	if err != nil || string(plain) != "newpass" {
		t.Fatalf("decrypt new password: %q, %v", plain, err)
	}
}

func TestAuth(t *testing.T) {
	h, st := newTestServer(t, nil)

	// Zero tokens: loopback allowed, anything else denied.
	rec := do(t, h, "GET", "/api/v1/devices", "")
	wantStatus(t, rec, http.StatusOK)
	rec = do(t, h, "GET", "/api/v1/devices", "", fromAddr("192.0.2.7:1234"))
	wantErrorCode(t, rec, http.StatusUnauthorized, "unauthorized")

	// Create a token: now every route requires it, even from loopback.
	_, plaintext, err := st.CreateToken(context.Background(), "test")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	rec = do(t, h, "GET", "/api/v1/devices", "")
	wantErrorCode(t, rec, http.StatusUnauthorized, "unauthorized")
	rec = do(t, h, "GET", "/api/v1/devices", "", withBearer("cst_"+strings.Repeat("0", 64)))
	wantErrorCode(t, rec, http.StatusUnauthorized, "unauthorized")
	rec = do(t, h, "GET", "/api/v1/devices", "", fromAddr("192.0.2.7:1234"), withBearer(plaintext))
	wantStatus(t, rec, http.StatusOK)

	// Healthz stays open.
	rec = do(t, h, "GET", "/healthz", "", fromAddr("192.0.2.7:1234"))
	wantStatus(t, rec, http.StatusOK)
}

// seedChanges registers two devices and a ladder of changes for filter tests.
func seedChanges(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	for _, id := range []string{"gw1", "gw2"} {
		err := st.CreateDevice(ctx, store.Device{ID: id, Name: id, Vendor: "auto", CollectorType: "file", CollectorConfig: `{"path":"/tmp/x.cfg"}`})
		if err != nil {
			t.Fatalf("create device %s: %v", id, err)
		}
	}
	severities := []string{"none", "low", "medium", "high", "low", "high"}
	for i, sev := range severities {
		device := "gw1"
		if i%2 == 1 {
			device = "gw2"
		}
		_, err := st.RecordChange(ctx, store.Change{
			DeviceID:    device,
			CommitHash:  fmt.Sprintf("commit-%d", i),
			Summary:     fmt.Sprintf("change %d", i),
			MaxSeverity: sev,
			Findings: []store.Finding{
				{FindingID: fmt.Sprintf("RISK-%03d", i), Severity: sev, Title: "finding"},
			},
		})
		if err != nil {
			t.Fatalf("record change %d: %v", i, err)
		}
	}
}

func TestChangeList(t *testing.T) {
	h, st := newTestServer(t, nil)
	seedChanges(t, st)

	type listResp struct {
		Changes []changeJSON `json:"changes"`
		Limit   int          `json:"limit"`
		Offset  int          `json:"offset"`
	}

	rec := do(t, h, "GET", "/api/v1/changes", "")
	wantStatus(t, rec, http.StatusOK)
	all := decode[listResp](t, rec)
	if len(all.Changes) != 6 || all.Limit != 50 || all.Offset != 0 {
		t.Fatalf("default list: %+v", all)
	}
	// Newest first.
	if all.Changes[0].Summary != "change 5" {
		t.Fatalf("ordering: first = %+v", all.Changes[0])
	}

	rec = do(t, h, "GET", "/api/v1/changes?limit=2&offset=1", "")
	paged := decode[listResp](t, rec)
	if len(paged.Changes) != 2 || paged.Changes[0].Summary != "change 4" {
		t.Fatalf("paged list: %+v", paged)
	}

	rec = do(t, h, "GET", "/api/v1/changes?device_id=gw2", "")
	byDevice := decode[listResp](t, rec)
	if len(byDevice.Changes) != 3 {
		t.Fatalf("device filter: %+v", byDevice)
	}
	for _, c := range byDevice.Changes {
		if c.DeviceID != "gw2" {
			t.Fatalf("device filter leak: %+v", c)
		}
	}

	rec = do(t, h, "GET", "/api/v1/changes?min_severity=medium", "")
	bySev := decode[listResp](t, rec)
	if len(bySev.Changes) != 3 {
		t.Fatalf("severity filter: %+v", bySev)
	}
	for _, c := range bySev.Changes {
		if store.SeverityRank(c.MaxSeverity) < store.SeverityRank("medium") {
			t.Fatalf("severity filter leak: %+v", c)
		}
	}

	// Limit clamps to 500.
	rec = do(t, h, "GET", "/api/v1/changes?limit=9999", "")
	clamped := decode[listResp](t, rec)
	if clamped.Limit != 500 {
		t.Fatalf("limit clamp: %+v", clamped.Limit)
	}

	// Bad params.
	rec = do(t, h, "GET", "/api/v1/changes?limit=abc", "")
	wantErrorCode(t, rec, http.StatusBadRequest, "bad_request")
	rec = do(t, h, "GET", "/api/v1/changes?min_severity=catastrophic", "")
	wantErrorCode(t, rec, http.StatusBadRequest, "bad_request")
}

func TestChangeGet(t *testing.T) {
	h, st := newTestServer(t, nil)
	ctx := context.Background()
	if err := st.CreateDevice(ctx, store.Device{ID: "gw1", Name: "gw1", Vendor: "auto", CollectorType: "file", CollectorConfig: `{"path":"/tmp/x.cfg"}`}); err != nil {
		t.Fatalf("create device: %v", err)
	}
	id, err := st.RecordChange(ctx, store.Change{
		DeviceID:     "gw1",
		CommitHash:   "abc123",
		Summary:      "1 finding (1 high) - 1 block changed",
		MaxSeverity:  "high",
		AnalysisJSON: `{"risk_findings":[{"id":"RISK-001"}]}`,
		Findings:     []store.Finding{{FindingID: "RISK-001", Severity: "high", Category: "acl", Title: "ACL removed", Recommendation: "review"}},
	})
	if err != nil {
		t.Fatalf("record change: %v", err)
	}

	rec := do(t, h, "GET", fmt.Sprintf("/api/v1/changes/%d", id), "")
	wantStatus(t, rec, http.StatusOK)
	detail := decode[changeDetailJSON](t, rec)
	if detail.MaxSeverity != "high" || len(detail.Findings) != 1 || detail.Findings[0].FindingID != "RISK-001" {
		t.Fatalf("detail: %+v", detail)
	}
	if !strings.Contains(string(detail.Analysis), "RISK-001") {
		t.Fatalf("analysis not embedded: %s", detail.Analysis)
	}

	rec = do(t, h, "GET", "/api/v1/changes/999", "")
	wantErrorCode(t, rec, http.StatusNotFound, "not_found")
	rec = do(t, h, "GET", "/api/v1/changes/abc", "")
	wantErrorCode(t, rec, http.StatusBadRequest, "bad_request")
}

// seedReportChange records a change whose report dir contains servable and
// non-servable files, plus a "secret" outside the report dir for traversal
// probes. Returns the change id and the report dir.
func seedReportChange(t *testing.T, st *store.Store) (int64, string) {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateDevice(ctx, store.Device{ID: "gw1", Name: "gw1", Vendor: "auto", CollectorType: "file", CollectorConfig: `{"path":"/tmp/x.cfg"}`}); err != nil {
		t.Fatalf("create device: %v", err)
	}
	root := t.TempDir()
	reportDir := filepath.Join(root, "reports", "gw1", "20260609-000000-abcdef12")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("mkdir report dir: %v", err)
	}
	files := map[string]string{
		"report.html":        "<html><body>report</body></html>",
		"report.md":          "# Report",
		"diff-analysis.json": `{"schema_version":"1.1"}`,
		"notes.txt":          "not servable",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(reportDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// A file outside the report dir that traversal must never reach.
	if err := os.WriteFile(filepath.Join(root, "reports", "SECRET.json"), []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	id, err := st.RecordChange(ctx, store.Change{DeviceID: "gw1", CommitHash: "abc", MaxSeverity: "low", ReportDir: reportDir})
	if err != nil {
		t.Fatalf("record change: %v", err)
	}
	return id, reportDir
}

func TestReportList(t *testing.T) {
	h, st := newTestServer(t, nil)
	id, _ := seedReportChange(t, st)

	rec := do(t, h, "GET", fmt.Sprintf("/api/v1/changes/%d/reports", id), "")
	wantStatus(t, rec, http.StatusOK)
	list := decode[map[string][]reportFileJSON](t, rec)
	names := make([]string, 0)
	for _, f := range list["reports"] {
		names = append(names, f.Name)
	}
	want := []string{"diff-analysis.json", "report.html", "report.md"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("report names = %v, want %v (txt files excluded)", names, want)
	}

	// Change without a report bundle lists empty.
	noReport, err := st.RecordChange(context.Background(), store.Change{DeviceID: "gw1", CommitHash: "def", MaxSeverity: "none"})
	if err != nil {
		t.Fatalf("record change: %v", err)
	}
	rec = do(t, h, "GET", fmt.Sprintf("/api/v1/changes/%d/reports", noReport), "")
	wantStatus(t, rec, http.StatusOK)
	empty := decode[map[string][]reportFileJSON](t, rec)
	if len(empty["reports"]) != 0 {
		t.Fatalf("expected empty report list: %+v", empty)
	}
}

func TestReportFile(t *testing.T) {
	h, st := newTestServer(t, nil)
	id, _ := seedReportChange(t, st)
	base := fmt.Sprintf("/api/v1/changes/%d/reports/", id)

	rec := do(t, h, "GET", base+"report.html", "")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("report.html content type = %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}
	if !strings.Contains(rec.Body.String(), "report") {
		t.Fatalf("report.html body: %s", rec.Body.String())
	}

	rec = do(t, h, "GET", base+"diff-analysis.json", "")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("json content type = %q", ct)
	}

	// Markdown is text/plain: only report.html ever gets text/html.
	rec = do(t, h, "GET", base+"report.md", "")
	wantStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("md content type = %q", ct)
	}

	// Allowlisted extension but missing file.
	rec = do(t, h, "GET", base+"missing.md", "")
	wantErrorCode(t, rec, http.StatusNotFound, "not_found")

	// Extension not in the allowlist.
	rec = do(t, h, "GET", base+"notes.txt", "")
	wantErrorCode(t, rec, http.StatusBadRequest, "bad_request")
}

func TestReportFileTraversal(t *testing.T) {
	h, st := newTestServer(t, nil)
	id, _ := seedReportChange(t, st)
	base := fmt.Sprintf("/api/v1/changes/%d/reports/", id)

	probes := []string{
		"../SECRET.json",
		"..%2fSECRET.json",
		"%2e%2e/SECRET.json",
		"%2e%2e%2fSECRET.json",
		"..%5cSECRET.json",
		"....//SECRET.json",
		"../../../../etc/passwd",
		"..%2f..%2f..%2f..%2fetc%2fpasswd",
		".hidden.json",
		"..",
	}
	for _, probe := range probes {
		rec := do(t, h, "GET", base+probe, "")
		if rec.Code == http.StatusOK {
			t.Errorf("traversal probe %q returned 200 (body: %s)", probe, rec.Body.String())
			continue
		}
		if strings.Contains(rec.Body.String(), "TOP-SECRET") || strings.Contains(rec.Body.String(), "root:") {
			t.Errorf("traversal probe %q leaked file contents", probe)
		}
	}
}

func TestValidReportName(t *testing.T) {
	valid := []string{"report.html", "report.md", "diff-analysis.json", "rollback-plan.md", "a_b-c.1.json"}
	for _, name := range valid {
		if !validReportName(name) {
			t.Errorf("validReportName(%q) = false, want true", name)
		}
	}
	invalid := []string{
		"", "..", "../x.md", "a/b.md", `a\b.md`, ".hidden.md", "-lead.md",
		"notes.txt", "report.html.exe", "a..b.md", "%2e%2e.json", "x.HTML",
	}
	for _, name := range invalid {
		if validReportName(name) {
			t.Errorf("validReportName(%q) = true, want false", name)
		}
	}
}

func TestSnapshotNow(t *testing.T) {
	change := store.Change{ID: 7, DeviceID: "gw1", CommitHash: "abc", Summary: "1 finding (1 low) - 1 block changed", MaxSeverity: "low"}
	calls := 0
	h, st := newTestServer(t, func(c *Config) {
		c.SnapshotNow = func(ctx context.Context, deviceID string) (*store.Change, bool, error) {
			calls++
			if calls == 1 {
				return &change, true, nil
			}
			return nil, false, nil
		}
	})
	if err := st.CreateDevice(context.Background(), store.Device{ID: "gw1", Name: "gw1", Vendor: "auto", CollectorType: "file", CollectorConfig: `{"path":"/tmp/x.cfg"}`}); err != nil {
		t.Fatalf("create device: %v", err)
	}

	rec := do(t, h, "POST", "/api/v1/devices/gw1/snapshot", "")
	wantStatus(t, rec, http.StatusOK)
	first := decode[map[string]any](t, rec)
	if first["changed"] != true {
		t.Fatalf("first snapshot: %v", first)
	}
	if !strings.Contains(rec.Body.String(), `"max_severity":"low"`) {
		t.Fatalf("change not embedded: %s", rec.Body.String())
	}

	rec = do(t, h, "POST", "/api/v1/devices/gw1/snapshot", "")
	wantStatus(t, rec, http.StatusOK)
	second := decode[map[string]any](t, rec)
	if second["changed"] != false {
		t.Fatalf("second snapshot: %v", second)
	}

	// Unknown device 404s without invoking the callback.
	before := calls
	rec = do(t, h, "POST", "/api/v1/devices/nope/snapshot", "")
	wantErrorCode(t, rec, http.StatusNotFound, "not_found")
	if calls != before {
		t.Fatal("SnapshotNow invoked for unknown device")
	}
}

func TestSnapshotNowUnwired(t *testing.T) {
	h, st := newTestServer(t, nil)
	if err := st.CreateDevice(context.Background(), store.Device{ID: "gw1", Name: "gw1", Vendor: "auto", CollectorType: "file", CollectorConfig: `{"path":"/tmp/x.cfg"}`}); err != nil {
		t.Fatalf("create device: %v", err)
	}
	rec := do(t, h, "POST", "/api/v1/devices/gw1/snapshot", "")
	wantErrorCode(t, rec, http.StatusNotImplemented, "not_implemented")
}

func TestCORS(t *testing.T) {
	h, _ := newTestServer(t, func(c *Config) { c.CORSOrigin = "http://localhost:5173" })

	// Preflight from the allowed origin succeeds without auth.
	rec := do(t, h, "OPTIONS", "/api/v1/devices", "", fromAddr("192.0.2.7:1234"), func(r *http.Request) {
		r.Header.Set("Origin", "http://localhost:5173")
		r.Header.Set("Access-Control-Request-Method", "POST")
	})
	wantStatus(t, rec, http.StatusNoContent)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("allow-origin = %q", got)
	}

	// Disallowed origin gets no CORS headers.
	rec = do(t, h, "OPTIONS", "/api/v1/devices", "", func(r *http.Request) {
		r.Header.Set("Origin", "http://evil.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
	})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin got allow-origin %q", got)
	}

	// Normal requests pass through with the header set.
	rec = do(t, h, "GET", "/api/v1/devices", "", func(r *http.Request) {
		r.Header.Set("Origin", "http://localhost:5173")
	})
	wantStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("simple request allow-origin = %q", got)
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	s := &Server{cfg: Config{Logger: discardLogger()}}
	h := s.recovery(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := do(t, h, "GET", "/anything", "")
	wantErrorCode(t, rec, http.StatusInternalServerError, "internal")
}
