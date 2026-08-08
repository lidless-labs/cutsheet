package collector

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lidless-labs/cutsheet/internal/secrets"
)

// fakeController emulates a UniFi Network controller in either UniFi OS or
// legacy auth style. Every response shuffles array element order so tests can
// prove the collector's output is deterministic regardless of API ordering.
type fakeController struct {
	t        *testing.T
	unifiOS  bool
	username string
	password string
	csrf     string

	mu          sync.Mutex
	loginCalls  map[string]int
	sawCSRF     bool
	missingCSRF bool
	rng         *rand.Rand
}

const fakeSessionCookie = "cutsheet-test-session"

// fakeSections is the controller-side dataset, defined once and shuffled per
// response. Mirrors the shape of testdata/unifi-before.json plus the sections
// it omits.
var fakeSections = map[string][]map[string]any{
	"networkconf": {
		{"_id": "n2", "name": "IoT", "vlan": 30, "purpose": "corporate", "ip_subnet": "198.19.30.1/24"},
		{"_id": "n1", "name": "Corp", "vlan": 10, "purpose": "corporate", "ip_subnet": "198.19.10.1/24"},
	},
	"portconf": {
		{"_id": "p1", "name": "All", "forward": "all"},
	},
	"firewallrule": {
		{"_id": "f2", "name": "LAN_IN_2", "ruleset": "LAN_IN", "action": "drop", "src_address": "198.19.30.0/24", "protocol": "all"},
		{"_id": "f1", "name": "LAN_IN_1", "ruleset": "LAN_IN", "action": "accept", "src_address": "198.19.10.0/24", "dst_address": "198.19.30.10", "protocol": "tcp"},
	},
	"firewallgroup": {
		{"_id": "g1", "name": "mgmt-hosts", "group_type": "address-group", "group_members": []any{"198.19.10.5", "198.19.10.6"}},
	},
	"routing": {
		{"_id": "r1", "name": "DEFAULT", "type": "static-route", "static-route_network": "0.0.0.0/0", "static-route_nexthop": "203.0.113.1"},
	},
	"wlanconf": {
		{"_id": "w1", "name": "corp-wifi", "security": "wpapsk", "enabled": true},
	},
}

// fakeDevices is the /stat/device payload: two switches with port_overrides
// plus one AP without any.
var fakeDevices = []map[string]any{
	{"_id": "dev2", "mac": "00:00:5e:00:53:02", "type": "usw", "port_overrides": []any{
		map[string]any{"port_idx": 24, "op_mode": "switch", "native_networkconf_id": "n2", "forward": "disabled"},
	}},
	{"_id": "dev1", "mac": "00:00:5e:00:53:01", "type": "usw", "port_overrides": []any{
		map[string]any{"port_idx": 10, "op_mode": "switch", "native_networkconf_id": "n1", "forward": "all", "poe_mode": "auto"},
	}},
	{"_id": "dev3", "mac": "00:00:5e:00:53:03", "type": "uap"},
}

func newFakeController(t *testing.T, unifiOS bool) *fakeController {
	return &fakeController{
		t:          t,
		unifiOS:    unifiOS,
		username:   "auditor",
		password:   "reading-glasses",
		csrf:       "csrf-token-42",
		loginCalls: map[string]int{},
		rng:        rand.New(rand.NewSource(1)),
	}
}

func (f *fakeController) start() *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handle))
	f.t.Cleanup(srv.Close)
	return srv
}

func (f *fakeController) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch r.URL.Path {
	case "/api/auth/login":
		f.loginCalls["unifi-os"]++
		if !f.unifiOS {
			http.NotFound(w, r)
			return
		}
		f.login(w, r, true)
		return
	case "/api/login":
		f.loginCalls["legacy"]++
		if f.unifiOS {
			http.NotFound(w, r)
			return
		}
		f.login(w, r, false)
		return
	}

	// All other routes require the session cookie.
	if c, err := r.Cookie("TOKEN"); err != nil || c.Value != fakeSessionCookie {
		http.Error(w, `{"meta":{"rc":"error","msg":"api.err.LoginRequired"}}`, http.StatusUnauthorized)
		return
	}
	if f.unifiOS {
		if r.Header.Get("X-Csrf-Token") == f.csrf {
			f.sawCSRF = true
		} else {
			f.missingCSRF = true
		}
	}

	path := r.URL.Path
	if f.unifiOS {
		var ok bool
		path, ok = strings.CutPrefix(path, "/proxy/network")
		if !ok {
			http.Error(w, "missing /proxy/network prefix on UniFi OS console", http.StatusNotFound)
			return
		}
	}
	prefix := "/api/s/default/"
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if rest == "stat/device" {
		f.respond(w, f.shuffledDevices())
		return
	}
	section, ok := strings.CutPrefix(rest, "rest/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, found := fakeSections[section]
	if !found {
		http.NotFound(w, r)
		return
	}
	f.respond(w, f.shuffled(data))
}

func (f *fakeController) login(w http.ResponseWriter, r *http.Request, unifiOS bool) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil ||
		creds.Username != f.username || creds.Password != f.password {
		http.Error(w, `{"meta":{"rc":"error","msg":"api.err.Invalid"}}`, http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: fakeSessionCookie, Path: "/"})
	if unifiOS {
		w.Header().Set("X-CSRF-Token", f.csrf)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
}

func (f *fakeController) respond(w http.ResponseWriter, data []map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"rc": "ok"}, "data": data})
}

// shuffled returns a freshly shuffled copy so consecutive fetches see
// different array orders.
func (f *fakeController) shuffled(data []map[string]any) []map[string]any {
	out := make([]map[string]any, len(data))
	copy(out, data)
	f.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func (f *fakeController) shuffledDevices() []map[string]any {
	return f.shuffled(fakeDevices)
}

func unifiTestConfig(url string, extra string) string {
	cfg := `{"url":"` + url + `","site":"default","username":"auditor","password":"reading-glasses","insecure_tls":true` + extra + `}`
	return cfg
}

func fetchUnifi(t *testing.T, configJSON string, box *secrets.Box) []byte {
	t.Helper()
	c, err := New("unifi", []byte(configJSON), box)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	return out
}

func TestUnifiConfigValidation(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantErr    string
	}{
		{"missing url", `{"username":"u","password":"p"}`, "url"},
		{"bad url scheme", `{"url":"ftp://c.example.invalid","username":"u","password":"p"}`, "url"},
		{"unparseable url", `{"url":"https://c.example.invalid:bad:port","username":"u","password":"p"}`, "url"},
		{"missing username", `{"url":"https://c.example.invalid","password":"p"}`, "username"},
		{"missing password", `{"url":"https://c.example.invalid","username":"u"}`, "password"},
		{"bad json", `{`, "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New("unifi", []byte(tt.configJSON), nil)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}

	if _, err := New("unifi", []byte(`{"url":"https://c.example.invalid","username":"u","password":"p"}`), nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestUnifiFetchMatchesGoldenAndIsDeterministic(t *testing.T) {
	for _, mode := range []struct {
		name    string
		unifiOS bool
		extra   string
	}{
		{"unifi-os auto-detect", true, ""},
		{"legacy auto-detect", false, ""},
		{"unifi-os explicit", true, `,"unifi_os":true`},
		{"legacy explicit", false, `,"unifi_os":false`},
	} {
		t.Run(mode.name, func(t *testing.T) {
			fake := newFakeController(t, mode.unifiOS)
			srv := fake.start()

			first := fetchUnifi(t, unifiTestConfig(srv.URL, mode.extra), nil)
			second := fetchUnifi(t, unifiTestConfig(srv.URL, mode.extra), nil)
			if string(first) != string(second) {
				t.Fatalf("output not deterministic across fetches:\nfirst:\n%s\nsecond:\n%s", first, second)
			}

			goldenPath := filepath.Join("testdata", "unifi-golden.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(goldenPath, first, 0o644); err != nil {
					t.Fatalf("update golden: %v", err)
				}
			}
			golden, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if string(first) != string(golden) {
				t.Fatalf("output does not match golden fixture:\ngot:\n%s\nwant:\n%s", first, golden)
			}

			fake.mu.Lock()
			defer fake.mu.Unlock()
			if mode.unifiOS && (!fake.sawCSRF || fake.missingCSRF) {
				t.Fatalf("UniFi OS requests should carry the CSRF token (saw=%v missing=%v)", fake.sawCSRF, fake.missingCSRF)
			}
		})
	}
}

func TestUnifiAutoDetectFallsBackToLegacy(t *testing.T) {
	fake := newFakeController(t, false)
	srv := fake.start()

	fetchUnifi(t, unifiTestConfig(srv.URL, ""), nil)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.loginCalls["unifi-os"] == 0 {
		t.Fatal("auto-detect should probe the UniFi OS login first")
	}
	if fake.loginCalls["legacy"] == 0 {
		t.Fatal("auto-detect should fall back to the legacy login")
	}
}

func TestUnifiExplicitStyleSkipsProbe(t *testing.T) {
	fake := newFakeController(t, false)
	srv := fake.start()

	fetchUnifi(t, unifiTestConfig(srv.URL, `,"unifi_os":false`), nil)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.loginCalls["unifi-os"] != 0 {
		t.Fatalf("explicit unifi_os:false should not probe /api/auth/login (got %d calls)", fake.loginCalls["unifi-os"])
	}
}

func TestUnifiEncryptedPassword(t *testing.T) {
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	box := secrets.New(key)
	enc, err := box.Encrypt([]byte("reading-glasses"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	fake := newFakeController(t, true)
	srv := fake.start()
	cfg := `{"url":"` + srv.URL + `","username":"auditor","password":"` + enc + `","insecure_tls":true}`

	out := fetchUnifi(t, cfg, box)
	if !strings.Contains(string(out), "networkconf") {
		t.Fatalf("fetch with encrypted password returned unexpected output:\n%s", out)
	}

	// Same encrypted config without a secrets box must fail at fetch time.
	c, err := New("unifi", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch with encrypted password and nil box: want error, got nil")
	}
}

func TestUnifiBadCredentials(t *testing.T) {
	fake := newFakeController(t, true)
	srv := fake.start()
	cfg := `{"url":"` + srv.URL + `","username":"auditor","password":"wrong","insecure_tls":true}`
	c, err := New("unifi", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch with bad credentials: want error, got nil")
	}
}

func TestUnifiDefaultSite(t *testing.T) {
	fake := newFakeController(t, true)
	srv := fake.start()
	// No "site" field: collector must default to "default", which is the only
	// site the fake serves.
	cfg := `{"url":"` + srv.URL + `","username":"auditor","password":"reading-glasses","insecure_tls":true}`
	out := fetchUnifi(t, cfg, nil)
	if !strings.Contains(string(out), "networkconf") {
		t.Fatalf("default-site fetch returned unexpected output:\n%s", out)
	}
}

// TestUnifiGoldenParsesAsUnifi guards the contract with pkg/configdiff: the
// assembled document must carry the keys the unifi-json parser keys on.
func TestUnifiGoldenShape(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "unifi-golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(golden, &root); err != nil {
		t.Fatalf("golden is not valid JSON: %v", err)
	}
	for _, key := range []string{"networkconf", "portconf", "port_overrides", "firewallrule", "firewallgroup", "routing", "wlanconf"} {
		if _, ok := root[key]; !ok {
			t.Errorf("golden missing top-level key %q expected by the unifi-json parser", key)
		}
	}
	var overrides []map[string]any
	if err := json.Unmarshal(root["port_overrides"], &overrides); err != nil {
		t.Fatalf("port_overrides: %v", err)
	}
	if len(overrides) != 2 {
		t.Fatalf("port_overrides: got %d entries, want 2 (flattened across devices)", len(overrides))
	}
}
