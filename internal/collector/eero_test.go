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

// fakeEero emulates the eero cloud API (api-user.e2ro.com style): cookie
// auth, {"meta":...,"data":...} envelopes, and the nested networks listing.
// Every list response is shuffled so tests can prove the collector's output
// is deterministic regardless of API ordering.
type fakeEero struct {
	t     *testing.T
	token string
	// flatNetworks serves GET /networks data as a bare array instead of the
	// nested {"networks":{"count":N,"data":[...]}} shape; the collector must
	// accept both (mirrors eero-cli's _extract_networks).
	flatNetworks bool
	networks     []map[string]any

	mu  sync.Mutex
	rng *rand.Rand
}

const fakeEeroToken = "eero-test-session-token"

var fakeEeroNetworkHome = map[string]any{"url": "/2.2/networks/1", "name": "Home"}
var fakeEeroNetworkCabin = map[string]any{"url": "/2.2/networks/2", "name": "Cabin"}

// fakeEeroDetails maps network id to the GET networks/{id} payload. Config
// fields sit next to volatile fields (status, speed, clients, health,
// geo_ip, updates, last_reboot) that the collector must strip.
var fakeEeroDetails = map[string]map[string]any{
	"1": {
		"url":      "/2.2/networks/1",
		"name":     "Home",
		"password": "wifi-passphrase",
		"wpa3":     true,
		"dns": map[string]any{
			"mode":   "custom",
			"custom": map[string]any{"ips": []any{"198.18.0.53", "198.18.0.54"}},
		},
		"dhcp": map[string]any{
			"mode": "custom",
			"custom": map[string]any{
				"subnet_ip":   "198.18.50.0",
				"subnet_mask": "255.255.255.0",
				"start_ip":    "198.18.50.10",
				"end_ip":      "198.18.50.200",
			},
		},
		"guest_network": map[string]any{"enabled": true, "name": "Home Guest", "password": "guest-pass"},
		"upnp":          false,
		"band_steering": true,
		"ipv6_upstream": false,
		"thread":        false,
		"sqm":           true,
		// Volatile fields the collector must drop:
		"status":      "connected",
		"clients":     map[string]any{"count": 12, "url": "/2.2/networks/1/devices"},
		"speed":       map[string]any{"down": map[string]any{"value": 940.2}, "up": map[string]any{"value": 880.1}, "date": "2026-06-09T01:02:03Z"},
		"health":      map[string]any{"internet": map[string]any{"isp_up": true}},
		"geo_ip":      map[string]any{"countryCode": "US", "isp": "ExampleNet"},
		"updates":     map[string]any{"target_firmware": "v7.6.0", "scheduled_update_time": "03:00"},
		"last_reboot": "2026-06-01T00:00:00Z",
	},
	"2": {
		"url":    "/2.2/networks/2",
		"name":   "Cabin",
		"wpa3":   false,
		"dns":    map[string]any{"mode": "auto"},
		"dhcp":   map[string]any{"mode": "auto"},
		"status": "connected",
	},
}

// fakeEeroSections holds the per-network subresource lists, shuffled per
// response. Eeros and profiles carry volatile fields that must be stripped;
// forwards and reservations pass through whole.
var fakeEeroSections = map[string][]map[string]any{
	"eeros": {
		{
			"url": "/2.2/eeros/12", "serial": "S2222222222222", "mac_address": "00:00:5E:00:53:02",
			"model": "eero Pro 6", "model_number": "K010001", "location": "Office",
			"os": "eeroOS 7.5.1-8", "os_version": "7.5.1", "gateway": false, "wired": true,
			// Volatile:
			"status": "green", "ip_address": "198.18.50.3", "connected_clients_count": 4,
			"last_heartbeat": "2026-06-09T01:02:03Z",
		},
		{
			"url": "/2.2/eeros/11", "serial": "S1111111111111", "mac_address": "00:00:5E:00:53:01",
			"model": "eero Pro 6", "model_number": "K010001", "location": "Living Room",
			"os": "eeroOS 7.5.1-8", "os_version": "7.5.1", "gateway": true, "wired": true,
			"status": "green", "ip_address": "198.18.50.2", "connected_clients_count": 8,
			"last_heartbeat": "2026-06-09T01:02:04Z",
		},
	},
	"forwards": {
		{"url": "/2.2/networks/1/forwards/22", "description": "ssh jump", "enabled": false, "ip": "198.18.50.21", "gateway_port": 2222, "client_port": 22, "protocol": "tcp"},
		{"url": "/2.2/networks/1/forwards/21", "description": "web server", "enabled": true, "ip": "198.18.50.20", "gateway_port": 443, "client_port": 443, "protocol": "tcp"},
	},
	"profiles": {
		{
			"url": "/2.2/networks/1/profiles/32", "name": "Kids", "paused": true,
			"schedule":       map[string]any{"enabled": true, "blocks": []any{map[string]any{"days": []any{"mon"}, "start": "21:00", "end": "06:00"}}},
			"content_filter": map[string]any{"adblock": true, "safe_search": true, "block_adult": true},
			"premium_dns":    map[string]any{"blocked_applications": []any{"tiktok"}},
			// Volatile:
			"devices": []any{map[string]any{"mac": "00:00:5E:00:53:20", "hostname": "kids-tablet"}},
			"state":   "paused",
		},
		{
			"url": "/2.2/networks/1/profiles/31", "name": "Adults", "paused": false,
			"content_filter": map[string]any{"adblock": false},
			"devices":        []any{map[string]any{"mac": "00:00:5E:00:53:21", "hostname": "laptop"}},
			"state":          "active",
		},
	},
	"reservations": {
		{"url": "/2.2/networks/1/reservations/42", "mac": "00:00:5E:00:53:11", "ip": "198.18.50.31", "description": "printer"},
		{"url": "/2.2/networks/1/reservations/41", "mac": "00:00:5E:00:53:10", "ip": "198.18.50.30", "description": "nas"},
	},
}

func newFakeEero(t *testing.T, networks ...map[string]any) *fakeEero {
	if len(networks) == 0 {
		networks = []map[string]any{fakeEeroNetworkHome}
	}
	return &fakeEero{
		t:        t,
		token:    fakeEeroToken,
		networks: networks,
		rng:      rand.New(rand.NewSource(1)),
	}
}

func (f *fakeEero) start() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	f.t.Cleanup(srv.Close)
	return srv
}

func (f *fakeEero) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cookie, err := r.Cookie("s")
	if err != nil || cookie.Value != f.token {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"meta":{"code":401,"error":"error.session.invalid"}}`))
		return
	}

	path := strings.Trim(r.URL.Path, "/")
	if path == "networks" {
		list := f.shuffled(f.networks)
		if f.flatNetworks {
			f.respond(w, list)
			return
		}
		f.respond(w, map[string]any{"networks": map[string]any{"count": len(list), "data": list}})
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) == 2 && parts[0] == "networks" {
		if detail, ok := fakeEeroDetails[parts[1]]; ok {
			f.respond(w, detail)
			return
		}
	}
	if len(parts) == 3 && parts[0] == "networks" {
		if _, ok := fakeEeroDetails[parts[1]]; ok {
			if data, ok := fakeEeroSections[parts[2]]; ok {
				f.respond(w, f.shuffled(data))
				return
			}
		}
	}
	http.NotFound(w, r)
}

func (f *fakeEero) respond(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"code": 200}, "data": data})
}

// shuffled returns a freshly shuffled copy so consecutive fetches see
// different array orders.
func (f *fakeEero) shuffled(data []map[string]any) []map[string]any {
	out := make([]map[string]any, len(data))
	copy(out, data)
	f.rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func eeroTestConfig(url, extra string) string {
	return `{"session_token":"` + fakeEeroToken + `","base_url":"` + url + `"` + extra + `}`
}

func fetchEero(t *testing.T, configJSON string, box *secrets.Box) []byte {
	t.Helper()
	c, err := New("eero", []byte(configJSON), box)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	return out
}

func TestEeroConfigValidation(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantErr    string
	}{
		{"missing session_token", `{"network_id":"1"}`, "session_token"},
		{"bad base_url scheme", `{"session_token":"tok","base_url":"ftp://api.example.invalid"}`, "base_url"},
		{"unparseable base_url", `{"session_token":"tok","base_url":"https://api.example.invalid:bad:port"}`, "base_url"},
		{"bad json", `{`, "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New("eero", []byte(tt.configJSON), nil)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}

	// The missing-token error must point users at the out-of-band login flow.
	_, err := New("eero", []byte(`{}`), nil)
	if err == nil || !strings.Contains(err.Error(), "eero-cli") {
		t.Fatalf("missing session_token error should mention eero-cli, got: %v", err)
	}

	if _, err := New("eero", []byte(`{"session_token":"tok"}`), nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestEeroFetchMatchesGoldenAndIsDeterministic(t *testing.T) {
	for _, mode := range []struct {
		name string
		flat bool
	}{
		{"nested networks listing", false},
		{"flat networks listing", true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			fake := newFakeEero(t)
			fake.flatNetworks = mode.flat
			srv := fake.start()

			first := fetchEero(t, eeroTestConfig(srv.URL, ""), nil)
			second := fetchEero(t, eeroTestConfig(srv.URL, ""), nil)
			if string(first) != string(second) {
				t.Fatalf("output not deterministic across fetches:\nfirst:\n%s\nsecond:\n%s", first, second)
			}

			goldenPath := filepath.Join("testdata", "eero-golden.json")
			if os.Getenv("UPDATE_GOLDEN") == "1" && !mode.flat {
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
		})
	}
}

// TestEeroGoldenShape pins the assembled document's contract: the five
// config sections are present and the volatile fields the fake serves
// (client lists, speeds, signal/status data, timestamps) are stripped.
func TestEeroGoldenShape(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "eero-golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(golden, &root); err != nil {
		t.Fatalf("golden is not valid JSON: %v", err)
	}
	for _, key := range []string{"eeros", "forwards", "network", "profiles", "reservations"} {
		if _, ok := root[key]; !ok {
			t.Errorf("golden missing top-level key %q", key)
		}
	}

	var network map[string]any
	if err := json.Unmarshal(root["network"], &network); err != nil {
		t.Fatalf("network: %v", err)
	}
	for _, volatile := range []string{"status", "clients", "speed", "health", "geo_ip", "updates", "last_reboot"} {
		if _, ok := network[volatile]; ok {
			t.Errorf("network section carries volatile field %q", volatile)
		}
	}

	var eeros []map[string]any
	if err := json.Unmarshal(root["eeros"], &eeros); err != nil {
		t.Fatalf("eeros: %v", err)
	}
	if len(eeros) != 2 {
		t.Fatalf("eeros: got %d entries, want 2", len(eeros))
	}
	for _, e := range eeros {
		for _, volatile := range []string{"status", "ip_address", "connected_clients_count", "last_heartbeat"} {
			if _, ok := e[volatile]; ok {
				t.Errorf("eero node carries volatile field %q", volatile)
			}
		}
	}

	var profiles []map[string]any
	if err := json.Unmarshal(root["profiles"], &profiles); err != nil {
		t.Fatalf("profiles: %v", err)
	}
	for _, p := range profiles {
		for _, volatile := range []string{"devices", "state"} {
			if _, ok := p[volatile]; ok {
				t.Errorf("profile carries volatile field %q", volatile)
			}
		}
	}
}

func TestEeroSingleNetworkAutoSelected(t *testing.T) {
	fake := newFakeEero(t) // one network, no network_id in config
	srv := fake.start()
	out := fetchEero(t, eeroTestConfig(srv.URL, ""), nil)
	if !strings.Contains(string(out), `"Home"`) {
		t.Fatalf("auto-selected fetch should snapshot the only network:\n%s", out)
	}
}

func TestEeroMultipleNetworksRequireNetworkID(t *testing.T) {
	fake := newFakeEero(t, fakeEeroNetworkHome, fakeEeroNetworkCabin)
	srv := fake.start()
	c, err := New("eero", []byte(eeroTestConfig(srv.URL, "")), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background())
	if err == nil {
		t.Fatal("multi-network account without network_id: want error, got nil")
	}
	for _, want := range []string{"network_id", "Home", "Cabin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestEeroNetworkIDSelection(t *testing.T) {
	fake := newFakeEero(t, fakeEeroNetworkHome, fakeEeroNetworkCabin)
	srv := fake.start()

	out := fetchEero(t, eeroTestConfig(srv.URL, `,"network_id":"2"`), nil)
	if !strings.Contains(string(out), `"Cabin"`) {
		t.Fatalf("network_id 2 should snapshot Cabin:\n%s", out)
	}

	out = fetchEero(t, eeroTestConfig(srv.URL, `,"network_id":"1"`), nil)
	if !strings.Contains(string(out), `"Home Guest"`) {
		t.Fatalf("network_id 1 should snapshot Home:\n%s", out)
	}
}

func TestEeroUnknownNetworkID(t *testing.T) {
	fake := newFakeEero(t, fakeEeroNetworkHome, fakeEeroNetworkCabin)
	srv := fake.start()
	c, err := New("eero", []byte(eeroTestConfig(srv.URL, `,"network_id":"9"`)), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background())
	if err == nil {
		t.Fatal("unknown network_id: want error, got nil")
	}
	for _, want := range []string{"9", "Home", "Cabin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// TestEeroRejectedToken pins the no-refresh decision: a 401 surfaces a clear
// "re-authenticate and update the token" error instead of any silent
// refresh/rotation attempt (eero's OTP login flow issues no refresh token).
func TestEeroRejectedToken(t *testing.T) {
	fake := newFakeEero(t)
	srv := fake.start()
	cfg := `{"session_token":"stale-token","base_url":"` + srv.URL + `"}`
	c, err := New("eero", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch with rejected token: want error, got nil")
	}
	for _, want := range []string{"401", "session_token", "eero-cli"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestEeroEncryptedSessionToken(t *testing.T) {
	box := testBox(t)
	enc, err := box.Encrypt([]byte(fakeEeroToken))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	fake := newFakeEero(t)
	srv := fake.start()
	cfg := `{"session_token":"` + enc + `","base_url":"` + srv.URL + `"}`

	out := fetchEero(t, cfg, box)
	if !strings.Contains(string(out), `"Home"`) {
		t.Fatalf("fetch with encrypted session token returned unexpected output:\n%s", out)
	}

	// Same encrypted config without a secrets box must fail at fetch time.
	c, err := New("eero", []byte(cfg), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch with encrypted token and nil box: want error, got nil")
	}
}
