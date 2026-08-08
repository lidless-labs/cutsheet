package collector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lidless-labs/cutsheet/internal/secrets"
)

// unifiHTTPTimeout bounds each HTTP request to the controller. The fetch
// context can cut it shorter.
const unifiHTTPTimeout = 30 * time.Second

// unifiConfig is the JSON config for the "unifi" collector.
type unifiConfig struct {
	URL         string `json:"url"`
	Site        string `json:"site"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	InsecureTLS bool   `json:"insecure_tls"`
	// UniFiOS selects the auth style: true = UniFi OS console
	// (/api/auth/login + /proxy/network prefix), false = legacy controller
	// (/api/login, no prefix), nil = auto-detect (try UniFi OS, fall back).
	UniFiOS *bool `json:"unifi_os"`
}

// unifiCollector polls a UniFi Network controller's REST API and assembles a
// single deterministic JSON document in the shape the configdiff unifi-json
// parser consumes.
type unifiCollector struct {
	cfg unifiConfig
	box *secrets.Box
}

func newUnifiCollector(configJSON []byte, box *secrets.Box) (Collector, error) {
	var cfg unifiConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("parse unifi collector config: %w", err)
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("unifi collector config: %q is required", "url")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("unifi collector config: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unifi collector config: url scheme must be http or https, got %q", u.Scheme)
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("unifi collector config: %q is required", "username")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("unifi collector config: %q is required", "password")
	}
	if cfg.Site == "" {
		cfg.Site = "default"
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &unifiCollector{cfg: cfg, box: box}, nil
}

// unifiExport is the assembled output document. Field order mirrors the
// sections the configdiff unifi-json parser handles; struct marshaling plus
// json's sorted map keys make the byte output stable for identical state.
type unifiExport struct {
	Networkconf   []map[string]any `json:"networkconf"`
	Portconf      []map[string]any `json:"portconf"`
	PortOverrides []map[string]any `json:"port_overrides"`
	Firewallrule  []map[string]any `json:"firewallrule"`
	Firewallgroup []map[string]any `json:"firewallgroup"`
	Routing       []map[string]any `json:"routing"`
	Wlanconf      []map[string]any `json:"wlanconf"`
}

// unifiSession is an authenticated controller session.
type unifiSession struct {
	client  *http.Client
	baseURL string
	prefix  string // "/proxy/network" on UniFi OS consoles, "" on legacy
	csrf    string
}

func (c *unifiCollector) Fetch(ctx context.Context) ([]byte, error) {
	password, err := decryptIfNeeded(c.cfg.Password, "password", c.box)
	if err != nil {
		return nil, fmt.Errorf("unifi collector: %w", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("unifi collector: cookie jar: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if c.cfg.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Jar: jar, Transport: transport, Timeout: unifiHTTPTimeout}

	session, err := c.login(ctx, client, password)
	if err != nil {
		return nil, err
	}

	export := unifiExport{}
	sitePath := "/api/s/" + url.PathEscape(c.cfg.Site)
	for _, section := range []struct {
		name string
		dest *[]map[string]any
	}{
		{"networkconf", &export.Networkconf},
		{"portconf", &export.Portconf},
		{"firewallrule", &export.Firewallrule},
		{"firewallgroup", &export.Firewallgroup},
		{"routing", &export.Routing},
		{"wlanconf", &export.Wlanconf},
	} {
		data, err := session.get(ctx, sitePath+"/rest/"+section.name)
		if err != nil {
			return nil, fmt.Errorf("unifi collector: fetch %s: %w", section.name, err)
		}
		*section.dest = data
	}

	devices, err := session.get(ctx, sitePath+"/stat/device")
	if err != nil {
		return nil, fmt.Errorf("unifi collector: fetch stat/device: %w", err)
	}
	export.PortOverrides = collectPortOverrides(devices)

	for _, arr := range []*[]map[string]any{
		&export.Networkconf, &export.Portconf, &export.PortOverrides,
		&export.Firewallrule, &export.Firewallgroup, &export.Routing, &export.Wlanconf,
	} {
		sortUnifiEntries(*arr)
		if *arr == nil {
			*arr = []map[string]any{}
		}
	}

	out, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unifi collector: marshal export: %w", err)
	}
	return append(out, '\n'), nil
}

// login authenticates and returns a session. With UniFiOS unset it probes the
// UniFi OS endpoint first and falls back to the legacy controller login.
func (c *unifiCollector) login(ctx context.Context, client *http.Client, password string) (*unifiSession, error) {
	body, err := json.Marshal(map[string]string{"username": c.cfg.Username, "password": password})
	if err != nil {
		return nil, fmt.Errorf("unifi collector: marshal login body: %w", err)
	}

	tryStyle := func(unifiOS bool) (*unifiSession, error) {
		loginPath, prefix := "/api/login", ""
		if unifiOS {
			loginPath, prefix = "/api/auth/login", "/proxy/network"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+loginPath, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build login request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("login request: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("login %s: HTTP %d", loginPath, resp.StatusCode)
		}
		return &unifiSession{
			client:  client,
			baseURL: c.cfg.URL,
			prefix:  prefix,
			csrf:    resp.Header.Get("X-CSRF-Token"),
		}, nil
	}

	if c.cfg.UniFiOS != nil {
		session, err := tryStyle(*c.cfg.UniFiOS)
		if err != nil {
			return nil, fmt.Errorf("unifi collector: %w", err)
		}
		return session, nil
	}
	session, osErr := tryStyle(true)
	if osErr == nil {
		return session, nil
	}
	session, legacyErr := tryStyle(false)
	if legacyErr != nil {
		return nil, fmt.Errorf("unifi collector: auto-detect failed: unifi os login: %v; legacy login: %w", osErr, legacyErr)
	}
	return session, nil
}

// get performs an authenticated GET and returns the "data" array of the
// standard UniFi {"meta":..., "data":[...]} envelope.
func (s *unifiSession) get(ctx context.Context, apiPath string) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+s.prefix+apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if s.csrf != "" {
		req.Header.Set("X-Csrf-Token", s.csrf)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return envelope.Data, nil
}

// collectPortOverrides flattens every device's port_overrides array into one
// list, the shape the unifi-json parser reads from the top-level key.
func collectPortOverrides(devices []map[string]any) []map[string]any {
	var overrides []map[string]any
	for _, device := range devices {
		raw, ok := device["port_overrides"].([]any)
		if !ok {
			continue
		}
		for _, item := range raw {
			if entry, ok := item.(map[string]any); ok {
				overrides = append(overrides, entry)
			}
		}
	}
	return overrides
}

// sortUnifiEntries orders entries by _id when present, falling back to the
// compact JSON encoding of the entry (covers port_overrides, which carry
// port_idx but no _id). Controllers do not guarantee array order, and a
// stable order is what keeps identical state byte-identical across polls.
func sortUnifiEntries(entries []map[string]any) {
	key := func(e map[string]any) string {
		if id, ok := e["_id"].(string); ok && id != "" {
			return "id:" + id
		}
		encoded, err := json.Marshal(e)
		if err != nil {
			return ""
		}
		return "json:" + string(encoded)
	}
	sort.SliceStable(entries, func(i, j int) bool { return key(entries[i]) < key(entries[j]) })
}
