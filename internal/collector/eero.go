package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lidless-labs/cutsheet/internal/secrets"
)

// eeroHTTPTimeout bounds each HTTP request to the eero cloud API. The fetch
// context can cut it shorter.
const eeroHTTPTimeout = 30 * time.Second

// eeroDefaultBaseURL is the unofficial eero cloud API consumed by the mobile
// app (and by eero-cli, the prior art this collector mirrors).
const eeroDefaultBaseURL = "https://api-user.e2ro.com/2.2"

// eeroConfig is the JSON config for the "eero" collector.
//
// Cutsheet does not run eero's OTP login flow (login -> SMS/email code ->
// verify); users obtain a session token out of band, e.g. with eero-cli
// (`eero auth`), and paste it here. Tokens from that flow are long-lived
// (~30 days) and carry no refresh token, so there is no transparent refresh:
// when the API returns 401 the collector surfaces a clear "re-authenticate
// and update session_token" error instead of silently rotating credentials.
type eeroConfig struct {
	SessionToken string `json:"session_token"`
	// NetworkID selects the eero network to snapshot. Optional when the
	// account has exactly one network; required (with a listing in the error)
	// when it has several.
	NetworkID string `json:"network_id"`
	// BaseURL overrides the eero cloud API endpoint, for tests.
	BaseURL string `json:"base_url"`
}

// eeroCollector polls the unofficial eero cloud API and assembles a single
// deterministic JSON document snapshotting the network's configuration state.
type eeroCollector struct {
	cfg eeroConfig
	box *secrets.Box
}

func newEeroCollector(configJSON []byte, box *secrets.Box) (Collector, error) {
	var cfg eeroConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("parse eero collector config: %w", err)
	}
	if cfg.SessionToken == "" {
		return nil, fmt.Errorf("eero collector config: %q is required (cutsheet does not run eero's OTP login; obtain a token with eero-cli's `eero auth` and copy it from its session file)", "session_token")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = eeroDefaultBaseURL
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("eero collector config: invalid base_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("eero collector config: base_url scheme must be http or https, got %q", u.Scheme)
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &eeroCollector{cfg: cfg, box: box}, nil
}

// eeroExport is the assembled output document, field order alphabetical so
// the whole document reads as sorted keys (json sorts map keys; struct order
// covers the top level). Marshaled with 2-space indent plus a trailing
// newline so the generic line-based differ produces readable diffs.
type eeroExport struct {
	Eeros        []map[string]any `json:"eeros"`
	Forwards     []map[string]any `json:"forwards"`
	Network      map[string]any   `json:"network"`
	Profiles     []map[string]any `json:"profiles"`
	Reservations []map[string]any `json:"reservations"`
}

// Field whitelists keep the snapshot to configuration state. The eero cloud
// mixes config with telemetry in the same payloads (client lists, speed
// tests, health probes, heartbeats), so the network detail, eero nodes, and
// profiles are filtered to known config fields; identical config must
// produce identical bytes. Forwards and reservations are pure config objects
// and pass through whole.
var (
	eeroNetworkFields = []string{
		"url", "name", "password", "wpa3", "dns", "dhcp", "ip_settings",
		"guest_network", "upnp", "band_steering", "ipv6_upstream", "thread", "sqm",
	}
	eeroNodeFields = []string{
		"url", "serial", "mac_address", "model", "model_number", "location",
		"os", "os_version", "gateway", "wired",
	}
	eeroProfileFields = []string{
		"url", "name", "paused", "schedule", "content_filter", "premium_dns",
	}
)

// eeroSession issues authenticated requests. Auth mirrors eero-cli's
// underlying library: the session token rides as the "s" cookie on every
// request; there is no Authorization header.
type eeroSession struct {
	client  *http.Client
	baseURL string
	token   string
}

func (c *eeroCollector) Fetch(ctx context.Context) ([]byte, error) {
	token, err := decryptIfNeeded(c.cfg.SessionToken, "session_token", c.box)
	if err != nil {
		return nil, fmt.Errorf("eero collector: %w", err)
	}
	session := &eeroSession{
		client:  &http.Client{Timeout: eeroHTTPTimeout},
		baseURL: c.cfg.BaseURL,
		token:   token,
	}

	rawNetworks, err := session.get(ctx, "networks")
	if err != nil {
		return nil, fmt.Errorf("eero collector: fetch networks: %w", err)
	}
	networks, err := eeroExtractNetworks(rawNetworks)
	if err != nil {
		return nil, fmt.Errorf("eero collector: %w", err)
	}
	networkID, err := c.resolveNetworkID(networks)
	if err != nil {
		return nil, fmt.Errorf("eero collector: %w", err)
	}
	netPath := "networks/" + url.PathEscape(networkID)

	rawDetail, err := session.get(ctx, netPath)
	if err != nil {
		return nil, fmt.Errorf("eero collector: fetch network %s: %w", networkID, err)
	}
	var detail map[string]any
	if err := json.Unmarshal(rawDetail, &detail); err != nil {
		return nil, fmt.Errorf("eero collector: decode network %s: %w", networkID, err)
	}

	export := eeroExport{Network: eeroFilterFields(detail, eeroNetworkFields)}
	for _, section := range []struct {
		name   string
		fields []string // nil = pass entries through whole
		dest   *[]map[string]any
	}{
		{"eeros", eeroNodeFields, &export.Eeros},
		{"forwards", nil, &export.Forwards},
		{"profiles", eeroProfileFields, &export.Profiles},
		{"reservations", nil, &export.Reservations},
	} {
		raw, err := session.get(ctx, netPath+"/"+section.name)
		if err != nil {
			return nil, fmt.Errorf("eero collector: fetch %s: %w", section.name, err)
		}
		var entries []map[string]any
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("eero collector: decode %s: %w", section.name, err)
		}
		if section.fields != nil {
			for i, entry := range entries {
				entries[i] = eeroFilterFields(entry, section.fields)
			}
		}
		sortEeroEntries(entries)
		if entries == nil {
			entries = []map[string]any{}
		}
		*section.dest = entries
	}

	out, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("eero collector: marshal export: %w", err)
	}
	return append(out, '\n'), nil
}

// get performs an authenticated GET and returns the "data" member of the
// standard eero {"meta":..., "data":...} envelope (an object or an array,
// depending on the endpoint).
func (s *eeroSession) get(ctx context.Context, apiPath string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/"+apiPath, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.AddCookie(&http.Cookie{Name: "s", Value: s.token})
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		// Deliberate no-refresh: eero's OTP login issues no refresh token, so
		// a rejected session cannot be renewed client-side. Surfacing the fix
		// beats silently rotating a credential v1 could not write back anyway.
		return nil, fmt.Errorf("HTTP 401: eero rejected the session token (expired or revoked); re-authenticate (e.g. `eero auth` in eero-cli) and update this device's session_token")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return envelope.Data, nil
}

// eeroExtractNetworks flattens the GET networks response. The eero cloud has
// served this in several shapes over time (mirrors eero-cli): a bare array,
// {"networks": [...]}, or {"networks": {"count": N, "data": [...]}}.
func eeroExtractNetworks(data json.RawMessage) ([]map[string]any, error) {
	toEntries := func(v any) ([]map[string]any, bool) {
		list, ok := v.([]any)
		if !ok {
			return nil, false
		}
		entries := make([]map[string]any, 0, len(list))
		for _, item := range list {
			if entry, ok := item.(map[string]any); ok {
				entries = append(entries, entry)
			}
		}
		return entries, true
	}

	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("decode networks: %w", err)
	}
	if entries, ok := toEntries(decoded); ok {
		return entries, nil
	}
	if outer, ok := decoded.(map[string]any); ok {
		inner := outer["networks"]
		if entries, ok := toEntries(inner); ok {
			return entries, nil
		}
		if nested, ok := inner.(map[string]any); ok {
			if entries, ok := toEntries(nested["data"]); ok {
				return entries, nil
			}
		}
	}
	return nil, fmt.Errorf("unrecognized networks response shape")
}

// eeroNetworkID extracts a network's id from its "id" field or, failing
// that, the trailing segment of its "url" (e.g. "/2.2/networks/123").
func eeroNetworkID(network map[string]any) string {
	switch id := network["id"].(type) {
	case string:
		if id != "" {
			return id
		}
	case float64:
		return strconv.FormatFloat(id, 'f', -1, 64)
	}
	if u, ok := network["url"].(string); ok && u != "" {
		trimmed := strings.TrimRight(u, "/")
		return trimmed[strings.LastIndex(trimmed, "/")+1:]
	}
	return ""
}

// resolveNetworkID picks the network to snapshot: an explicit network_id is
// validated against the account, no network_id auto-selects a sole network,
// and a multi-network account without one is an error that lists the choices.
func (c *eeroCollector) resolveNetworkID(networks []map[string]any) (string, error) {
	if len(networks) == 0 {
		return "", fmt.Errorf("no networks visible on this eero account")
	}
	visible := make([]string, 0, len(networks))
	for _, n := range networks {
		name, _ := n["name"].(string)
		visible = append(visible, fmt.Sprintf("%s=%s", name, eeroNetworkID(n)))
	}
	sort.Strings(visible)

	if c.cfg.NetworkID != "" {
		for _, n := range networks {
			if eeroNetworkID(n) == c.cfg.NetworkID {
				return c.cfg.NetworkID, nil
			}
		}
		return "", fmt.Errorf("network_id %q not found on this account (visible: %s)", c.cfg.NetworkID, strings.Join(visible, ", "))
	}
	if len(networks) > 1 {
		return "", fmt.Errorf("account has %d networks (%s); set %q in the collector config", len(networks), strings.Join(visible, ", "), "network_id")
	}
	id := eeroNetworkID(networks[0])
	if id == "" {
		return "", fmt.Errorf("could not determine the network id: networks entry has no id or url")
	}
	return id, nil
}

// eeroFilterFields whitelists entry down to the given config fields.
func eeroFilterFields(entry map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields))
	for _, field := range fields {
		if value, ok := entry[field]; ok {
			out[field] = value
		}
	}
	return out
}

// sortEeroEntries orders entries by their "url" (every eero resource carries
// one), falling back to the compact JSON encoding. The cloud does not
// guarantee array order, and a stable order is what keeps identical state
// byte-identical across polls.
func sortEeroEntries(entries []map[string]any) {
	key := func(e map[string]any) string {
		if u, ok := e["url"].(string); ok && u != "" {
			return "url:" + u
		}
		encoded, err := json.Marshal(e)
		if err != nil {
			return ""
		}
		return "json:" + string(encoded)
	}
	sort.SliceStable(entries, func(i, j int) bool { return key(entries[i]) < key(entries[j]) })
}
