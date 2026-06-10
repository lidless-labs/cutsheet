package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solomonneas/cutsheet/internal/api"
	"github.com/solomonneas/cutsheet/internal/notify"
	"github.com/solomonneas/cutsheet/internal/pipeline"
	"github.com/solomonneas/cutsheet/internal/secrets"
	"github.com/solomonneas/cutsheet/internal/store"
)

func TestParseDeviceAdd(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
		check   func(t *testing.T, got addedDevice)
	}{
		{
			name: "full flags",
			args: []string{
				"--id", "edge-gw1", "--name", "Edge Gateway", "--vendor", "edgeos",
				"--address", "198.18.0.1", "--collector", "file",
				"--config", `{"path":"/var/lib/cutsheet/fixtures/gw1.cfg"}`,
				"--interval", "300",
			},
			check: func(t *testing.T, got addedDevice) {
				d := got.device
				if d.ID != "edge-gw1" || d.Name != "Edge Gateway" || d.Vendor != "edgeos" ||
					d.Address != "198.18.0.1" || d.CollectorType != "file" ||
					d.PollIntervalSeconds != 300 || !d.Enabled {
					t.Fatalf("device: %+v", d)
				}
			},
		},
		{
			name: "defaults",
			args: []string{"--id", "sw1", "--collector", "file", "--config", `{"path":"/tmp/sw1.cfg"}`},
			check: func(t *testing.T, got addedDevice) {
				d := got.device
				if d.Name != "sw1" {
					t.Fatalf("Name default: got %q, want id", d.Name)
				}
				if d.Vendor != "auto" {
					t.Fatalf("Vendor default: got %q, want auto", d.Vendor)
				}
				if d.PollIntervalSeconds != 300 {
					t.Fatalf("interval default: got %d, want 300", d.PollIntervalSeconds)
				}
				if !d.Enabled {
					t.Fatal("Enabled default: got false, want true")
				}
			},
		},
		{
			name:    "missing id",
			args:    []string{"--collector", "file", "--config", `{"path":"/tmp/x.cfg"}`},
			wantErr: "--id",
		},
		{
			name:    "bad id characters",
			args:    []string{"--id", "bad id!", "--collector", "file", "--config", `{"path":"/tmp/x.cfg"}`},
			wantErr: "device id",
		},
		{
			name:    "unknown collector",
			args:    []string{"--id", "x1", "--collector", "carrier-pigeon", "--config", `{}`},
			wantErr: "collector",
		},
		{
			name:    "invalid collector config",
			args:    []string{"--id", "x1", "--collector", "file", "--config", `{"path":""}`},
			wantErr: "collector",
		},
		{
			name:    "negative interval",
			args:    []string{"--id", "x1", "--collector", "file", "--config", `{"path":"/tmp/x.cfg"}`, "--interval", "-5"},
			wantErr: "interval",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDeviceAdd(tt.args)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDeviceAdd: %v", err)
			}
			tt.check(t, got)
		})
	}
}

func TestValidDeviceID(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{"gw1", true},
		{"edge-gw1", true},
		{"core.sw_2", true},
		{"GW1", true},
		{"", false},
		{"-leading-dash", false},
		{"has space", false},
		{"slash/y", false},
		{"dots/../up", false},
	}
	for _, tt := range tests {
		if got := validDeviceID(tt.id); got != tt.want {
			t.Errorf("validDeviceID(%q) = %v, want %v", tt.id, got, tt.want)
		}
	}
}

func TestParseDeviceAddNetworkCollectors(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
		check   func(t *testing.T, got addedDevice)
	}{
		{
			name: "unifi defaults vendor to unifi-json",
			args: []string{"--id", "ctrl1", "--collector", "unifi",
				"--config", `{"url":"https://ctrl.example.invalid","username":"audit","password":"pw"}`},
			check: func(t *testing.T, got addedDevice) {
				if got.device.Vendor != "unifi-json" {
					t.Fatalf("Vendor: got %q, want unifi-json", got.device.Vendor)
				}
			},
		},
		{
			name: "explicit vendor wins over unifi default",
			args: []string{"--id", "ctrl1", "--vendor", "auto", "--collector", "unifi",
				"--config", `{"url":"https://ctrl.example.invalid","username":"audit","password":"pw"}`},
			check: func(t *testing.T, got addedDevice) {
				if got.device.Vendor != "auto" {
					t.Fatalf("Vendor: got %q, want explicit auto", got.device.Vendor)
				}
			},
		},
		{
			name: "ssh preset junos defaults vendor",
			args: []string{"--id", "mx1", "--collector", "ssh",
				"--config", `{"host":"mx1.example.invalid","username":"audit","password":"pw","preset":"junos","insecure_ignore_host_key":true}`},
			check: func(t *testing.T, got addedDevice) {
				if got.device.Vendor != "junos" {
					t.Fatalf("Vendor: got %q, want junos", got.device.Vendor)
				}
			},
		},
		{
			name: "ssh without preset keeps auto vendor",
			args: []string{"--id", "gw1", "--collector", "ssh",
				"--config", `{"host":"gw1.example.invalid","username":"audit","password":"pw","command":"show config","insecure_ignore_host_key":true}`},
			check: func(t *testing.T, got addedDevice) {
				if got.device.Vendor != "auto" {
					t.Fatalf("Vendor: got %q, want auto", got.device.Vendor)
				}
			},
		},
		{
			name: "unifi missing url rejected",
			args: []string{"--id", "ctrl1", "--collector", "unifi",
				"--config", `{"username":"audit","password":"pw"}`},
			wantErr: "url",
		},
		{
			name: "ssh missing host key policy rejected",
			args: []string{"--id", "gw1", "--collector", "ssh",
				"--config", `{"host":"gw1.example.invalid","username":"audit","password":"pw","preset":"edgeos"}`},
			wantErr: "host_key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDeviceAdd(tt.args)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDeviceAdd: %v", err)
			}
			tt.check(t, got)
		})
	}
}

func TestRunDeviceAddEncryptsCredentials(t *testing.T) {
	t.Setenv(secrets.EnvKey, "")
	dataDir := t.TempDir()

	err := runDeviceAdd([]string{
		"--data-dir", dataDir, "--id", "gw1", "--collector", "ssh",
		"--config", `{"host":"gw1.example.invalid","username":"audit","password":"tape-and-string","preset":"edgeos","insecure_ignore_host_key":true}`,
	})
	if err != nil {
		t.Fatalf("runDeviceAdd: %v", err)
	}

	st, err := openStore(dataDir)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()
	d, err := st.GetDevice(context.Background(), "gw1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(d.CollectorConfig), &cfg); err != nil {
		t.Fatalf("parse stored config: %v", err)
	}
	stored, _ := cfg["password"].(string)
	if !secrets.IsEncrypted(stored) {
		t.Fatalf("stored password not encrypted: %q", stored)
	}
	if strings.Contains(d.CollectorConfig, "tape-and-string") {
		t.Fatal("plaintext password leaked into stored config")
	}

	box, err := secrets.Open(dataDir)
	if err != nil {
		t.Fatalf("secrets.Open: %v", err)
	}
	plain, err := box.Decrypt(stored)
	if err != nil {
		t.Fatalf("Decrypt stored password: %v", err)
	}
	if string(plain) != "tape-and-string" {
		t.Fatalf("decrypted password: got %q", plain)
	}
}

func TestRunDeviceAddFileSkipsSecretKey(t *testing.T) {
	t.Setenv(secrets.EnvKey, "")
	dataDir := t.TempDir()
	err := runDeviceAdd([]string{
		"--data-dir", dataDir, "--id", "fx1", "--collector", "file",
		"--config", `{"path":"/var/lib/cutsheet/fixtures/fx1.cfg"}`,
	})
	if err != nil {
		t.Fatalf("runDeviceAdd: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "secret.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file collector should not generate a secret key (stat err: %v)", err)
	}
}

func TestResolveNotifySettings(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		want    notifySettings
		wantErr string
	}{
		{
			name: "defaults",
			want: notifySettings{minSeverity: "low"},
		},
		{
			name: "flags only",
			args: []string{
				"--webhook-url", "https://hooks.example.com/a",
				"--discord-webhook-url", "https://discord.example.com/b",
				"--notify-min-severity", "high",
			},
			want: notifySettings{
				webhookURL:  "https://hooks.example.com/a",
				discordURL:  "https://discord.example.com/b",
				minSeverity: "high",
			},
		},
		{
			name: "env fallback",
			env: map[string]string{
				"CUTSHEET_WEBHOOK_URL":         "https://hooks.example.com/env",
				"CUTSHEET_DISCORD_WEBHOOK_URL": "https://discord.example.com/env",
				"CUTSHEET_NOTIFY_MIN_SEVERITY": "medium",
			},
			want: notifySettings{
				webhookURL:  "https://hooks.example.com/env",
				discordURL:  "https://discord.example.com/env",
				minSeverity: "medium",
			},
		},
		{
			name: "flags win over env",
			args: []string{
				"--webhook-url", "https://hooks.example.com/flag",
				"--notify-min-severity", "none",
			},
			env: map[string]string{
				"CUTSHEET_WEBHOOK_URL":         "https://hooks.example.com/env",
				"CUTSHEET_DISCORD_WEBHOOK_URL": "https://discord.example.com/env",
				"CUTSHEET_NOTIFY_MIN_SEVERITY": "medium",
			},
			want: notifySettings{
				webhookURL:  "https://hooks.example.com/flag",
				discordURL:  "https://discord.example.com/env",
				minSeverity: "none",
			},
		},
		{
			name:    "invalid severity flag",
			args:    []string{"--notify-min-severity", "critical"},
			wantErr: "notify-min-severity",
		},
		{
			name:    "invalid severity env",
			env:     map[string]string{"CUTSHEET_NOTIFY_MIN_SEVERITY": "urgent"},
			wantErr: "notify-min-severity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("serve", flag.ContinueOnError)
			webhookURL := fs.String("webhook-url", "", "")
			discordURL := fs.String("discord-webhook-url", "", "")
			minSeverity := fs.String("notify-min-severity", "low", "")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("parse flags: %v", err)
			}
			getenv := func(key string) string { return tt.env[key] }
			got, err := resolveNotifySettings(fs, *webhookURL, *discordURL, *minSeverity, getenv)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveNotifySettings: %v", err)
			}
			if got != tt.want {
				t.Fatalf("settings:\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// readFixture loads a shared testdata fixture.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}

// TestSnapshotNowEndToEnd drives POST /devices/{id}/snapshot through the real
// serve wiring (store + snapshots + pipeline + file collector), the same
// composition runServe builds: an on-demand snapshot records the initial
// change, an unchanged config reports changed=false, and a changed config
// produces an analyzed change whose report bundle the API then serves.
func TestSnapshotNowEndToEnd(t *testing.T) {
	t.Setenv(secrets.EnvKey, "")
	dataDir := t.TempDir()

	st, snaps, err := openDataDir(dataDir)
	if err != nil {
		t.Fatalf("openDataDir: %v", err)
	}
	defer st.Close()

	cfgPath := filepath.Join(dataDir, "device.cfg")
	if err := os.WriteFile(cfgPath, readFixture(t, "sample-before.cfg"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	device := store.Device{
		ID: "gw1", Name: "gw1", Vendor: "auto",
		CollectorType:   "file",
		CollectorConfig: `{"path":"` + cfgPath + `"}`,
	}
	if err := st.CreateDevice(context.Background(), device); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pipe := pipeline.New(st, filepath.Join(dataDir, "reports"), logger)
	fanout := &notify.Fanout{Logger: logger}
	processChange := makeProcessChange(snaps, pipe, fanout, logger)
	handler := api.New(api.Config{
		Store:       st,
		SnapshotNow: makeSnapshotNow(st, snaps, nil, processChange),
		Logger:      logger,
	})

	post := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", target, nil)
		req.RemoteAddr = "127.0.0.1:50000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	get := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", target, nil)
		req.RemoteAddr = "127.0.0.1:50000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// First snapshot: initial change recorded.
	rec := post("/api/v1/devices/gw1/snapshot")
	if rec.Code != 200 {
		t.Fatalf("first snapshot status %d: %s", rec.Code, rec.Body.String())
	}
	var first struct {
		Changed bool `json:"changed"`
		Change  struct {
			ID          int64  `json:"id"`
			Summary     string `json:"summary"`
			MaxSeverity string `json:"max_severity"`
		} `json:"change"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if !first.Changed || first.Change.Summary != "initial snapshot" {
		t.Fatalf("first snapshot: %s", rec.Body.String())
	}

	// Same content again: no change.
	rec = post("/api/v1/devices/gw1/snapshot")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Fatalf("unchanged snapshot: %d %s", rec.Code, rec.Body.String())
	}

	// Mutate the config: analyzed change with findings and a report bundle.
	if err := os.WriteFile(cfgPath, readFixture(t, "sample-after.cfg"), 0o600); err != nil {
		t.Fatalf("write changed fixture: %v", err)
	}
	rec = post("/api/v1/devices/gw1/snapshot")
	if rec.Code != 200 {
		t.Fatalf("changed snapshot status %d: %s", rec.Code, rec.Body.String())
	}
	var changed struct {
		Changed bool `json:"changed"`
		Change  struct {
			ID          int64  `json:"id"`
			MaxSeverity string `json:"max_severity"`
			HasReport   bool   `json:"has_report"`
		} `json:"change"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &changed); err != nil {
		t.Fatalf("decode changed response: %v", err)
	}
	if !changed.Changed || !changed.Change.HasReport || changed.Change.MaxSeverity == "none" {
		t.Fatalf("changed snapshot: %s", rec.Body.String())
	}

	// The recorded change's report bundle is servable through the API.
	rec = get(fmt.Sprintf("/api/v1/changes/%d/reports", changed.Change.ID))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "report.html") {
		t.Fatalf("report list: %d %s", rec.Code, rec.Body.String())
	}
	rec = get(fmt.Sprintf("/api/v1/changes/%d/reports/report.html", changed.Change.ID))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("report.html: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestTokenCLI(t *testing.T) {
	dataDir := t.TempDir()

	// create prints the plaintext exactly once.
	out := captureStdout(t, func() {
		if err := runTokenCreate([]string{"--data-dir", dataDir, "--name", "ci"}); err != nil {
			t.Fatalf("token create: %v", err)
		}
	})
	if !strings.Contains(out, "cst_") {
		t.Fatalf("token create output missing plaintext: %q", out)
	}

	out = captureStdout(t, func() {
		if err := runTokenList([]string{"--data-dir", dataDir}); err != nil {
			t.Fatalf("token list: %v", err)
		}
	})
	if !strings.Contains(out, "ci") || strings.Contains(out, "cst_") {
		t.Fatalf("token list output: %q", out)
	}

	if err := runTokenRm([]string{"--data-dir", dataDir, "--id", "1"}); err != nil {
		t.Fatalf("token rm: %v", err)
	}
	st, err := openStore(dataDir)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.Close()
	n, err := st.CountTokens(context.Background())
	if err != nil {
		t.Fatalf("CountTokens: %v", err)
	}
	if n != 0 {
		t.Fatalf("tokens after rm = %d, want 0", n)
	}

	if err := runTokenRm([]string{"--data-dir", dataDir, "--id", "1"}); err == nil {
		t.Fatal("token rm of missing id should error")
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}
