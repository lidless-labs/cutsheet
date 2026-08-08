package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidless-labs/cutsheet/internal/secrets"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name          string
		collectorType string
		configJSON    string
		wantErr       bool
	}{
		{"file ok", "file", `{"path":"/etc/hostname"}`, false},
		{"file empty path", "file", `{"path":""}`, true},
		{"file missing path", "file", `{}`, true},
		{"file bad json", "file", `{`, true},
		{"unknown type", "carrier-pigeon", `{}`, true},
		{"empty type", "", `{}`, true},
		{"ssh incomplete config", "ssh", `{"address":"198.18.0.1"}`, true},
		{"unifi incomplete config", "unifi", `{"site":"default"}`, true},
		{"eero incomplete config", "eero", `{"network_id":"1"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(tt.collectorType, []byte(tt.configJSON), nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if c == nil {
				t.Fatal("New returned nil collector")
			}
		})
	}
}

func TestFileCollectorFetch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "running.cfg")
	want := "hostname gw1\ninterface eth0\n address 198.18.0.1/24\n"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	c, err := New("file", []byte(`{"path":"`+path+`"}`), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != want {
		t.Fatalf("Fetch: got %q, want %q", got, want)
	}
}

func TestFileCollectorFetchMissingFile(t *testing.T) {
	c, err := New("file", []byte(`{"path":"`+filepath.Join(t.TempDir(), "absent.cfg")+`"}`), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch missing file: want error, got nil")
	}
}

func TestFileCollectorFetchCancelledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "running.cfg")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	c, err := New("file", []byte(`{"path":"`+path+`"}`), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Fetch(ctx); err == nil {
		t.Fatal("Fetch with cancelled context: want error, got nil")
	}
}

func TestNeedsSecrets(t *testing.T) {
	tests := []struct {
		collectorType string
		want          bool
	}{
		{"file", false},
		{"unifi", true},
		{"ssh", true},
		{"eero", true},
		{"carrier-pigeon", false},
	}
	for _, tt := range tests {
		if got := NeedsSecrets(tt.collectorType); got != tt.want {
			t.Errorf("NeedsSecrets(%q) = %v, want %v", tt.collectorType, got, tt.want)
		}
	}
}

func TestEncryptConfig(t *testing.T) {
	box := testBox(t)

	t.Run("file passes through unchanged", func(t *testing.T) {
		in := `{"path": "/tmp/x.cfg"}` // odd spacing must survive untouched
		out, err := EncryptConfig("file", []byte(in), box)
		if err != nil {
			t.Fatalf("EncryptConfig: %v", err)
		}
		if string(out) != in {
			t.Fatalf("file config changed: got %q, want %q", out, in)
		}
	})

	t.Run("unifi password encrypted", func(t *testing.T) {
		out, err := EncryptConfig("unifi", []byte(`{"url":"https://c.example.invalid","username":"u","password":"hunter2"}`), box)
		if err != nil {
			t.Fatalf("EncryptConfig: %v", err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(out, &cfg); err != nil {
			t.Fatalf("parse output: %v", err)
		}
		password, _ := cfg["password"].(string)
		if !secrets.IsEncrypted(password) {
			t.Fatalf("password not encrypted: %q", password)
		}
		plain, err := box.Decrypt(password)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(plain) != "hunter2" {
			t.Fatalf("decrypted password: got %q", plain)
		}
		if url, _ := cfg["url"].(string); url != "https://c.example.invalid" {
			t.Fatalf("non-sensitive field changed: %q", url)
		}
	})

	t.Run("ssh password and private_key encrypted", func(t *testing.T) {
		out, err := EncryptConfig("ssh", []byte(`{"host":"h.example.invalid","username":"u","password":"p","private_key":"PEM"}`), box)
		if err != nil {
			t.Fatalf("EncryptConfig: %v", err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(out, &cfg); err != nil {
			t.Fatalf("parse output: %v", err)
		}
		for _, field := range []string{"password", "private_key"} {
			value, _ := cfg[field].(string)
			if !secrets.IsEncrypted(value) {
				t.Fatalf("%s not encrypted: %q", field, value)
			}
		}
	})

	t.Run("eero session_token encrypted", func(t *testing.T) {
		out, err := EncryptConfig("eero", []byte(`{"session_token":"tok-123","network_id":"1"}`), box)
		if err != nil {
			t.Fatalf("EncryptConfig: %v", err)
		}
		var cfg map[string]any
		if err := json.Unmarshal(out, &cfg); err != nil {
			t.Fatalf("parse output: %v", err)
		}
		token, _ := cfg["session_token"].(string)
		if !secrets.IsEncrypted(token) {
			t.Fatalf("session_token not encrypted: %q", token)
		}
		plain, err := box.Decrypt(token)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(plain) != "tok-123" {
			t.Fatalf("decrypted session_token: got %q", plain)
		}
		if id, _ := cfg["network_id"].(string); id != "1" {
			t.Fatalf("non-sensitive field changed: %q", id)
		}
	})

	t.Run("already encrypted passes through", func(t *testing.T) {
		enc, err := box.Encrypt([]byte("hunter2"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		out, err := EncryptConfig("unifi", []byte(`{"password":"`+enc+`"}`), box)
		if err != nil {
			t.Fatalf("EncryptConfig: %v", err)
		}
		var cfg map[string]string
		if err := json.Unmarshal(out, &cfg); err != nil {
			t.Fatalf("parse output: %v", err)
		}
		if cfg["password"] != enc {
			t.Fatalf("double encryption: got %q, want %q", cfg["password"], enc)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		if _, err := EncryptConfig("ssh", []byte(`{`), box); err == nil {
			t.Fatal("EncryptConfig with bad JSON: want error, got nil")
		}
	})
}
