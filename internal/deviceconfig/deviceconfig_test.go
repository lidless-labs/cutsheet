package deviceconfig

import (
	"strings"
	"testing"

	"github.com/solomonneas/cutsheet/internal/store"
)

func TestValidID(t *testing.T) {
	valid := []string{"edge-gw1", "SW1", "a", "core.fw_2", "9rack"}
	for _, id := range valid {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false, want true", id)
		}
	}
	invalid := []string{"", "-leading", ".dot", "_under", "has space", "slash/y", "semi;colon", "dots/../up"}
	for _, id := range invalid {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true, want false", id)
		}
	}
}

func TestValidate(t *testing.T) {
	base := store.Device{
		ID:              "gw1",
		CollectorType:   "file",
		CollectorConfig: `{"path":"/var/lib/cutsheet/fixtures/gw1.cfg"}`,
	}
	tests := []struct {
		name    string
		mutate  func(d store.Device) store.Device
		wantErr string
	}{
		{name: "valid", mutate: func(d store.Device) store.Device { return d }},
		{
			name:    "missing id",
			mutate:  func(d store.Device) store.Device { d.ID = ""; return d },
			wantErr: "id is required",
		},
		{
			name:    "bad id",
			mutate:  func(d store.Device) store.Device { d.ID = "bad id!"; return d },
			wantErr: "device id",
		},
		{
			name:    "negative interval",
			mutate:  func(d store.Device) store.Device { d.PollIntervalSeconds = -1; return d },
			wantErr: "interval",
		},
		{
			name:    "unknown collector",
			mutate:  func(d store.Device) store.Device { d.CollectorType = "carrier-pigeon"; return d },
			wantErr: "collector",
		},
		{
			name:    "invalid collector config",
			mutate:  func(d store.Device) store.Device { d.CollectorConfig = `{"path":""}`; return d },
			wantErr: "collector",
		},
		{
			name:    "malformed collector config json",
			mutate:  func(d store.Device) store.Device { d.CollectorConfig = `{`; return d },
			wantErr: "collector",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.mutate(base))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	d := ApplyDefaults(store.Device{ID: "gw1", CollectorType: "file", CollectorConfig: `{"path":"/tmp/x.cfg"}`})
	if d.Name != "gw1" {
		t.Errorf("Name default = %q, want id", d.Name)
	}
	if d.Vendor != "auto" {
		t.Errorf("Vendor default = %q, want auto", d.Vendor)
	}

	d = ApplyDefaults(store.Device{ID: "ctl", CollectorType: "unifi", CollectorConfig: `{}`})
	if d.Vendor != "unifi-json" {
		t.Errorf("unifi Vendor default = %q, want unifi-json", d.Vendor)
	}

	d = ApplyDefaults(store.Device{ID: "gw2", Name: "Edge", Vendor: "edgeos", CollectorType: "file", CollectorConfig: `{}`})
	if d.Name != "Edge" || d.Vendor != "edgeos" {
		t.Errorf("explicit name/vendor overridden: %+v", d)
	}
}

func TestSuggestedVendor(t *testing.T) {
	if got := SuggestedVendor("unifi", []byte(`{}`)); got != "unifi-json" {
		t.Errorf("unifi: got %q", got)
	}
	if got := SuggestedVendor("ssh", []byte(`{"preset":"edgeos"}`)); got != "edgeos" {
		t.Errorf("ssh edgeos preset: got %q", got)
	}
	if got := SuggestedVendor("ssh", []byte(`not json`)); got != "" {
		t.Errorf("ssh bad json: got %q", got)
	}
	if got := SuggestedVendor("file", []byte(`{}`)); got != "" {
		t.Errorf("file: got %q", got)
	}
}
