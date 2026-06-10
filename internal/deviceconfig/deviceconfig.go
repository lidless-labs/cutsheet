// Package deviceconfig validates device registrations. It is the shared
// validation path for every way a device enters the registry (the `device add`
// CLI and the REST API), so the two can never drift on what a legal device
// looks like.
package deviceconfig

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/solomonneas/cutsheet/internal/collector"
	"github.com/solomonneas/cutsheet/internal/store"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidID reports whether id is a legal device id slug: letters, digits,
// . _ -, starting with a letter or digit.
func ValidID(id string) bool {
	return idPattern.MatchString(id)
}

// Validate checks a device record for registration or update: id slug,
// non-negative poll interval, and a collector type + config that the
// collector factory accepts. It does not touch the database and never
// decrypts credentials (collector.New with a nil secrets box is
// validation-only by design).
func Validate(d store.Device) error {
	if d.ID == "" {
		return fmt.Errorf("device id is required")
	}
	if !ValidID(d.ID) {
		return fmt.Errorf("invalid device id %q: use letters, digits, . _ - (must start with a letter or digit)", d.ID)
	}
	if d.PollIntervalSeconds < 0 {
		return fmt.Errorf("interval must be >= 0, got %d", d.PollIntervalSeconds)
	}
	if _, err := collector.New(d.CollectorType, []byte(d.CollectorConfig), nil); err != nil {
		return fmt.Errorf("invalid collector: %w", err)
	}
	return nil
}

// ApplyDefaults fills the registration defaults shared by the CLI and the
// API: empty name falls back to the id, and an empty vendor falls back to
// the collector-suggested parser mode (or "auto" when there is none).
func ApplyDefaults(d store.Device) store.Device {
	if d.Name == "" {
		d.Name = d.ID
	}
	if d.Vendor == "" {
		if suggested := SuggestedVendor(d.CollectorType, []byte(d.CollectorConfig)); suggested != "" {
			d.Vendor = suggested
		} else {
			d.Vendor = "auto"
		}
	}
	return d
}

// SuggestedVendor picks a configdiff parser mode from the collector setup
// when the caller did not specify one: unifi collectors emit controller
// JSON, and ssh presets name the vendor they target. Returns "" when there
// is no better suggestion than "auto".
func SuggestedVendor(collectorType string, configJSON []byte) string {
	switch collectorType {
	case "unifi":
		return "unifi-json"
	case "ssh":
		var cfg struct {
			Preset string `json:"preset"`
		}
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			return ""
		}
		return collector.PresetVendor(cfg.Preset)
	default:
		return ""
	}
}
