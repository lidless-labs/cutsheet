// Package collector fetches device configurations. Collectors are read-only
// by design: Cutsheet never writes to a device. v1 ships "file" (fixtures and
// demo mode), "unifi" (UniFi Network controller API), "ssh" (generic command
// runner with vendor presets), and "eero" (unofficial eero cloud API).
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/solomonneas/cutsheet/internal/secrets"
)

// Collector fetches the current configuration of one device.
type Collector interface {
	Fetch(ctx context.Context) ([]byte, error)
}

// factory builds a collector from its JSON config. The secrets box may be nil
// (e.g. config validation at device-add time); collectors that hold encrypted
// credentials defer decryption to Fetch and fail there if no box is available.
type factory func(configJSON []byte, box *secrets.Box) (Collector, error)

// factories maps collector type names to constructors. New collector types
// slot in here.
var factories = map[string]factory{
	"file":  newFileCollector,
	"unifi": newUnifiCollector,
	"ssh":   newSSHCollector,
	"eero":  newEeroCollector,
}

// sensitiveFields lists, per collector type, the top-level string fields in
// the collector config that hold credentials and must be encrypted at rest.
var sensitiveFields = map[string][]string{
	"unifi": {"password"},
	"ssh":   {"password", "private_key"},
	"eero":  {"session_token"},
}

// SensitiveFields returns a copy of the collector type's top-level config
// fields that hold credentials. Callers use this to keep API redaction and
// PATCH merge behavior aligned with the encryption boundary.
func SensitiveFields(collectorType string) []string {
	fields := sensitiveFields[collectorType]
	out := make([]string, len(fields))
	copy(out, fields)
	return out
}

// New builds a collector of the given type from its JSON config. box supplies
// decryption for encrypted credential fields and may be nil for
// validation-only construction.
func New(collectorType string, configJSON []byte, box *secrets.Box) (Collector, error) {
	f, ok := factories[collectorType]
	if !ok {
		return nil, fmt.Errorf("unknown collector type %q", collectorType)
	}
	return f(configJSON, box)
}

// NeedsSecrets reports whether the collector type carries credential fields
// that are encrypted at rest.
func NeedsSecrets(collectorType string) bool {
	return len(sensitiveFields[collectorType]) > 0
}

// EncryptConfig returns configJSON with the collector type's sensitive fields
// encrypted via box. Already-encrypted and empty fields pass through; types
// without sensitive fields return the input unchanged byte for byte.
func EncryptConfig(collectorType string, configJSON []byte, box *secrets.Box) ([]byte, error) {
	fields := sensitiveFields[collectorType]
	if len(fields) == 0 {
		return configJSON, nil
	}
	var cfg map[string]any
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s collector config: %w", collectorType, err)
	}
	for _, field := range fields {
		value, ok := cfg[field].(string)
		if !ok || value == "" || secrets.IsEncrypted(value) {
			continue
		}
		enc, err := box.Encrypt([]byte(value))
		if err != nil {
			return nil, fmt.Errorf("encrypt %s config field %q: %w", collectorType, field, err)
		}
		cfg[field] = enc
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal %s collector config: %w", collectorType, err)
	}
	return out, nil
}

// decryptIfNeeded returns the plaintext of value, decrypting enc:v1: values
// via box. Plaintext values pass through so dev/test setups keep working.
func decryptIfNeeded(value, field string, box *secrets.Box) (string, error) {
	if !secrets.IsEncrypted(value) {
		return value, nil
	}
	if box == nil {
		return "", fmt.Errorf("field %q is encrypted but no secret key is available", field)
	}
	plaintext, err := box.Decrypt(value)
	if err != nil {
		return "", fmt.Errorf("decrypt field %q: %w", field, err)
	}
	return string(plaintext), nil
}

// fileCollector reads a config from a local file. Used for fixture-driven
// tests and the zero-hardware demo mode.
type fileCollector struct {
	path string
}

func newFileCollector(configJSON []byte, _ *secrets.Box) (Collector, error) {
	var cfg struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("parse file collector config: %w", err)
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("file collector config: %q is required", "path")
	}
	return &fileCollector{path: cfg.Path}, nil
}

func (c *fileCollector) Fetch(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	content, err := os.ReadFile(c.path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return content, nil
}
