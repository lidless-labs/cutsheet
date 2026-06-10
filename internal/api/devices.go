package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/solomonneas/cutsheet/internal/collector"
	"github.com/solomonneas/cutsheet/internal/deviceconfig"
	"github.com/solomonneas/cutsheet/internal/store"
)

// redactedValue replaces credential material in API responses.
const redactedValue = "***"

// sensitiveConfigKeys are the top-level collector-config fields that are
// never returned by the API, regardless of collector type (defense in depth:
// even a future collector type with a "password" field stays redacted).
var sensitiveConfigKeys = []string{"password", "private_key"}

// deviceJSON is the wire form of a device. CollectorConfig is the parsed
// config object with credential fields redacted; plaintext or ciphertext,
// they never leave the server.
type deviceJSON struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Vendor              string          `json:"vendor"`
	Address             string          `json:"address"`
	CollectorType       string          `json:"collector_type"`
	CollectorConfig     json.RawMessage `json:"collector_config"`
	PollIntervalSeconds int             `json:"poll_interval_seconds"`
	Enabled             bool            `json:"enabled"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

func toDeviceJSON(d store.Device) deviceJSON {
	return deviceJSON{
		ID:                  d.ID,
		Name:                d.Name,
		Vendor:              d.Vendor,
		Address:             d.Address,
		CollectorType:       d.CollectorType,
		CollectorConfig:     redactConfig(d.CollectorConfig),
		PollIntervalSeconds: d.PollIntervalSeconds,
		Enabled:             d.Enabled,
		CreatedAt:           d.CreatedAt.UTC(),
		UpdatedAt:           d.UpdatedAt.UTC(),
	}
}

// redactConfig returns configJSON with every sensitive top-level field
// replaced by "***". A config that fails to parse is replaced wholesale with
// {} rather than risk echoing raw credential bytes.
func redactConfig(configJSON string) json.RawMessage {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return json.RawMessage("{}")
	}
	for _, key := range sensitiveConfigKeys {
		if v, ok := cfg[key].(string); ok && v != "" {
			cfg[key] = redactedValue
		}
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return json.RawMessage("{}")
	}
	return out
}

func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	devices, err := s.cfg.Store.ListDevices(r.Context())
	if err != nil {
		s.writeStoreError(w, err, "list devices")
		return
	}
	out := make([]deviceJSON, 0, len(devices))
	for _, d := range devices {
		out = append(out, toDeviceJSON(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) handleDeviceGet(w http.ResponseWriter, r *http.Request) {
	d, err := s.cfg.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "get device")
		return
	}
	writeJSON(w, http.StatusOK, toDeviceJSON(d))
}

// deviceCreateRequest mirrors `device add` defaults: name falls back to id,
// vendor to the collector-suggested mode, collector to "file" with {} config,
// interval to 300s, enabled to true.
type deviceCreateRequest struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Vendor              string          `json:"vendor"`
	Address             string          `json:"address"`
	CollectorType       string          `json:"collector_type"`
	CollectorConfig     json.RawMessage `json:"collector_config"`
	PollIntervalSeconds *int            `json:"poll_interval_seconds"`
	Enabled             *bool           `json:"enabled"`
}

func (s *Server) handleDeviceCreate(w http.ResponseWriter, r *http.Request) {
	var req deviceCreateRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}

	d := store.Device{
		ID:                  req.ID,
		Name:                req.Name,
		Vendor:              req.Vendor,
		Address:             req.Address,
		CollectorType:       req.CollectorType,
		CollectorConfig:     string(req.CollectorConfig),
		PollIntervalSeconds: 300,
		Enabled:             true,
	}
	if d.CollectorType == "" {
		d.CollectorType = "file"
	}
	if d.CollectorConfig == "" {
		d.CollectorConfig = "{}"
	}
	if req.PollIntervalSeconds != nil {
		d.PollIntervalSeconds = *req.PollIntervalSeconds
	}
	if req.Enabled != nil {
		d.Enabled = *req.Enabled
	}
	d = deviceconfig.ApplyDefaults(d)

	if err := deviceconfig.Validate(d); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	encrypted, ok := s.encryptConfig(w, d.CollectorType, d.CollectorConfig)
	if !ok {
		return
	}
	d.CollectorConfig = encrypted

	if err := s.cfg.Store.CreateDevice(r.Context(), d); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			writeError(w, http.StatusConflict, "conflict", "device "+d.ID+" already exists")
			return
		}
		s.writeStoreError(w, err, "create device")
		return
	}
	s.notifyDevicesChanged()

	created, err := s.cfg.Store.GetDevice(r.Context(), d.ID)
	if err != nil {
		s.writeStoreError(w, err, "get device")
		return
	}
	writeJSON(w, http.StatusCreated, toDeviceJSON(created))
}

// devicePatchRequest is a partial device update. Omitted fields keep their
// value. A collector_config containing "***" for a credential field keeps
// the stored credential (so clients can round-trip redacted GET responses).
type devicePatchRequest struct {
	Name                *string         `json:"name"`
	Vendor              *string         `json:"vendor"`
	Address             *string         `json:"address"`
	CollectorType       *string         `json:"collector_type"`
	CollectorConfig     json.RawMessage `json:"collector_config"`
	PollIntervalSeconds *int            `json:"poll_interval_seconds"`
	Enabled             *bool           `json:"enabled"`
}

func (s *Server) handleDevicePatch(w http.ResponseWriter, r *http.Request) {
	d, err := s.cfg.Store.GetDevice(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err, "get device")
		return
	}

	var req devicePatchRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return
	}

	if req.Name != nil {
		d.Name = *req.Name
	}
	if req.Vendor != nil {
		d.Vendor = *req.Vendor
	}
	if req.Address != nil {
		d.Address = *req.Address
	}
	if req.CollectorType != nil {
		d.CollectorType = *req.CollectorType
	}
	if req.PollIntervalSeconds != nil {
		d.PollIntervalSeconds = *req.PollIntervalSeconds
	}
	if req.Enabled != nil {
		d.Enabled = *req.Enabled
	}
	if req.CollectorConfig != nil {
		merged, err := mergeRedactedSecrets(string(req.CollectorConfig), d.CollectorConfig)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "invalid collector_config: "+err.Error())
			return
		}
		d.CollectorConfig = merged
	}

	if err := deviceconfig.Validate(d); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	encrypted, ok := s.encryptConfig(w, d.CollectorType, d.CollectorConfig)
	if !ok {
		return
	}
	d.CollectorConfig = encrypted

	if err := s.cfg.Store.UpdateDevice(r.Context(), d); err != nil {
		s.writeStoreError(w, err, "update device")
		return
	}
	s.notifyDevicesChanged()

	updated, err := s.cfg.Store.GetDevice(r.Context(), d.ID)
	if err != nil {
		s.writeStoreError(w, err, "get device")
		return
	}
	writeJSON(w, http.StatusOK, toDeviceJSON(updated))
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Store.DeleteDevice(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err, "delete device")
		return
	}
	s.notifyDevicesChanged()
	w.WriteHeader(http.StatusNoContent)
}

// encryptConfig encrypts credential fields for storage. Returns ok=false
// after writing an error response.
func (s *Server) encryptConfig(w http.ResponseWriter, collectorType, configJSON string) (string, bool) {
	if !collector.NeedsSecrets(collectorType) {
		return configJSON, true
	}
	if s.cfg.Secrets == nil {
		writeError(w, http.StatusInternalServerError, "internal", "secret store unavailable")
		return "", false
	}
	encrypted, err := collector.EncryptConfig(collectorType, []byte(configJSON), s.cfg.Secrets)
	if err != nil {
		s.cfg.Logger.Error("encrypt collector config failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "encrypt collector config failed")
		return "", false
	}
	return string(encrypted), true
}

// mergeRedactedSecrets returns newConfig with any credential field whose
// value is the redaction sentinel ("***") replaced by the stored value from
// oldConfig. This lets clients PATCH back a config object they previously
// Got without wiping credentials.
func mergeRedactedSecrets(newConfig, oldConfig string) (string, error) {
	var newCfg map[string]any
	if err := json.Unmarshal([]byte(newConfig), &newCfg); err != nil {
		return "", err
	}
	var oldCfg map[string]any
	if err := json.Unmarshal([]byte(oldConfig), &oldCfg); err != nil {
		// Old config unparsable: nothing to merge from.
		oldCfg = nil
	}
	for _, key := range sensitiveConfigKeys {
		if v, ok := newCfg[key].(string); ok && v == redactedValue {
			if old, ok := oldCfg[key].(string); ok {
				newCfg[key] = old
			} else {
				delete(newCfg, key)
			}
		}
	}
	out, err := json.Marshal(newCfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (s *Server) notifyDevicesChanged() {
	if s.cfg.DevicesChanged != nil {
		s.cfg.DevicesChanged()
	}
}
