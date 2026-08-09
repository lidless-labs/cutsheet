package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cutsheet.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func testDevice(id string) Device {
	return Device{
		ID:                  id,
		Name:                "Edge Router " + id,
		Vendor:              "cisco-ios",
		Address:             "198.18.0.1",
		CollectorType:       "file",
		CollectorConfig:     `{"path":"/tmp/` + id + `.cfg"}`,
		PollIntervalSeconds: 300,
		Enabled:             true,
	}
}

func TestDeviceCRUD(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	dev := testDevice("core-sw1")
	if err := s.CreateDevice(ctx, dev); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	got, err := s.GetDevice(ctx, "core-sw1")
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.Name != dev.Name || got.Vendor != dev.Vendor || got.Address != dev.Address ||
		got.CollectorType != dev.CollectorType || got.CollectorConfig != dev.CollectorConfig ||
		got.PollIntervalSeconds != dev.PollIntervalSeconds || got.Enabled != dev.Enabled {
		t.Fatalf("GetDevice mismatch: got %+v want %+v", got, dev)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps not set: %+v", got)
	}

	// Duplicate ID is rejected.
	if err := s.CreateDevice(ctx, dev); err == nil {
		t.Fatal("CreateDevice duplicate: want error, got nil")
	}

	// Update.
	got.Name = "renamed"
	got.PollIntervalSeconds = 0
	got.Enabled = false
	if err := s.UpdateDevice(ctx, got); err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	updated, err := s.GetDevice(ctx, "core-sw1")
	if err != nil {
		t.Fatalf("GetDevice after update: %v", err)
	}
	if updated.Name != "renamed" || updated.PollIntervalSeconds != 0 || updated.Enabled {
		t.Fatalf("update not applied: %+v", updated)
	}
	if updated.UpdatedAt.Before(updated.CreatedAt) {
		t.Fatalf("UpdatedAt %v before CreatedAt %v", updated.UpdatedAt, updated.CreatedAt)
	}

	// List.
	if err := s.CreateDevice(ctx, testDevice("branch-fw1")); err != nil {
		t.Fatalf("CreateDevice second: %v", err)
	}
	devices, err := s.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("ListDevices: got %d devices, want 2", len(devices))
	}
	if devices[0].ID != "branch-fw1" || devices[1].ID != "core-sw1" {
		t.Fatalf("ListDevices order: got %q, %q", devices[0].ID, devices[1].ID)
	}

	// Delete.
	if err := s.DeleteDevice(ctx, "core-sw1"); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	if _, err := s.GetDevice(ctx, "core-sw1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDevice after delete: got %v, want ErrNotFound", err)
	}
	if err := s.DeleteDevice(ctx, "core-sw1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteDevice missing: got %v, want ErrNotFound", err)
	}
}

func TestGetDeviceNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetDevice(context.Background(), "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestRecordAndGetChange(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.CreateDevice(ctx, testDevice("gw1")); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	change := Change{
		DeviceID:       "gw1",
		CommitHash:     "abc123",
		PrevCommitHash: "def456",
		Summary:        "1 ACL broadened",
		MaxSeverity:    "high",
		AnalysisJSON:   `{"schema_version":"1.1"}`,
		ReportDir:      "/data/reports/gw1/1",
		Findings: []Finding{
			{FindingID: "RISK-001", Severity: "high", Category: "acl", Title: "ACL broadened to any", Recommendation: "Review rule 10."},
			{FindingID: "RISK-007", Severity: "low", Category: "logging", Title: "Logging host removed", Recommendation: "Confirm intent."},
		},
	}
	id, err := s.RecordChange(ctx, change)
	if err != nil {
		t.Fatalf("RecordChange: %v", err)
	}
	if id <= 0 {
		t.Fatalf("RecordChange id: got %d", id)
	}

	got, err := s.GetChange(ctx, id)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if got.DeviceID != "gw1" || got.CommitHash != "abc123" || got.PrevCommitHash != "def456" ||
		got.Summary != change.Summary || got.MaxSeverity != "high" ||
		got.AnalysisJSON != change.AnalysisJSON || got.ReportDir != change.ReportDir ||
		got.ChangedBy != "" {
		t.Fatalf("GetChange mismatch: %+v", got)
	}
	if got.DetectedAt.IsZero() {
		t.Fatal("DetectedAt not set")
	}
	if len(got.Findings) != 2 {
		t.Fatalf("findings: got %d, want 2", len(got.Findings))
	}
	if got.Findings[0].FindingID != "RISK-001" || got.Findings[0].Severity != "high" {
		t.Fatalf("finding[0] mismatch: %+v", got.Findings[0])
	}

	if _, err := s.GetChange(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetChange missing: got %v, want ErrNotFound", err)
	}
}

func TestRecordChangeChangedBy(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if err := s.CreateDevice(ctx, testDevice("gw1")); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	id, err := s.RecordChange(ctx, Change{
		DeviceID:    "gw1",
		CommitHash:  "abc123",
		MaxSeverity: "low",
		ChangedBy:   "alice",
	})
	if err != nil {
		t.Fatalf("RecordChange: %v", err)
	}
	got, err := s.GetChange(ctx, id)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if got.ChangedBy != "alice" {
		t.Fatalf("ChangedBy = %q, want alice", got.ChangedBy)
	}
	listed, err := s.ListChanges(ctx, ListChangesOptions{DeviceID: "gw1"})
	if err != nil {
		t.Fatalf("ListChanges: %v", err)
	}
	if len(listed) != 1 || listed[0].ChangedBy != "alice" {
		t.Fatalf("ListChanges ChangedBy = %+v", listed)
	}
}

func TestRecordChangeUnknownDevice(t *testing.T) {
	s := openTestStore(t)
	_, err := s.RecordChange(context.Background(), Change{DeviceID: "nope", CommitHash: "abc"})
	if err == nil {
		t.Fatal("want foreign key error, got nil")
	}
}

func TestListChanges(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	for _, id := range []string{"gw1", "gw2"} {
		if err := s.CreateDevice(ctx, testDevice(id)); err != nil {
			t.Fatalf("CreateDevice %s: %v", id, err)
		}
	}
	// 3 changes on gw1, 1 on gw2, inserted in order.
	for i, devID := range []string{"gw1", "gw1", "gw2", "gw1"} {
		_, err := s.RecordChange(ctx, Change{
			DeviceID:    devID,
			CommitHash:  "hash" + string(rune('a'+i)),
			MaxSeverity: "none",
		})
		if err != nil {
			t.Fatalf("RecordChange %d: %v", i, err)
		}
	}

	tests := []struct {
		name      string
		opts      ListChangesOptions
		wantLen   int
		wantFirst string // commit hash of first row (newest)
	}{
		{"global newest first", ListChangesOptions{}, 4, "hashd"},
		{"by device", ListChangesOptions{DeviceID: "gw1"}, 3, "hashd"},
		{"by other device", ListChangesOptions{DeviceID: "gw2"}, 1, "hashc"},
		{"limit", ListChangesOptions{Limit: 2}, 2, "hashd"},
		{"limit offset", ListChangesOptions{Limit: 2, Offset: 2}, 2, "hashb"},
		{"no match", ListChangesOptions{DeviceID: "ghost"}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ListChanges(ctx, tt.opts)
			if err != nil {
				t.Fatalf("ListChanges: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("len: got %d, want %d", len(got), tt.wantLen)
			}
			if tt.wantLen > 0 && got[0].CommitHash != tt.wantFirst {
				t.Fatalf("first: got %q, want %q", got[0].CommitHash, tt.wantFirst)
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"none", 0},
		{"low", 1},
		{"medium", 2},
		{"high", 3},
		{"", 0},
		{"catastrophic", 0}, // unknown severities rank with none
	}
	for _, tt := range tests {
		if got := SeverityRank(tt.severity); got != tt.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}
