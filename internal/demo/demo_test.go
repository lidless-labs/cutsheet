package demo

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidless-labs/cutsheet/internal/store"
)

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunSeedsDevicesAndAnalyzedChanges(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "demo-data")

	summary, err := Run(context.Background(), dataDir, discard())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.Devices != len(devices) {
		t.Fatalf("Devices = %d, want %d", summary.Devices, len(devices))
	}
	if want := 2 * len(devices); summary.Changes != want {
		t.Fatalf("Changes = %d, want %d", summary.Changes, want)
	}
	if summary.Findings == 0 {
		t.Fatal("Findings = 0, want > 0")
	}

	st, err := store.Open(filepath.Join(dataDir, "cutsheet.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	got, err := st.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(got) != len(devices) {
		t.Fatalf("devices in store = %d, want %d", len(got), len(devices))
	}

	for _, d := range devices {
		changes, err := st.ListChanges(ctx, store.ListChangesOptions{DeviceID: d.id})
		if err != nil {
			t.Fatalf("ListChanges(%s): %v", d.id, err)
		}
		if len(changes) != 2 {
			t.Fatalf("%s: %d changes, want 2 (initial + analyzed)", d.id, len(changes))
		}
		// Newest first: the analyzed change precedes the initial snapshot.
		analyzed, initial := changes[0], changes[1]
		if initial.Summary != "initial snapshot" {
			t.Errorf("%s: oldest change summary = %q, want initial snapshot", d.id, initial.Summary)
		}
		if analyzed.MaxSeverity != "high" {
			t.Errorf("%s: analyzed change severity = %q, want high", d.id, analyzed.MaxSeverity)
		}
		full, err := st.GetChange(ctx, analyzed.ID)
		if err != nil {
			t.Fatalf("GetChange(%d): %v", analyzed.ID, err)
		}
		if len(full.Findings) == 0 {
			t.Errorf("%s: analyzed change has no findings", d.id)
		}
		if analyzed.ReportDir == "" {
			t.Errorf("%s: analyzed change has no report dir", d.id)
		} else if _, err := os.Stat(filepath.Join(analyzed.ReportDir, "report.html")); err != nil {
			t.Errorf("%s: report.html missing: %v", d.id, err)
		}
	}

	// The seeded collectors must point inside the data dir, not at repo
	// testdata, so the data dir is self-contained and pollable.
	for _, d := range devices {
		dev, err := st.GetDevice(ctx, d.id)
		if err != nil {
			t.Fatalf("GetDevice(%s): %v", d.id, err)
		}
		wantPath := filepath.Join(dataDir, "demo-configs", d.configFile)
		if !strings.Contains(dev.CollectorConfig, wantPath) {
			t.Errorf("%s collector config %q does not point at %q", d.id, dev.CollectorConfig, wantPath)
		}
		if _, err := os.Stat(wantPath); err != nil {
			t.Errorf("%s demo config missing: %v", d.id, err)
		}
	}
}

func TestRunRefusesNonEmptyDataDir(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "existing.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Run(context.Background(), dataDir, discard())
	if err == nil {
		t.Fatal("Run on non-empty dir: want error, got nil")
	}
	if !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("error %q does not mention non-empty dir", err)
	}
}

func TestRunCreatesMissingDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "nested", "demo-data")
	if _, err := Run(context.Background(), dataDir, discard()); err != nil {
		t.Fatalf("Run into missing dir: %v", err)
	}
}
