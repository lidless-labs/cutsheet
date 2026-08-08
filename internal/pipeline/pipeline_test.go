package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidless-labs/cutsheet/internal/scheduler"
	"github.com/lidless-labs/cutsheet/internal/snapshots"
	"github.com/lidless-labs/cutsheet/internal/store"
	"github.com/lidless-labs/cutsheet/pkg/configdiff"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return content
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "cutsheet.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func createDevice(t *testing.T, st *store.Store, d store.Device) store.Device {
	t.Helper()
	if err := st.CreateDevice(context.Background(), d); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	return d
}

func TestHandleChangeInitialSnapshot(t *testing.T) {
	st := newTestStore(t)
	device := createDevice(t, st, store.Device{
		ID: "gw1", Name: "gw1", Vendor: "auto", CollectorType: "file",
	})
	p := New(st, filepath.Join(t.TempDir(), "reports"), testLogger())

	result := snapshots.SaveResult{
		Changed:    true,
		CommitHash: "0123456789abcdef0123456789abcdef01234567",
	}
	change, err := p.HandleChange(context.Background(), device, result, readFixture(t, "sample-before.cfg"), "")
	if err != nil {
		t.Fatalf("HandleChange: %v", err)
	}
	if change.ID == 0 {
		t.Fatal("change.ID = 0, want recorded id")
	}
	if change.Summary != "initial snapshot" {
		t.Fatalf("Summary = %q, want %q", change.Summary, "initial snapshot")
	}
	if change.MaxSeverity != "none" {
		t.Fatalf("MaxSeverity = %q, want none", change.MaxSeverity)
	}
	if change.ReportDir != "" {
		t.Fatalf("ReportDir = %q, want empty", change.ReportDir)
	}
	if len(change.Findings) != 0 {
		t.Fatalf("Findings = %d, want 0", len(change.Findings))
	}

	stored, err := st.GetChange(context.Background(), change.ID)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if stored.CommitHash != result.CommitHash || stored.Summary != "initial snapshot" || len(stored.Findings) != 0 {
		t.Fatalf("stored change: %+v", stored)
	}
}

func TestHandleChangeAnalyzed(t *testing.T) {
	st := newTestStore(t)
	device := createDevice(t, st, store.Device{
		ID: "edge1", Name: "edge1", Vendor: "", CollectorType: "file", // empty vendor must fall back to auto
	})
	reportsRoot := filepath.Join(t.TempDir(), "reports")
	p := New(st, reportsRoot, testLogger())

	before := readFixture(t, "sample-before.cfg")
	after := readFixture(t, "sample-after.cfg")
	result := snapshots.SaveResult{
		Changed:        true,
		CommitHash:     "fedcba9876543210fedcba9876543210fedcba98",
		PrevCommitHash: "0123456789abcdef0123456789abcdef01234567",
		PrevContent:    before,
	}
	change, err := p.HandleChange(context.Background(), device, result, after, "")
	if err != nil {
		t.Fatalf("HandleChange: %v", err)
	}

	if change.MaxSeverity != "high" {
		t.Fatalf("MaxSeverity = %q, want high", change.MaxSeverity)
	}
	if change.ChangedBy != "" {
		t.Fatalf("ChangedBy = %q, want empty without attribution", change.ChangedBy)
	}
	if len(change.Findings) == 0 {
		t.Fatal("Findings empty, want risk findings from sample fixtures")
	}
	for _, f := range change.Findings {
		if f.FindingID == "" || f.Severity == "" || f.Title == "" {
			t.Fatalf("incomplete finding: %+v", f)
		}
	}
	if !strings.Contains(change.Summary, "finding") {
		t.Fatalf("Summary = %q, want findings count line", change.Summary)
	}
	if change.PrevCommitHash != result.PrevCommitHash || change.CommitHash != result.CommitHash {
		t.Fatalf("commit linkage: %+v", change)
	}

	// Report dir: <root>/<deviceID>/<timestamp>-<short hash>, with the bundle inside.
	wantPrefix := filepath.Join(reportsRoot, device.ID) + string(filepath.Separator)
	if !strings.HasPrefix(change.ReportDir, wantPrefix) {
		t.Fatalf("ReportDir = %q, want prefix %q", change.ReportDir, wantPrefix)
	}
	if !strings.HasSuffix(change.ReportDir, "-fedcba98") {
		t.Fatalf("ReportDir = %q, want short-hash suffix -fedcba98", change.ReportDir)
	}
	for _, name := range []string{"report.html", "diff-analysis.json"} {
		if _, err := os.Stat(filepath.Join(change.ReportDir, name)); err != nil {
			t.Fatalf("report artifact %s: %v", name, err)
		}
	}

	// analysis_json round-trips and the platform fell back to auto-detection.
	var analysis configdiff.Analysis
	if err := json.Unmarshal([]byte(change.AnalysisJSON), &analysis); err != nil {
		t.Fatalf("unmarshal AnalysisJSON: %v", err)
	}
	if analysis.DetectedPlatform.RequestedVendor != "auto" {
		t.Fatalf("RequestedVendor = %q, want auto", analysis.DetectedPlatform.RequestedVendor)
	}
	if len(analysis.RiskFindings) != len(change.Findings) {
		t.Fatalf("findings mismatch: analysis %d, stored %d", len(analysis.RiskFindings), len(change.Findings))
	}

	stored, err := st.GetChange(context.Background(), change.ID)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if stored.MaxSeverity != "high" || len(stored.Findings) != len(change.Findings) {
		t.Fatalf("stored change: severity %q, findings %d", stored.MaxSeverity, len(stored.Findings))
	}
}

func TestHandleChangeChangedBy(t *testing.T) {
	st := newTestStore(t)
	device := createDevice(t, st, store.Device{
		ID: "gw1", Name: "gw1", Vendor: "auto", CollectorType: "file",
	})
	p := New(st, filepath.Join(t.TempDir(), "reports"), testLogger())
	before := readFixture(t, "sample-before.cfg")
	after := readFixture(t, "sample-after.cfg")
	result := snapshots.SaveResult{
		Changed:        true,
		CommitHash:     "fedcba9876543210fedcba9876543210fedcba98",
		PrevCommitHash: "0123456789abcdef0123456789abcdef01234567",
		PrevContent:    before,
	}
	change, err := p.HandleChange(context.Background(), device, result, after, "alice")
	if err != nil {
		t.Fatalf("HandleChange: %v", err)
	}
	if change.ChangedBy != "alice" {
		t.Fatalf("ChangedBy = %q, want alice", change.ChangedBy)
	}
	stored, err := st.GetChange(context.Background(), change.ID)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if stored.ChangedBy != "alice" {
		t.Fatalf("stored ChangedBy = %q, want alice", stored.ChangedBy)
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severities []string
		want       string
	}{
		{"no findings", nil, "none"},
		{"single low", []string{"low"}, "low"},
		{"medium beats low", []string{"low", "medium", "low"}, "medium"},
		{"high beats all", []string{"medium", "high", "low"}, "high"},
		{"unknown severity ignored", []string{"bogus", "low"}, "low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := make([]configdiff.RiskFinding, len(tt.severities))
			for i, s := range tt.severities {
				findings[i] = configdiff.RiskFinding{Severity: s}
			}
			if got := maxSeverity(findings); got != tt.want {
				t.Errorf("maxSeverity(%v) = %q, want %q", tt.severities, got, tt.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	tests := []struct {
		name     string
		analysis configdiff.Analysis
		want     string
	}{
		{
			name:     "no findings",
			analysis: configdiff.Analysis{BlockChanges: make([]configdiff.BlockChange, 2)},
			want:     "no findings - 2 blocks changed",
		},
		{
			name: "single finding single block",
			analysis: configdiff.Analysis{
				BlockChanges: make([]configdiff.BlockChange, 1),
				RiskFindings: []configdiff.RiskFinding{{Severity: "medium"}},
			},
			want: "1 finding (1 medium) - 1 block changed",
		},
		{
			name: "mixed severities counts the max tier",
			analysis: configdiff.Analysis{
				BlockChanges: make([]configdiff.BlockChange, 5),
				RiskFindings: []configdiff.RiskFinding{
					{Severity: "high"}, {Severity: "medium"}, {Severity: "low"},
				},
			},
			want: "3 findings (1 high) - 5 blocks changed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarize(tt.analysis); got != tt.want {
				t.Errorf("summarize() = %q, want %q", got, tt.want)
			}
		})
	}
}

// waitFor polls cond until it returns true or the deadline passes.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// TestEndToEndPollAnalyzeRecord drives a full cycle the way `cutsheet serve`
// does: scheduler polls a file collector, the snapshot store commits, and the
// pipeline records an initial snapshot then a risk-analyzed change.
func TestEndToEndPollAnalyzeRecord(t *testing.T) {
	dataDir := t.TempDir()
	st := newTestStore(t)
	snaps, err := snapshots.Open(filepath.Join(dataDir, "snapshots"))
	if err != nil {
		t.Fatalf("snapshots.Open: %v", err)
	}

	cfgPath := filepath.Join(dataDir, "gw1.cfg")
	if err := os.WriteFile(cfgPath, readFixture(t, "sample-before.cfg"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	device := createDevice(t, st, store.Device{
		ID: "gw1", Name: "gw1", Vendor: "auto",
		CollectorType: "file", CollectorConfig: `{"path":"` + cfgPath + `"}`,
		PollIntervalSeconds: 1, Enabled: true,
	})

	p := New(st, filepath.Join(dataDir, "reports"), testLogger())
	handler := func(ctx context.Context, d store.Device, result snapshots.SaveResult) {
		current, err := snaps.GetAt(d.ID, result.CommitHash)
		if err != nil {
			t.Errorf("GetAt: %v", err)
			return
		}
		if _, err := p.HandleChange(ctx, d, result, current, ""); err != nil {
			t.Errorf("HandleChange: %v", err)
			return
		}
		if err := snaps.MarkProcessed(d.ID, result.CommitHash); err != nil {
			t.Errorf("MarkProcessed: %v", err)
		}
	}
	sched := scheduler.New(st, snaps, handler, scheduler.Options{
		Logger:   testLogger(),
		Interval: func(store.Device) time.Duration { return 50 * time.Millisecond },
	})
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sched.Stop()

	countChanges := func() int {
		changes, err := st.ListChanges(context.Background(), store.ListChangesOptions{DeviceID: device.ID})
		if err != nil {
			t.Fatalf("ListChanges: %v", err)
		}
		return len(changes)
	}
	if !waitFor(t, 5*time.Second, func() bool { return countChanges() == 1 }) {
		t.Fatalf("initial snapshot: %d changes recorded, want 1", countChanges())
	}

	if err := os.WriteFile(cfgPath, readFixture(t, "sample-after.cfg"), 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	if !waitFor(t, 5*time.Second, func() bool { return countChanges() == 2 }) {
		t.Fatalf("analyzed change: %d changes recorded, want 2", countChanges())
	}
	sched.Stop()

	changes, err := st.ListChanges(context.Background(), store.ListChangesOptions{DeviceID: device.ID})
	if err != nil {
		t.Fatalf("ListChanges: %v", err)
	}
	// Newest first: changes[1] is the initial snapshot, changes[0] the analyzed one.
	if changes[1].Summary != "initial snapshot" || changes[1].MaxSeverity != "none" {
		t.Fatalf("initial change: %+v", changes[1])
	}
	analyzed, err := st.GetChange(context.Background(), changes[0].ID)
	if err != nil {
		t.Fatalf("GetChange: %v", err)
	}
	if analyzed.MaxSeverity != "high" || len(analyzed.Findings) == 0 {
		t.Fatalf("analyzed change: severity %q, findings %d", analyzed.MaxSeverity, len(analyzed.Findings))
	}
	if _, err := os.Stat(filepath.Join(analyzed.ReportDir, "report.html")); err != nil {
		t.Fatalf("report.html: %v", err)
	}
	if analyzed.PrevCommitHash != changes[1].CommitHash {
		t.Fatalf("PrevCommitHash = %q, want %q", analyzed.PrevCommitHash, changes[1].CommitHash)
	}
}
