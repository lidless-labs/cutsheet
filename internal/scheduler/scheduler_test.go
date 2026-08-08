package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lidless-labs/cutsheet/internal/snapshots"
	"github.com/lidless-labs/cutsheet/internal/store"
)

// fakeLister is an in-memory DeviceLister.
type fakeLister struct {
	mu      sync.Mutex
	devices []store.Device
}

func (f *fakeLister) ListDevices(ctx context.Context) ([]store.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]store.Device, len(f.devices))
	copy(out, f.devices)
	return out, nil
}

func (f *fakeLister) set(devices ...store.Device) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices = devices
}

// changeRecorder collects handler invocations.
type changeRecorder struct {
	mu    sync.Mutex
	calls []recordedChange
}

type recordedChange struct {
	deviceID string
	result   snapshots.SaveResult
}

func (r *changeRecorder) handler(ctx context.Context, device store.Device, result snapshots.SaveResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedChange{deviceID: device.ID, result: result})
}

func (r *changeRecorder) snapshot() []recordedChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedChange, len(r.calls))
	copy(out, r.calls)
	return out
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

func fileDevice(id, path string, intervalSeconds int, enabled bool) store.Device {
	return store.Device{
		ID:                  id,
		Name:                id,
		Vendor:              "auto",
		CollectorType:       "file",
		CollectorConfig:     `{"path":"` + path + `"}`,
		PollIntervalSeconds: intervalSeconds,
		Enabled:             enabled,
	}
}

func newTestScheduler(t *testing.T, lister DeviceLister, rec *changeRecorder) *Scheduler {
	t.Helper()
	snaps, err := snapshots.Open(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatalf("snapshots.Open: %v", err)
	}
	handler := func(ctx context.Context, device store.Device, result snapshots.SaveResult) {
		rec.handler(ctx, device, result)
		if err := snaps.MarkProcessed(device.ID, result.CommitHash); err != nil {
			t.Errorf("MarkProcessed: %v", err)
		}
	}
	sched := New(lister, snaps, handler, Options{
		Interval: func(d store.Device) time.Duration { return 50 * time.Millisecond },
	})
	return sched
}

func TestSchedulerFiresOnChangeNotOnIdentical(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "gw1.cfg")
	if err := os.WriteFile(cfgPath, []byte("hostname gw1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	lister := &fakeLister{}
	lister.set(fileDevice("gw1", cfgPath, 1, true))
	rec := &changeRecorder{}
	sched := newTestScheduler(t, lister, rec)

	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sched.Stop()

	// First poll snapshots new content -> one change.
	if !waitFor(t, 3*time.Second, func() bool { return len(rec.snapshot()) == 1 }) {
		t.Fatalf("first change: handler fired %d times, want 1", len(rec.snapshot()))
	}
	first := rec.snapshot()[0]
	if first.deviceID != "gw1" || !first.result.Changed || first.result.CommitHash == "" {
		t.Fatalf("first change: %+v", first)
	}

	// Identical content: several more ticks, no new handler calls.
	time.Sleep(300 * time.Millisecond)
	if got := len(rec.snapshot()); got != 1 {
		t.Fatalf("identical content: handler fired %d times, want 1", got)
	}

	// Changed content fires exactly once more, with prev linkage.
	if err := os.WriteFile(cfgPath, []byte("hostname gw1\nntp server 192.0.2.10\n"), 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	if !waitFor(t, 3*time.Second, func() bool { return len(rec.snapshot()) == 2 }) {
		t.Fatalf("second change: handler fired %d times, want 2", len(rec.snapshot()))
	}
	second := rec.snapshot()[1]
	if second.result.PrevCommitHash != first.result.CommitHash {
		t.Fatalf("second change PrevCommitHash = %q, want %q", second.result.PrevCommitHash, first.result.CommitHash)
	}
	if string(second.result.PrevContent) != "hostname gw1\n" {
		t.Fatalf("second change PrevContent = %q", second.result.PrevContent)
	}
}

func TestSchedulerSkipsDisabledAndManualDevices(t *testing.T) {
	dir := t.TempDir()
	enabledPath := filepath.Join(dir, "on.cfg")
	disabledPath := filepath.Join(dir, "off.cfg")
	manualPath := filepath.Join(dir, "manual.cfg")
	for _, p := range []string{enabledPath, disabledPath, manualPath} {
		if err := os.WriteFile(p, []byte("hostname x\n"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	lister := &fakeLister{}
	lister.set(
		fileDevice("on1", enabledPath, 1, true),
		fileDevice("off1", disabledPath, 1, false),
		fileDevice("manual1", manualPath, 0, true),
	)
	rec := &changeRecorder{}
	sched := newTestScheduler(t, lister, rec)
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sched.Stop()

	if !waitFor(t, 3*time.Second, func() bool { return len(rec.snapshot()) >= 1 }) {
		t.Fatal("enabled device never fired")
	}
	time.Sleep(300 * time.Millisecond)
	for _, call := range rec.snapshot() {
		if call.deviceID != "on1" {
			t.Fatalf("handler fired for %q, want only on1", call.deviceID)
		}
	}
}

func TestSchedulerRefreshPicksUpNewDevice(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "new.cfg")
	if err := os.WriteFile(cfgPath, []byte("hostname new1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	lister := &fakeLister{}
	rec := &changeRecorder{}
	sched := newTestScheduler(t, lister, rec)
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sched.Stop()

	time.Sleep(150 * time.Millisecond)
	if got := len(rec.snapshot()); got != 0 {
		t.Fatalf("no devices yet: handler fired %d times", got)
	}

	lister.set(fileDevice("new1", cfgPath, 1, true))
	if err := sched.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !waitFor(t, 3*time.Second, func() bool { return len(rec.snapshot()) == 1 }) {
		t.Fatal("new device never fired after Refresh")
	}
}

func TestSchedulerRefreshRemovesDevice(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "gone.cfg")
	if err := os.WriteFile(cfgPath, []byte("hostname gone1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	lister := &fakeLister{}
	lister.set(fileDevice("gone1", cfgPath, 1, true))
	rec := &changeRecorder{}
	sched := newTestScheduler(t, lister, rec)
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sched.Stop()

	if !waitFor(t, 3*time.Second, func() bool { return len(rec.snapshot()) == 1 }) {
		t.Fatal("device never fired before removal")
	}

	lister.set() // device removed
	if err := sched.Refresh(); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// A change after removal must not fire.
	if err := os.WriteFile(cfgPath, []byte("hostname gone1-changed\n"), 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := len(rec.snapshot()); got != 1 {
		t.Fatalf("after removal: handler fired %d times, want 1", got)
	}
}

func TestSchedulerSurvivesFetchErrors(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "late.cfg") // does not exist yet

	lister := &fakeLister{}
	lister.set(fileDevice("late1", cfgPath, 1, true))
	rec := &changeRecorder{}
	sched := newTestScheduler(t, lister, rec)
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sched.Stop()

	// Let several failing polls happen.
	time.Sleep(200 * time.Millisecond)
	if got := len(rec.snapshot()); got != 0 {
		t.Fatalf("missing file: handler fired %d times", got)
	}

	// Once the file appears, the loop recovers.
	if err := os.WriteFile(cfgPath, []byte("hostname late1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if !waitFor(t, 3*time.Second, func() bool { return len(rec.snapshot()) == 1 }) {
		t.Fatal("loop did not recover after fetch errors")
	}
}

func TestRefreshBeforeStart(t *testing.T) {
	rec := &changeRecorder{}
	sched := newTestScheduler(t, &fakeLister{}, rec)
	if err := sched.Refresh(); err == nil {
		t.Fatal("Refresh before Start: want error, got nil")
	}
}

// TestSchedulerReinvokesHandlerWhileUnprocessed covers the scheduler poll
// contract with SnapshotStore: skipping MarkProcessed leaves HEAD ahead of the
// processing cursor so identical polls re-enter the handler. Real
// Pipeline.HandleChange failure through makeProcessChange is covered in
// cmd/cutsheet.TestSchedulerRetriesAfterRealHandleChangeFailure.
func TestSchedulerReinvokesHandlerWhileUnprocessed(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "gw1.cfg")
	before := []byte("hostname gw1\n")
	after := []byte("hostname gw1\nntp server 192.0.2.10\n")
	if err := os.WriteFile(cfgPath, before, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	lister := &fakeLister{}
	lister.set(fileDevice("gw1", cfgPath, 1, true))

	snaps, err := snapshots.Open(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatalf("snapshots.Open: %v", err)
	}

	var mu sync.Mutex
	var calls []snapshots.SaveResult
	process := true
	handler := func(ctx context.Context, device store.Device, result snapshots.SaveResult) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, result)
		if !process {
			return
		}
		if err := snaps.MarkProcessed(device.ID, result.CommitHash); err != nil {
			t.Errorf("MarkProcessed: %v", err)
		}
	}

	sched := New(lister, snaps, handler, Options{
		Interval: func(d store.Device) time.Duration { return 50 * time.Millisecond },
	})
	if err := sched.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sched.Stop()

	if !waitFor(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(calls) == 1
	}) {
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		t.Fatalf("initial change: handler fired %d times, want 1", n)
	}

	mu.Lock()
	process = false
	mu.Unlock()
	if err := os.WriteFile(cfgPath, after, 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	if !waitFor(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(calls) >= 3
	}) {
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		t.Fatalf("unprocessed identical polls: handler fired %d times, want >= 3", n)
	}

	mu.Lock()
	second, third := calls[1], calls[2]
	mu.Unlock()
	if second.CommitHash != third.CommitHash {
		t.Fatalf("retry CommitHash = %q, want %q", third.CommitHash, second.CommitHash)
	}
	if string(third.PrevContent) != string(before) {
		t.Fatalf("retry PrevContent = %q, want %q", third.PrevContent, before)
	}

	mu.Lock()
	process = true
	mu.Unlock()
	stableAt := 0
	if !waitFor(t, 3*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if len(calls) < 3 {
			return false
		}
		if stableAt == 0 {
			stableAt = len(calls)
			return false
		}
		return len(calls) == stableAt
	}) {
		t.Fatal("handler kept firing after successful processing")
	}
}
