package syslogtrigger

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/solomonneas/cutsheet/internal/store"
)

type fakeDeviceLister struct {
	mu      sync.Mutex
	devices []store.Device
}

func (f *fakeDeviceLister) ListDevices(ctx context.Context) ([]store.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]store.Device, len(f.devices))
	copy(out, f.devices)
	return out, nil
}

func (f *fakeDeviceLister) set(devices ...store.Device) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices = append(f.devices[:0], devices...)
}

type snapshotRecorder struct {
	mu      sync.Mutex
	ids     []string
	started chan string
	block   chan struct{}
}

func newSnapshotRecorder() *snapshotRecorder {
	return &snapshotRecorder{started: make(chan string, 20)}
}

func (r *snapshotRecorder) snapshot(ctx context.Context, deviceID string) error {
	r.started <- deviceID
	if r.block != nil {
		select {
		case <-r.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.mu.Lock()
	r.ids = append(r.ids, deviceID)
	r.mu.Unlock()
	return nil
}

func (r *snapshotRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ids)
}

func (r *snapshotRecorder) idsSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.ids))
	copy(out, r.ids)
	return out
}

func TestListenerMatchesSSHHost(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListener(t, lister, rec, 20*time.Millisecond, time.Minute)
	defer cancel()

	sendSyslog(t, ln.Addr())

	got := waitStarted(t, rec)
	if got != "edge-gw1" {
		t.Fatalf("snapshot device = %q, want edge-gw1", got)
	}
}

func TestListenerMatchesSyslogSource(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "file-router",
		Enabled:         true,
		CollectorType:   "file",
		CollectorConfig: `{"path":"/tmp/file-router.cfg","syslog_source":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListener(t, lister, rec, 20*time.Millisecond, time.Minute)
	defer cancel()

	sendSyslog(t, ln.Addr())

	got := waitStarted(t, rec)
	if got != "file-router" {
		t.Fatalf("snapshot device = %q, want file-router", got)
	}
}

func TestListenerDropsUnknownSource(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"198.18.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListener(t, lister, rec, 10*time.Millisecond, time.Minute)
	defer cancel()

	sendSyslog(t, ln.Addr())
	assertNoSnapshot(t, rec, 60*time.Millisecond)
}

func TestListenerDebouncesPerDevice(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListener(t, lister, rec, 35*time.Millisecond, time.Minute)
	defer cancel()

	sendSyslog(t, ln.Addr())
	sendSyslog(t, ln.Addr())
	sendSyslog(t, ln.Addr())

	got := waitStarted(t, rec)
	if got != "edge-gw1" {
		t.Fatalf("snapshot device = %q, want edge-gw1", got)
	}
	assertNoSnapshot(t, rec, 70*time.Millisecond)
	if ids := rec.idsSnapshot(); len(ids) != 1 || ids[0] != "edge-gw1" {
		t.Fatalf("snapshots = %#v, want one edge-gw1", ids)
	}
}

func TestListenerSkipsConcurrentTriggerForSameDevice(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	rec.block = make(chan struct{})
	ln, cancel := startTestListener(t, lister, rec, 15*time.Millisecond, time.Minute)
	defer cancel()

	sendSyslog(t, ln.Addr())
	if got := waitStarted(t, rec); got != "edge-gw1" {
		t.Fatalf("first snapshot device = %q, want edge-gw1", got)
	}

	sendSyslog(t, ln.Addr())
	assertNoSnapshot(t, rec, 80*time.Millisecond)
	close(rec.block)

	deadline := time.After(200 * time.Millisecond)
	for rec.count() == 0 {
		select {
		case <-deadline:
			t.Fatal("first snapshot did not finish")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if rec.count() != 1 {
		t.Fatalf("completed snapshots = %d, want 1", rec.count())
	}
}

func TestListenerRefreshesIPMapAfterTTL(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"198.18.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListener(t, lister, rec, 10*time.Millisecond, 40*time.Millisecond)
	defer cancel()

	sendSyslog(t, ln.Addr())
	assertNoSnapshot(t, rec, 25*time.Millisecond)

	lister.set(store.Device{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	})
	sendSyslog(t, ln.Addr())
	assertNoSnapshot(t, rec, 25*time.Millisecond)

	time.Sleep(45 * time.Millisecond)
	sendSyslog(t, ln.Addr())
	if got := waitStarted(t, rec); got != "edge-gw1" {
		t.Fatalf("snapshot device after TTL refresh = %q, want edge-gw1", got)
	}
}

func TestListenerShutsDownWithContext(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListener(t, lister, rec, 10*time.Millisecond, time.Minute)

	cancel()
	done := make(chan error, 1)
	go func() { done <- ln.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("listener did not stop after context cancellation")
	}

	sendSyslog(t, ln.Addr())
	assertNoSnapshot(t, rec, 40*time.Millisecond)
}

func startTestListener(t *testing.T, lister *fakeDeviceLister, rec *snapshotRecorder, debounce, ttl time.Duration) (*Listener, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln := New(lister, rec.snapshot, Options{
		ListenAddr: "127.0.0.1:0",
		Debounce:   debounce,
		MapTTL:     ttl,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err := ln.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		if err := ln.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait cleanup: %v", err)
		}
	})
	return ln, cancel
}

func sendSyslog(t *testing.T, addr net.Addr) {
	t.Helper()
	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("Dial udp: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("<189>config changed")); err != nil {
		t.Fatalf("Write syslog packet: %v", err)
	}
}

func waitStarted(t *testing.T, rec *snapshotRecorder) string {
	t.Helper()
	select {
	case id := <-rec.started:
		return id
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for snapshot callback")
		return ""
	}
}

func assertNoSnapshot(t *testing.T, rec *snapshotRecorder, d time.Duration) {
	t.Helper()
	select {
	case id := <-rec.started:
		t.Fatalf("unexpected snapshot callback for %s", id)
	case <-time.After(d):
	}
}

// A device that logs more often than the debounce interval must still
// snapshot: the window is fixed from the first packet, not reset per packet.
func TestListenerFixedWindowFiresUnderSustainedChatter(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListener(t, lister, rec, 60*time.Millisecond, time.Minute)
	defer cancel()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				// Best-effort chatter; not the test goroutine, so no t.Fatalf.
				if conn, err := net.Dial("udp", ln.Addr().String()); err == nil {
					_, _ = conn.Write([]byte("<189>config changed"))
					conn.Close()
				}
			}
		}
	}()

	got := waitStarted(t, rec)
	close(stop)
	<-done
	if got != "edge-gw1" {
		t.Fatalf("snapshot device = %q, want edge-gw1", got)
	}
}
