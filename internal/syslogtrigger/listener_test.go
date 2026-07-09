package syslogtrigger

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
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

func TestListenerDropsPacketsDuringCooldown(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListenerWithOptions(t, lister, rec, Options{
		ListenAddr: "127.0.0.1:0",
		Debounce:   10 * time.Millisecond,
		Cooldown:   80 * time.Millisecond,
		MapTTL:     time.Minute,
	})
	defer cancel()

	sendSyslog(t, ln.Addr())
	if got := waitStarted(t, rec); got != "edge-gw1" {
		t.Fatalf("first snapshot device = %q, want edge-gw1", got)
	}
	waitCompleted(t, rec, 1)

	sendSyslog(t, ln.Addr())
	assertNoSnapshot(t, rec, 120*time.Millisecond)
	if got := rec.count(); got != 1 {
		t.Fatalf("snapshots after cooldown drop = %d, want 1", got)
	}

	sendSyslog(t, ln.Addr())
	if got := waitStarted(t, rec); got != "edge-gw1" {
		t.Fatalf("snapshot after cooldown = %q, want edge-gw1", got)
	}
	waitCompleted(t, rec, 2)
}

func TestListenerCooldownIsPerDevice(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{
		{
			ID:              "edge-gw1",
			Enabled:         true,
			CollectorType:   "file",
			CollectorConfig: `{"path":"/tmp/edge-gw1.cfg","syslog_source":"127.0.0.1"}`,
		},
		{
			ID:              "edge-gw2",
			Enabled:         true,
			CollectorType:   "file",
			CollectorConfig: `{"path":"/tmp/edge-gw2.cfg","syslog_source":"127.0.0.2"}`,
		},
	}}
	rec := newSnapshotRecorder()
	ln, cancel := startTestListenerWithOptions(t, lister, rec, Options{
		ListenAddr: "127.0.0.1:0",
		Debounce:   10 * time.Millisecond,
		Cooldown:   120 * time.Millisecond,
		MapTTL:     time.Minute,
	})
	defer cancel()

	sendSyslog(t, ln.Addr())
	if got := waitStarted(t, rec); got != "edge-gw1" {
		t.Fatalf("first snapshot device = %q, want edge-gw1", got)
	}
	waitCompleted(t, rec, 1)

	sendSyslog(t, ln.Addr())
	sendSyslogFrom(t, ln.Addr(), "127.0.0.2:0")
	if got := waitStarted(t, rec); got != "edge-gw2" {
		t.Fatalf("second snapshot device = %q, want edge-gw2", got)
	}
	waitCompleted(t, rec, 2)
	if ids := rec.idsSnapshot(); len(ids) != 2 || ids[0] != "edge-gw1" || ids[1] != "edge-gw2" {
		t.Fatalf("snapshots = %#v, want edge-gw1 then edge-gw2", ids)
	}
}

func TestListenerCooldownAbsorbsQueuedChatterAndAllowsOneLaterSnapshot(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	rec.block = make(chan struct{})
	ln, cancel := startTestListenerWithOptions(t, lister, rec, Options{
		ListenAddr: "127.0.0.1:0",
		Debounce:   25 * time.Millisecond,
		Cooldown:   120 * time.Millisecond,
		MapTTL:     time.Minute,
	})
	defer cancel()

	sendSyslog(t, ln.Addr())
	if got := waitStarted(t, rec); got != "edge-gw1" {
		t.Fatalf("first snapshot device = %q, want edge-gw1", got)
	}
	sendSyslog(t, ln.Addr())
	close(rec.block)
	waitCompleted(t, rec, 1)

	assertNoSnapshot(t, rec, 80*time.Millisecond)
	if got := rec.count(); got != 1 {
		t.Fatalf("snapshots during cooldown = %d, want 1", got)
	}

	time.Sleep(60 * time.Millisecond)
	sendSyslog(t, ln.Addr())
	if got := waitStarted(t, rec); got != "edge-gw1" {
		t.Fatalf("snapshot after cooldown = %q, want edge-gw1", got)
	}
	waitCompleted(t, rec, 2)
	assertNoSnapshot(t, rec, 70*time.Millisecond)
	if got := rec.count(); got != 2 {
		t.Fatalf("snapshots after cooldown expiry = %d, want 2", got)
	}
}

func TestListenerCooldownLogsAreRateLimitedAndCounted(t *testing.T) {
	lister := &fakeDeviceLister{devices: []store.Device{{
		ID:              "edge-gw1",
		Enabled:         true,
		CollectorType:   "ssh",
		CollectorConfig: `{"host":"127.0.0.1"}`,
	}}}
	rec := newSnapshotRecorder()
	logs := &recordingHandler{}
	ln, cancel := startTestListenerWithOptions(t, lister, rec, Options{
		ListenAddr:         "127.0.0.1:0",
		Debounce:           5 * time.Millisecond,
		Cooldown:           150 * time.Millisecond,
		MapTTL:             time.Minute,
		UnknownLogInterval: 40 * time.Millisecond,
		Logger:             slog.New(logs),
	})
	defer cancel()

	sendSyslog(t, ln.Addr())
	waitStarted(t, rec)
	waitCompleted(t, rec, 1)

	sendSyslog(t, ln.Addr())
	sendSyslog(t, ln.Addr())
	sendSyslog(t, ln.Addr())
	time.Sleep(50 * time.Millisecond)
	sendSyslog(t, ln.Addr())

	entries := logs.waitMessages(t, "syslog packet dropped during device cooldown", 2)
	if entries[0].suppressed != 0 {
		t.Fatalf("first cooldown log suppressed = %d, want 0", entries[0].suppressed)
	}
	if entries[1].suppressed != 2 {
		t.Fatalf("second cooldown log suppressed = %d, want 2", entries[1].suppressed)
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
	return startTestListenerWithOptions(t, lister, rec, Options{
		ListenAddr: "127.0.0.1:0",
		Debounce:   debounce,
		MapTTL:     ttl,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func startTestListenerWithOptions(t *testing.T, lister *fakeDeviceLister, rec *snapshotRecorder, opts Options) (*Listener, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ln := New(lister, rec.snapshot, opts)
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
	sendSyslogFrom(t, addr, "")
}

func sendSyslogFrom(t *testing.T, addr net.Addr, localAddr string) {
	t.Helper()
	var dialer net.Dialer
	if localAddr != "" {
		udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
		if err != nil {
			t.Fatalf("ResolveUDPAddr %q: %v", localAddr, err)
		}
		dialer.LocalAddr = udpAddr
	}
	conn, err := dialer.Dial("udp", addr.String())
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

func waitCompleted(t *testing.T, rec *snapshotRecorder, want int) {
	t.Helper()
	deadline := time.After(250 * time.Millisecond)
	for {
		if rec.count() >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("completed snapshots = %d, want at least %d", rec.count(), want)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

type logEntry struct {
	message    string
	suppressed int
}

type recordingHandler struct {
	mu      sync.Mutex
	entries []logEntry
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(ctx context.Context, r slog.Record) error {
	entry := logEntry{message: r.Message}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "suppressed" {
			entry.suppressed = int(a.Value.Int64())
		}
		return true
	})
	h.mu.Lock()
	h.entries = append(h.entries, entry)
	h.mu.Unlock()
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(name string) slog.Handler { return h }

func (h *recordingHandler) waitMessages(t *testing.T, message string, want int) []logEntry {
	t.Helper()
	deadline := time.After(250 * time.Millisecond)
	for {
		h.mu.Lock()
		var matches []logEntry
		for _, entry := range h.entries {
			if strings.Contains(entry.message, message) {
				matches = append(matches, entry)
			}
		}
		h.mu.Unlock()
		if len(matches) >= want {
			return matches
		}
		select {
		case <-deadline:
			t.Fatalf("log entries containing %q = %d, want %d", message, len(matches), want)
		default:
			time.Sleep(time.Millisecond)
		}
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
