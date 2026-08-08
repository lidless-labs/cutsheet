// Package scheduler polls enabled devices on their configured interval,
// snapshots fetched configs, and invokes a change handler when content
// actually changed. The analysis pipeline plugs in behind the handler.
package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lidless-labs/cutsheet/internal/collector"
	"github.com/lidless-labs/cutsheet/internal/secrets"
	"github.com/lidless-labs/cutsheet/internal/snapshots"
	"github.com/lidless-labs/cutsheet/internal/store"
)

// defaultFetchTimeout bounds a single collector fetch.
const defaultFetchTimeout = 60 * time.Second

// DeviceLister supplies the current device set; satisfied by *store.Store.
type DeviceLister interface {
	ListDevices(ctx context.Context) ([]store.Device, error)
}

// ChangeHandler is invoked when a poll produced new or changed content.
type ChangeHandler func(ctx context.Context, device store.Device, result snapshots.SaveResult)

// Options tunes a Scheduler. The zero value is usable.
type Options struct {
	// Logger receives poll errors; defaults to slog.Default().
	Logger *slog.Logger
	// FetchTimeout bounds one collector fetch; defaults to 60s.
	FetchTimeout time.Duration
	// Interval overrides the per-device poll interval (tests use this to run
	// sub-second). Defaults to PollIntervalSeconds.
	Interval func(store.Device) time.Duration
	// Secrets decrypts encrypted collector credentials. Nil is fine for
	// collectors without credentials (e.g. file).
	Secrets *secrets.Box
}

// Scheduler runs one polling goroutine per enabled device.
type Scheduler struct {
	lister  DeviceLister
	snaps   *snapshots.SnapshotStore
	handler ChangeHandler
	opts    Options

	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	loops  map[string]*deviceLoop
	wg     sync.WaitGroup
}

type deviceLoop struct {
	cancel context.CancelFunc
	device store.Device
}

// New builds a Scheduler. Call Start to begin polling.
func New(lister DeviceLister, snaps *snapshots.SnapshotStore, handler ChangeHandler, opts Options) *Scheduler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.FetchTimeout <= 0 {
		opts.FetchTimeout = defaultFetchTimeout
	}
	if opts.Interval == nil {
		opts.Interval = func(d store.Device) time.Duration {
			return time.Duration(d.PollIntervalSeconds) * time.Second
		}
	}
	return &Scheduler{
		lister:  lister,
		snaps:   snaps,
		handler: handler,
		opts:    opts,
		loops:   make(map[string]*deviceLoop),
	}
}

// Start loads the device set and begins polling. The provided context bounds
// the scheduler's lifetime; Stop also shuts it down.
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.ctx != nil {
		s.mu.Unlock()
		return errors.New("scheduler already started")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()
	return s.Refresh()
}

// Stop cancels all device loops and waits for them to exit.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Refresh re-reads the device set and reconciles running loops: new pollable
// devices get a loop, removed/disabled/manual-only devices lose theirs, and
// devices whose polling config changed are restarted.
func (s *Scheduler) Refresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return errors.New("scheduler not started")
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}

	devices, err := s.lister.ListDevices(s.ctx)
	if err != nil {
		return err
	}

	wanted := make(map[string]store.Device)
	for _, d := range devices {
		if d.Enabled && d.PollIntervalSeconds > 0 {
			wanted[d.ID] = d
		}
	}

	// Stop loops for devices that are gone or whose polling config changed.
	for id, loop := range s.loops {
		d, ok := wanted[id]
		if ok && samePollingConfig(loop.device, d) {
			continue
		}
		loop.cancel()
		delete(s.loops, id)
	}

	// Start loops for new (or restarted) devices.
	for id, d := range wanted {
		if _, ok := s.loops[id]; ok {
			continue
		}
		loopCtx, cancel := context.WithCancel(s.ctx)
		s.loops[id] = &deviceLoop{cancel: cancel, device: d}
		s.wg.Add(1)
		go s.run(loopCtx, d)
	}
	return nil
}

func samePollingConfig(a, b store.Device) bool {
	return a.PollIntervalSeconds == b.PollIntervalSeconds &&
		a.CollectorType == b.CollectorType &&
		a.CollectorConfig == b.CollectorConfig
}

// run is one device's polling loop. It never panics or exits on poll errors;
// it ends only when its context is cancelled.
func (s *Scheduler) run(ctx context.Context, device store.Device) {
	defer s.wg.Done()

	coll, err := collector.New(device.CollectorType, []byte(device.CollectorConfig), s.opts.Secrets)
	if err != nil {
		s.opts.Logger.Error("collector init failed, device not polled",
			"device", device.ID, "collector", device.CollectorType, "error", err)
		return
	}

	ticker := time.NewTicker(s.opts.Interval(device))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.poll(ctx, device, coll)
		}
	}
}

func (s *Scheduler) poll(ctx context.Context, device store.Device, coll collector.Collector) {
	fetchCtx, cancel := context.WithTimeout(ctx, s.opts.FetchTimeout)
	defer cancel()

	content, err := coll.Fetch(fetchCtx)
	if err != nil {
		if ctx.Err() == nil { // don't log shutdown races as fetch failures
			s.opts.Logger.Error("fetch failed", "device", device.ID, "error", err)
		}
		return
	}
	result, err := s.snaps.Save(device.ID, content)
	if err != nil {
		s.opts.Logger.Error("snapshot save failed", "device", device.ID, "error", err)
		return
	}
	if result.Changed && s.handler != nil {
		s.handler(ctx, device, result)
	}
}
