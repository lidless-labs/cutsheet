// Package syslogtrigger starts on-demand snapshots from inbound syslog
// packets. It matches by sender IP only; parsing syslog message content is
// intentionally out of scope for the trigger path.
package syslogtrigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/solomonneas/cutsheet/internal/store"
)

const (
	defaultMapTTL             = 30 * time.Second
	defaultDebounce           = 10 * time.Second
	defaultUnknownLogInterval = 30 * time.Second
)

// DeviceLister supplies the current device set; satisfied by *store.Store.
type DeviceLister interface {
	ListDevices(ctx context.Context) ([]store.Device, error)
}

// SnapshotFunc triggers an immediate snapshot for one device.
type SnapshotFunc func(ctx context.Context, deviceID string) error

// Resolver is the subset of net.Resolver used for hostname collector configs.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Options tunes a Listener. The zero value is usable once ListenAddr is set.
type Options struct {
	// ListenAddr is the UDP listen address, for example "0.0.0.0:5514".
	ListenAddr string
	// Debounce coalesces repeated syslog packets for one device.
	Debounce time.Duration
	// MapTTL controls how long source IP to device matches are cached.
	MapTTL time.Duration
	// Resolver resolves DNS names in collector host/syslog_source fields.
	// Nil uses net.DefaultResolver.
	Resolver Resolver
	// Logger receives listener and trigger errors; defaults to slog.Default().
	Logger *slog.Logger
	// UnknownLogInterval rate-limits debug logs for unmatched source IPs.
	UnknownLogInterval time.Duration
}

// Listener binds a UDP socket and triggers snapshots for matched source IPs.
type Listener struct {
	lister   DeviceLister
	snapshot SnapshotFunc
	opts     Options
	logger   *slog.Logger
	resolver Resolver

	conn *net.UDPConn
	ctx  context.Context

	readWG    sync.WaitGroup
	pendingWG sync.WaitGroup

	mu                sync.Mutex
	readErr           error
	ipMap             map[string][]string
	mapExpires        time.Time
	debouncers        map[string]*debounceTimer
	inFlight          map[string]bool
	nextUnknownLog    time.Time
	unknownSuppressed int
}

type debounceTimer struct {
	timer      *time.Timer
	generation int
}

// New builds a Listener. Call Start to bind the UDP socket.
func New(lister DeviceLister, snapshot SnapshotFunc, opts Options) *Listener {
	if opts.ListenAddr == "" {
		opts.ListenAddr = ":0"
	}
	if opts.Debounce <= 0 {
		opts.Debounce = defaultDebounce
	}
	if opts.MapTTL <= 0 {
		opts.MapTTL = defaultMapTTL
	}
	if opts.UnknownLogInterval <= 0 {
		opts.UnknownLogInterval = defaultUnknownLogInterval
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Listener{
		lister:     lister,
		snapshot:   snapshot,
		opts:       opts,
		logger:     logger,
		resolver:   resolver,
		ipMap:      make(map[string][]string),
		debouncers: make(map[string]*debounceTimer),
		inFlight:   make(map[string]bool),
	}
}

// Start binds the UDP socket and starts the read loop.
func (l *Listener) Start(ctx context.Context) error {
	if l.lister == nil {
		return errors.New("syslogtrigger: nil device lister")
	}
	if l.snapshot == nil {
		return errors.New("syslogtrigger: nil snapshot callback")
	}
	addr, err := net.ResolveUDPAddr("udp", l.opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve syslog listen address %q: %w", l.opts.ListenAddr, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", l.opts.ListenAddr, err)
	}

	l.mu.Lock()
	if l.conn != nil {
		l.mu.Unlock()
		conn.Close()
		return errors.New("syslogtrigger: listener already started")
	}
	l.conn = conn
	l.ctx = ctx
	l.mu.Unlock()

	l.readWG.Add(1)
	go l.readLoop(ctx, conn)
	return nil
}

// Addr returns the bound UDP address. It is nil before Start succeeds.
func (l *Listener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil
	}
	return l.conn.LocalAddr()
}

// Wait waits for the read loop and any pending debounced trigger to exit.
func (l *Listener) Wait() error {
	l.readWG.Wait()
	l.pendingWG.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.readErr
}

func (l *Listener) readLoop(ctx context.Context, conn *net.UDPConn) {
	defer l.readWG.Done()
	closeOnCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer closeOnCancel()
	defer l.stopDebouncers()

	buf := make([]byte, 64*1024)
	for {
		_, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			l.setReadErr(fmt.Errorf("read syslog packet: %w", err))
			return
		}
		if remote == nil || remote.IP == nil {
			continue
		}
		sourceIP := remote.IP.String()
		deviceIDs, err := l.deviceIDsForSource(ctx, sourceIP)
		if err != nil {
			if ctx.Err() == nil {
				l.logger.Error("syslog source map refresh failed", "error", err)
			}
			continue
		}
		if len(deviceIDs) == 0 {
			l.logUnknown(sourceIP)
			continue
		}
		for _, deviceID := range deviceIDs {
			l.schedule(deviceID)
		}
	}
}

func (l *Listener) setReadErr(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.readErr = err
}

func (l *Listener) deviceIDsForSource(ctx context.Context, sourceIP string) ([]string, error) {
	now := time.Now()
	l.mu.Lock()
	if now.Before(l.mapExpires) {
		ids := append([]string(nil), l.ipMap[sourceIP]...)
		l.mu.Unlock()
		return ids, nil
	}
	l.mu.Unlock()

	devices, err := l.lister.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	next := make(map[string][]string)
	for _, d := range devices {
		if !d.Enabled {
			continue
		}
		for _, ip := range l.deviceSourceIPs(ctx, d) {
			next[ip] = append(next[ip], d.ID)
		}
	}

	l.mu.Lock()
	l.ipMap = next
	l.mapExpires = now.Add(l.opts.MapTTL)
	ids := append([]string(nil), l.ipMap[sourceIP]...)
	l.mu.Unlock()
	return ids, nil
}

func (l *Listener) deviceSourceIPs(ctx context.Context, d store.Device) []string {
	var cfg struct {
		Host         string `json:"host"`
		SyslogSource string `json:"syslog_source"`
	}
	if err := json.Unmarshal([]byte(d.CollectorConfig), &cfg); err != nil {
		l.logger.Debug("skip device with malformed collector config for syslog trigger",
			"device", d.ID, "error", err)
		return nil
	}

	var out []string
	if cfg.SyslogSource != "" {
		out = append(out, l.resolveHost(ctx, cfg.SyslogSource)...)
	}
	if d.CollectorType == "ssh" && cfg.Host != "" {
		out = append(out, l.resolveHost(ctx, cfg.Host)...)
	}
	return out
}

func (l *Listener) resolveHost(ctx context.Context, host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	addrs, err := l.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		l.logger.Debug("syslog trigger DNS resolution failed", "host", host, "error", err)
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			out = append(out, addr.IP.String())
		}
	}
	return out
}

func (l *Listener) schedule(deviceID string) {
	l.mu.Lock()
	// Fixed debounce window: the first packet arms the timer and later
	// packets coalesce into it without resetting it. A sliding window would
	// never fire on a device that logs more often than the debounce
	// interval, which is exactly the kind of device worth watching.
	if _, armed := l.debouncers[deviceID]; armed {
		l.mu.Unlock()
		return
	}
	state := &debounceTimer{generation: 1}
	l.debouncers[deviceID] = state
	generation := state.generation
	l.pendingWG.Add(1)
	state.timer = time.AfterFunc(l.opts.Debounce, func() {
		defer l.pendingWG.Done()
		l.fire(deviceID, generation)
	})
	l.mu.Unlock()
}

func (l *Listener) fire(deviceID string, generation int) {
	l.mu.Lock()
	state := l.debouncers[deviceID]
	if state == nil || state.generation != generation {
		l.mu.Unlock()
		return
	}
	delete(l.debouncers, deviceID)
	if l.inFlight[deviceID] {
		l.mu.Unlock()
		l.logger.Debug("syslog-triggered snapshot skipped; snapshot already in flight", "device", deviceID)
		return
	}
	l.inFlight[deviceID] = true
	ctx := l.ctx
	l.mu.Unlock()

	if err := l.snapshot(ctx, deviceID); err != nil && ctx.Err() == nil {
		l.logger.Error("syslog-triggered snapshot failed", "device", deviceID, "error", err)
	}

	l.mu.Lock()
	delete(l.inFlight, deviceID)
	l.mu.Unlock()
}

func (l *Listener) stopDebouncers() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for deviceID, state := range l.debouncers {
		if state.timer.Stop() {
			l.pendingWG.Done()
		}
		delete(l.debouncers, deviceID)
	}
}

func (l *Listener) logUnknown(sourceIP string) {
	now := time.Now()
	l.mu.Lock()
	if now.Before(l.nextUnknownLog) {
		l.unknownSuppressed++
		l.mu.Unlock()
		return
	}
	suppressed := l.unknownSuppressed
	l.unknownSuppressed = 0
	l.nextUnknownLog = now.Add(l.opts.UnknownLogInterval)
	l.mu.Unlock()

	l.logger.Debug("syslog packet from unknown source",
		"source", sourceIP,
		"suppressed", suppressed)
}
