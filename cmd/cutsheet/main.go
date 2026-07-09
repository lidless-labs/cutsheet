// Command cutsheet runs the Cutsheet server and manages the device registry.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/solomonneas/cutsheet/internal/api"
	"github.com/solomonneas/cutsheet/internal/collector"
	"github.com/solomonneas/cutsheet/internal/demo"
	"github.com/solomonneas/cutsheet/internal/deviceconfig"
	"github.com/solomonneas/cutsheet/internal/notify"
	"github.com/solomonneas/cutsheet/internal/pipeline"
	"github.com/solomonneas/cutsheet/internal/scheduler"
	"github.com/solomonneas/cutsheet/internal/secrets"
	"github.com/solomonneas/cutsheet/internal/snapshots"
	"github.com/solomonneas/cutsheet/internal/store"
	"github.com/solomonneas/cutsheet/internal/syslogtrigger"
	"github.com/solomonneas/cutsheet/internal/webui"
)

// version is the build version reported by /healthz (overridable via
// -ldflags "-X main.version=...").
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "cutsheet: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "device":
		return runDevice(args[1:])
	case "token":
		return runToken(args[1:])
	case "demo":
		return runDemo(args[1:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return usageError()
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory (database + snapshot repo)")
	listen := fs.String("listen", "127.0.0.1:8633", "REST API listen address (env CUTSHEET_LISTEN)")
	corsOrigin := fs.String("cors-origin", "", "allowed cross-origin Origin for the API, e.g. a UI dev server (env CUTSHEET_CORS_ORIGIN)")
	webhookURL := fs.String("webhook-url", "", "POST change events as JSON to this URL (env CUTSHEET_WEBHOOK_URL)")
	discordURL := fs.String("discord-webhook-url", "", "POST change embeds to this Discord webhook URL (env CUTSHEET_DISCORD_WEBHOOK_URL)")
	minSeverity := fs.String("notify-min-severity", "low", "minimum change severity to notify on: none, low, medium, high (env CUTSHEET_NOTIFY_MIN_SEVERITY)")
	syslogListen := fs.String("syslog-listen", "", "UDP syslog listen address for snapshot triggers, disabled when empty (env CUTSHEET_SYSLOG_LISTEN)")
	syslogDebounce := fs.Duration("syslog-debounce", 10*time.Second, "coalesce repeated syslog packets per device for this duration (env CUTSHEET_SYSLOG_DEBOUNCE)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return fmt.Errorf("serve requires --data-dir")
	}
	notifyCfg, err := resolveNotifySettings(fs, *webhookURL, *discordURL, *minSeverity, os.Getenv)
	if err != nil {
		return err
	}
	syslogCfg, err := resolveSyslogSettings(fs, *syslogListen, *syslogDebounce, os.Getenv)
	if err != nil {
		return err
	}
	// Flags win over env, same pattern as the notify settings.
	if !flagWasSet(fs, "listen") {
		if v := os.Getenv("CUTSHEET_LISTEN"); v != "" {
			*listen = v
		}
	}
	if !flagWasSet(fs, "cors-origin") {
		if v := os.Getenv("CUTSHEET_CORS_ORIGIN"); v != "" {
			*corsOrigin = v
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var notifiers []notify.Notifier
	if notifyCfg.webhookURL != "" {
		notifiers = append(notifiers, &notify.Webhook{URL: notifyCfg.webhookURL})
	}
	if notifyCfg.discordURL != "" {
		notifiers = append(notifiers, &notify.Discord{URL: notifyCfg.discordURL})
	}
	fanout := &notify.Fanout{Notifiers: notifiers, MinSeverity: notifyCfg.minSeverity, Logger: logger}

	st, snaps, err := openDataDir(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	box, err := secrets.Open(*dataDir)
	if err != nil {
		return fmt.Errorf("open secrets: %w", err)
	}

	// Every changed snapshot (including a device's first) flows through the
	// analysis pipeline: diff, report bundle, recorded change + findings.
	// processChange is the single analyze+record+notify path shared by the
	// scheduler tick handler and the API's snapshot-now callback.
	pipe := pipeline.New(st, filepath.Join(*dataDir, "reports"), logger)
	processChange := makeProcessChange(snaps, pipe, fanout, logger)
	handler := func(ctx context.Context, device store.Device, result snapshots.SaveResult) {
		// Same goroutine on purpose: the notifiers have their own timeouts,
		// and Fanout logs failures instead of returning them, so a dead
		// webhook can delay this device's poll loop briefly but never crash
		// or fail the pipeline.
		if _, err := processChange(ctx, device, result); err != nil {
			logger.Error("change analysis failed", "device", device.ID, "error", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sched := scheduler.New(st, snaps, handler, scheduler.Options{Logger: logger, Secrets: box})
	if err := sched.Start(ctx); err != nil {
		return fmt.Errorf("start scheduler: %w", err)
	}

	snapshotNow := makeSnapshotNow(st, snaps, box, processChange)
	var syslogListener *syslogtrigger.Listener
	if syslogCfg.listen != "" {
		syslogListener = syslogtrigger.New(st, func(ctx context.Context, deviceID string) error {
			change, changed, err := snapshotNow(ctx, deviceID)
			if err != nil {
				return err
			}
			if changed && change != nil {
				logger.Info("syslog-triggered snapshot recorded change",
					"device", deviceID, "change", change.ID, "severity", change.MaxSeverity)
			} else {
				logger.Info("syslog-triggered snapshot found no change", "device", deviceID)
			}
			return nil
		}, syslogtrigger.Options{
			ListenAddr: syslogCfg.listen,
			Debounce:   syslogCfg.debounce,
			Logger:     logger,
		})
		if err := syslogListener.Start(ctx); err != nil {
			sched.Stop()
			return fmt.Errorf("start syslog trigger: %w", err)
		}
	}

	apiHandler := api.New(api.Config{
		Store:       st,
		SnapshotNow: snapshotNow,
		Secrets:     box,
		DevicesChanged: func() {
			if err := sched.Refresh(); err != nil {
				logger.Error("scheduler refresh failed", "error", err)
			}
		},
		CORSOrigin: *corsOrigin,
		Version:    version,
		Logger:     logger,
	})
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		stop()
		if syslogListener != nil {
			_ = syslogListener.Wait()
		}
		sched.Stop()
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}
	// The embedded web UI handles every path the API does not: /api/ and
	// /healthz stay on the API handler (auth and all), everything else is the
	// SPA with index.html fallback for client routes.
	srv := &http.Server{Handler: webui.Root(apiHandler), ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	devices, err := st.ListDevices(ctx)
	if err != nil {
		stop()
		_ = srv.Close()
		if syslogListener != nil {
			_ = syslogListener.Wait()
		}
		sched.Stop()
		return err
	}
	logger.Info("cutsheet server started",
		"data_dir", *dataDir, "devices", len(devices), "listen", ln.Addr().String())
	if syslogListener != nil {
		logger.Info("syslog trigger started",
			"listen", syslogListener.Addr().String(),
			"debounce", syslogCfg.debounce.String())
	}

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		stop()
		if syslogListener != nil {
			_ = syslogListener.Wait()
		}
		sched.Stop()
		return fmt.Errorf("api server: %w", err)
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("api shutdown failed", "error", err)
	}
	sched.Stop()
	if syslogListener != nil {
		if err := syslogListener.Wait(); err != nil {
			logger.Error("syslog trigger shutdown failed", "error", err)
		}
	}
	return nil
}

// makeProcessChange builds the analyze+record+notify step that runs after a
// snapshot changed, shared verbatim by the scheduler's change handler and the
// API's snapshot-now path so the two can never diverge in behavior.
func makeProcessChange(snaps *snapshots.SnapshotStore, pipe *pipeline.Pipeline, fanout *notify.Fanout, logger *slog.Logger) func(context.Context, store.Device, snapshots.SaveResult) (store.Change, error) {
	return func(ctx context.Context, device store.Device, result snapshots.SaveResult) (store.Change, error) {
		current, err := snaps.GetAt(device.ID, result.CommitHash)
		if err != nil {
			return store.Change{}, fmt.Errorf("load snapshot content for commit %s: %w", result.CommitHash, err)
		}
		change, err := pipe.HandleChange(ctx, device, result, current)
		if err != nil {
			return store.Change{}, err
		}
		logger.Info("config change recorded",
			"device", device.ID,
			"severity", change.MaxSeverity,
			"findings", len(change.Findings),
			"report_dir", change.ReportDir)
		fanout.Notify(ctx, notify.EventFromChange(device, change))
		return change, nil
	}
}

// snapshotFetchTimeout bounds the collector fetch of an on-demand snapshot,
// mirroring the scheduler's default.
const snapshotFetchTimeout = 60 * time.Second

// makeSnapshotNow builds the API callback for POST /devices/{id}/snapshot:
// an immediate fetch+save, then the same processChange path a scheduled poll
// takes. The fetch+save prelude intentionally parallels scheduler.poll; it is
// not shared because the scheduler caches one collector per device loop and
// reports through a fire-and-forget handler, while this path builds a fresh
// collector from the current registry row and must return the recorded
// change.
func makeSnapshotNow(st *store.Store, snaps *snapshots.SnapshotStore, box *secrets.Box, processChange func(context.Context, store.Device, snapshots.SaveResult) (store.Change, error)) api.SnapshotNow {
	return func(ctx context.Context, deviceID string) (*store.Change, bool, error) {
		device, err := st.GetDevice(ctx, deviceID)
		if err != nil {
			return nil, false, err
		}
		coll, err := collector.New(device.CollectorType, []byte(device.CollectorConfig), box)
		if err != nil {
			return nil, false, fmt.Errorf("build collector: %w", err)
		}
		fetchCtx, cancel := context.WithTimeout(ctx, snapshotFetchTimeout)
		defer cancel()
		content, err := coll.Fetch(fetchCtx)
		if err != nil {
			return nil, false, fmt.Errorf("fetch config: %w", err)
		}
		result, err := snaps.Save(device.ID, content)
		if err != nil {
			return nil, false, fmt.Errorf("save snapshot: %w", err)
		}
		if !result.Changed {
			return nil, false, nil
		}
		change, err := processChange(ctx, device, result)
		if err != nil {
			return nil, false, err
		}
		return &change, true, nil
	}
}

// runDemo seeds a fresh data dir with sample devices and analyzed changes so
// the platform can be evaluated with zero hardware.
func runDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory to seed (must be empty or missing)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return fmt.Errorf("demo requires --data-dir")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	summary, err := demo.Run(context.Background(), *dataDir, logger)
	if err != nil {
		return err
	}
	fmt.Printf("Seeded demo data: %d devices, %d changes, %d risk findings.\n\n",
		summary.Devices, summary.Changes, summary.Findings)
	fmt.Println("Next steps:")
	fmt.Printf("  cutsheet serve --data-dir %s\n", *dataDir)
	fmt.Println("  open http://127.0.0.1:8633")
	return nil
}

// notifySettings is the resolved notification config for serve.
type notifySettings struct {
	webhookURL  string
	discordURL  string
	minSeverity string
}

// syslogSettings is the resolved syslog-trigger config for serve.
type syslogSettings struct {
	listen   string
	debounce time.Duration
}

// resolveNotifySettings merges notification flags with their environment
// fallbacks (CUTSHEET_WEBHOOK_URL, CUTSHEET_DISCORD_WEBHOOK_URL,
// CUTSHEET_NOTIFY_MIN_SEVERITY). An explicitly passed flag always wins over
// the environment; the env var only fills in when the flag was omitted.
func resolveNotifySettings(fs *flag.FlagSet, webhookURL, discordURL, minSeverity string, getenv func(string) string) (notifySettings, error) {
	s := notifySettings{webhookURL: webhookURL, discordURL: discordURL, minSeverity: minSeverity}
	if !flagWasSet(fs, "webhook-url") {
		if v := getenv("CUTSHEET_WEBHOOK_URL"); v != "" {
			s.webhookURL = v
		}
	}
	if !flagWasSet(fs, "discord-webhook-url") {
		if v := getenv("CUTSHEET_DISCORD_WEBHOOK_URL"); v != "" {
			s.discordURL = v
		}
	}
	if !flagWasSet(fs, "notify-min-severity") {
		if v := getenv("CUTSHEET_NOTIFY_MIN_SEVERITY"); v != "" {
			s.minSeverity = v
		}
	}
	switch s.minSeverity {
	case "none", "low", "medium", "high":
	default:
		return notifySettings{}, fmt.Errorf("invalid --notify-min-severity %q: use none, low, medium, or high", s.minSeverity)
	}
	return s, nil
}

// resolveSyslogSettings merges syslog trigger flags with their environment
// fallbacks (CUTSHEET_SYSLOG_LISTEN, CUTSHEET_SYSLOG_DEBOUNCE). An explicitly
// passed flag always wins over the environment.
func resolveSyslogSettings(fs *flag.FlagSet, listen string, debounce time.Duration, getenv func(string) string) (syslogSettings, error) {
	s := syslogSettings{listen: listen, debounce: debounce}
	if !flagWasSet(fs, "syslog-listen") {
		if v := getenv("CUTSHEET_SYSLOG_LISTEN"); v != "" {
			s.listen = v
		}
	}
	if !flagWasSet(fs, "syslog-debounce") {
		if v := getenv("CUTSHEET_SYSLOG_DEBOUNCE"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return syslogSettings{}, fmt.Errorf("invalid CUTSHEET_SYSLOG_DEBOUNCE %q: %w", v, err)
			}
			s.debounce = d
		}
	}
	if s.debounce <= 0 {
		return syslogSettings{}, fmt.Errorf("invalid --syslog-debounce %s: must be > 0", s.debounce)
	}
	return s, nil
}

func runDevice(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "add":
		return runDeviceAdd(args[1:])
	case "list":
		return runDeviceList(args[1:])
	case "rm":
		return runDeviceRm(args[1:])
	default:
		return usageError()
	}
}

// addedDevice is the parsed result of `device add` flags.
type addedDevice struct {
	dataDir string
	device  store.Device
}

func parseDeviceAdd(args []string) (addedDevice, error) {
	fs := flag.NewFlagSet("device add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory")
	id := fs.String("id", "", "device id (slug: letters, digits, . _ -)")
	name := fs.String("name", "", "display name (defaults to id)")
	vendor := fs.String("vendor", "auto", "configdiff parser mode (e.g. cisco-ios, unifi-json, auto)")
	address := fs.String("address", "", "device address")
	collectorType := fs.String("collector", "file", "collector type (file, unifi, ssh, eero)")
	configJSON := fs.String("config", "{}", "collector config JSON")
	interval := fs.Int("interval", 300, "poll interval in seconds (0 = manual only)")
	disabled := fs.Bool("disabled", false, "register the device without polling it")
	if err := fs.Parse(args); err != nil {
		return addedDevice{}, err
	}

	if *id == "" {
		return addedDevice{}, fmt.Errorf("device add requires --id")
	}
	d := store.Device{
		ID:                  *id,
		Name:                *name,
		Vendor:              *vendor,
		Address:             *address,
		CollectorType:       *collectorType,
		CollectorConfig:     *configJSON,
		PollIntervalSeconds: *interval,
		Enabled:             !*disabled,
	}
	// An omitted --vendor means "let the collector suggest one"; the flag
	// default "auto" only sticks when the user typed it (flag.Visit), so
	// ApplyDefaults sees the empty value it expects.
	if !flagWasSet(fs, "vendor") {
		d.Vendor = ""
	}
	d = deviceconfig.ApplyDefaults(d)
	// Shared validation (id slug, interval, collector type + config) lives in
	// internal/deviceconfig so the CLI and the REST API can never drift. The
	// nil secrets box inside Validate is fine: credentials are only decrypted
	// at fetch time.
	if err := deviceconfig.Validate(d); err != nil {
		return addedDevice{}, err
	}

	return addedDevice{dataDir: *dataDir, device: d}, nil
}

// validDeviceID delegates to the shared deviceconfig rules.
func validDeviceID(id string) bool {
	return deviceconfig.ValidID(id)
}

// flagWasSet reports whether the user passed the named flag explicitly.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func runDeviceAdd(args []string) error {
	parsed, err := parseDeviceAdd(args)
	if err != nil {
		return err
	}
	if parsed.dataDir == "" {
		return fmt.Errorf("device add requires --data-dir")
	}
	st, err := openStore(parsed.dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	// Encrypt credential fields before they touch the database. Only
	// credential-bearing collector types open the secrets box, so a file-only
	// setup never generates a key.
	if collector.NeedsSecrets(parsed.device.CollectorType) {
		box, err := secrets.Open(parsed.dataDir)
		if err != nil {
			return fmt.Errorf("open secrets: %w", err)
		}
		encrypted, err := collector.EncryptConfig(parsed.device.CollectorType, []byte(parsed.device.CollectorConfig), box)
		if err != nil {
			return err
		}
		parsed.device.CollectorConfig = string(encrypted)
	}

	if err := st.CreateDevice(context.Background(), parsed.device); err != nil {
		return err
	}
	fmt.Printf("Added device %s\n", parsed.device.ID)
	return nil
}

func runDeviceList(args []string) error {
	fs := flag.NewFlagSet("device list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return fmt.Errorf("device list requires --data-dir")
	}
	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	devices, err := st.ListDevices(context.Background())
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tVENDOR\tCOLLECTOR\tINTERVAL\tENABLED")
	for _, d := range devices {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%t\n",
			d.ID, d.Name, d.Vendor, d.CollectorType, d.PollIntervalSeconds, d.Enabled)
	}
	return w.Flush()
}

func runDeviceRm(args []string) error {
	fs := flag.NewFlagSet("device rm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory")
	id := fs.String("id", "", "device id to remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *id == "" {
		return fmt.Errorf("device rm requires --data-dir and --id")
	}
	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.DeleteDevice(context.Background(), *id); err != nil {
		return err
	}
	fmt.Printf("Removed device %s\n", *id)
	return nil
}

func runToken(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "create":
		return runTokenCreate(args[1:])
	case "list":
		return runTokenList(args[1:])
	case "rm":
		return runTokenRm(args[1:])
	default:
		return usageError()
	}
}

func runTokenCreate(args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory")
	name := fs.String("name", "", "token name (e.g. ci, laptop)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *name == "" {
		return fmt.Errorf("token create requires --data-dir and --name")
	}
	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	tok, plaintext, err := st.CreateToken(context.Background(), *name)
	if err != nil {
		return err
	}
	fmt.Printf("Created token %q (id %d)\n\n  %s\n\n", tok.Name, tok.ID, plaintext)
	fmt.Println("This token is shown once and cannot be recovered; store it now.")
	fmt.Println("The API now requires a bearer token on every request (including from localhost).")
	return nil
}

func runTokenList(args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return fmt.Errorf("token list requires --data-dir")
	}
	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	tokens, err := st.ListTokens(context.Background())
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tCREATED")
	for _, t := range tokens {
		fmt.Fprintf(w, "%d\t%s\t%s\n", t.ID, t.Name, t.CreatedAt.UTC().Format(time.RFC3339))
	}
	return w.Flush()
}

func runTokenRm(args []string) error {
	fs := flag.NewFlagSet("token rm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "data directory")
	idStr := fs.String("id", "", "token id to remove (see token list)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *idStr == "" {
		return fmt.Errorf("token rm requires --data-dir and --id")
	}
	id, err := strconv.ParseInt(*idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid token id %q", *idStr)
	}
	st, err := openStore(*dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.DeleteToken(context.Background(), id); err != nil {
		return err
	}
	fmt.Printf("Removed token %d\n", id)
	n, err := st.CountTokens(context.Background())
	if err == nil && n == 0 {
		fmt.Println("No tokens remain: the API now allows unauthenticated requests from localhost only.")
	}
	return nil
}

func openStore(dataDir string) (*store.Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	return store.Open(filepath.Join(dataDir, "cutsheet.db"))
}

func openDataDir(dataDir string) (*store.Store, *snapshots.SnapshotStore, error) {
	st, err := openStore(dataDir)
	if err != nil {
		return nil, nil, err
	}
	snaps, err := snapshots.Open(filepath.Join(dataDir, "snapshots"))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, snaps, nil
}

func usageError() error {
	printUsage()
	return fmt.Errorf("expected command: serve, demo, device add|list|rm, or token create|list|rm")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  cutsheet serve --data-dir ./data [--listen 127.0.0.1:8633] [--cors-origin URL]")
	fmt.Fprintln(os.Stderr, "  cutsheet device add --data-dir ./data --id edge-gw1 --name 'Edge Gateway' --vendor edgeos --collector file --config '{\"path\":\"/abs/path/gw1.cfg\"}' --interval 300")
	fmt.Fprintln(os.Stderr, "  cutsheet device list --data-dir ./data")
	fmt.Fprintln(os.Stderr, "  cutsheet device rm --data-dir ./data --id edge-gw1")
	fmt.Fprintln(os.Stderr, "  cutsheet demo --data-dir ./demo-data")
	fmt.Fprintln(os.Stderr, "  cutsheet token create --data-dir ./data --name ci")
	fmt.Fprintln(os.Stderr, "  cutsheet token list --data-dir ./data")
	fmt.Fprintln(os.Stderr, "  cutsheet token rm --data-dir ./data --id 1")
}
