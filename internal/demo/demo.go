// Package demo seeds a fresh data directory with sample devices and real
// analyzed changes so Cutsheet can be evaluated with zero hardware. The
// fixtures are lab-safe copies of the shared testdata pairs (no RFC 1918
// addresses) embedded in the binary, so `cutsheet demo` works from any
// install location.
package demo

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/lidless-labs/cutsheet/internal/collector"
	"github.com/lidless-labs/cutsheet/internal/pipeline"
	"github.com/lidless-labs/cutsheet/internal/snapshots"
	"github.com/lidless-labs/cutsheet/internal/store"
)

//go:embed fixtures
var fixturesFS embed.FS

// device describes one seeded sample device and its before/after fixture
// pair. The "before" content is snapshotted first, then the config file is
// mutated to the "after" variant and snapshotted again, producing a real
// risk-analyzed change in the timeline.
type device struct {
	id            string
	name          string
	vendor        string
	address       string
	fixtureBefore string
	fixtureAfter  string
	configFile    string
}

// devices is the demo inventory: four vendors, all with fixture pairs known
// to produce high-severity findings.
var devices = []device{
	{
		id: "core-switch", name: "Core Switch", vendor: "cisco-ios",
		address:       "198.18.0.10",
		fixtureBefore: "catalyst-before.cfg", fixtureAfter: "catalyst-after.cfg",
		configFile: "core-switch.cfg",
	},
	{
		id: "branch-gateway", name: "Branch Gateway", vendor: "edgeos",
		address:       "198.18.0.1",
		fixtureBefore: "edgeos-before.cfg", fixtureAfter: "edgeos-after.cfg",
		configFile: "branch-gateway.cfg",
	},
	{
		id: "campus-unifi", name: "Campus UniFi Controller", vendor: "unifi-json",
		address:       "198.18.0.20",
		fixtureBefore: "unifi-before.json", fixtureAfter: "unifi-after.json",
		configFile: "campus-unifi.json",
	},
	{
		id: "dmz-firewall", name: "DMZ Firewall", vendor: "fortinet",
		address:       "198.18.0.30",
		fixtureBefore: "fortinet-before.cfg", fixtureAfter: "fortinet-after.cfg",
		configFile: "dmz-firewall.cfg",
	},
}

// Summary reports what Run seeded.
type Summary struct {
	Devices  int
	Changes  int
	Findings int
}

// Run seeds dataDir with the demo inventory: it copies the "before" fixtures
// into <dataDir>/demo-configs, registers a file-collector device per fixture,
// snapshots each, then mutates the fixture copies to their "after" variants
// and snapshots again so the timeline contains real analyzed changes with
// findings. It refuses to touch a non-empty data directory.
func Run(ctx context.Context, dataDir string, logger *slog.Logger) (Summary, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if err := ensureEmptyDir(dataDir); err != nil {
		return Summary{}, err
	}

	configsDir := filepath.Join(dataDir, "demo-configs")
	if err := os.MkdirAll(configsDir, 0o755); err != nil {
		return Summary{}, fmt.Errorf("create demo configs dir: %w", err)
	}

	st, err := store.Open(filepath.Join(dataDir, "cutsheet.db"))
	if err != nil {
		return Summary{}, err
	}
	defer st.Close()
	snaps, err := snapshots.Open(filepath.Join(dataDir, "snapshots"))
	if err != nil {
		return Summary{}, err
	}
	pipe := pipeline.New(st, filepath.Join(dataDir, "reports"), logger)

	var summary Summary

	// Phase 1: write the "before" configs, register the devices, snapshot.
	for _, d := range devices {
		cfgPath := filepath.Join(configsDir, d.configFile)
		if err := writeFixture(d.fixtureBefore, cfgPath); err != nil {
			return Summary{}, err
		}
		rec := store.Device{
			ID:                  d.id,
			Name:                d.name,
			Vendor:              d.vendor,
			Address:             d.address,
			CollectorType:       "file",
			CollectorConfig:     fmt.Sprintf("{\"path\":%q}", cfgPath),
			PollIntervalSeconds: 300,
			Enabled:             true,
		}
		if err := st.CreateDevice(ctx, rec); err != nil {
			return Summary{}, fmt.Errorf("create demo device %s: %w", d.id, err)
		}
		change, err := snapshot(ctx, st, snaps, pipe, d.id)
		if err != nil {
			return Summary{}, err
		}
		summary.Changes++
		summary.Findings += len(change.Findings)
	}
	summary.Devices = len(devices)

	// Phase 2: mutate every config to its "after" variant and snapshot again,
	// producing risk-analyzed changes in the timeline.
	for _, d := range devices {
		cfgPath := filepath.Join(configsDir, d.configFile)
		if err := writeFixture(d.fixtureAfter, cfgPath); err != nil {
			return Summary{}, err
		}
		change, err := snapshot(ctx, st, snaps, pipe, d.id)
		if err != nil {
			return Summary{}, err
		}
		summary.Changes++
		summary.Findings += len(change.Findings)
		logger.Info("demo change recorded",
			"device", d.id, "severity", change.MaxSeverity, "summary", change.Summary)
	}

	return summary, nil
}

// snapshot fetches the device's current config through its real collector,
// saves it to the snapshot store, and runs the analysis pipeline, exactly the
// path a scheduled poll takes.
func snapshot(ctx context.Context, st *store.Store, snaps *snapshots.SnapshotStore, pipe *pipeline.Pipeline, deviceID string) (store.Change, error) {
	dev, err := st.GetDevice(ctx, deviceID)
	if err != nil {
		return store.Change{}, err
	}
	coll, err := collector.New(dev.CollectorType, []byte(dev.CollectorConfig), nil)
	if err != nil {
		return store.Change{}, fmt.Errorf("build collector for %s: %w", deviceID, err)
	}
	content, err := coll.Fetch(ctx)
	if err != nil {
		return store.Change{}, fmt.Errorf("fetch config for %s: %w", deviceID, err)
	}
	result, err := snaps.Save(dev.ID, content)
	if err != nil {
		return store.Change{}, fmt.Errorf("save snapshot for %s: %w", deviceID, err)
	}
	if !result.Changed {
		return store.Change{}, fmt.Errorf("demo snapshot for %s recorded no change; fixtures out of sync", deviceID)
	}
	change, err := pipe.HandleChange(ctx, dev, result, content, "")
	if err != nil {
		return store.Change{}, fmt.Errorf("analyze change for %s: %w", deviceID, err)
	}
	return change, nil
}

// writeFixture copies an embedded fixture to dst.
func writeFixture(name, dst string) error {
	content, err := fs.ReadFile(fixturesFS, "fixtures/"+name)
	if err != nil {
		return fmt.Errorf("read embedded fixture %s: %w", name, err)
	}
	if err := os.WriteFile(dst, content, 0o644); err != nil {
		return fmt.Errorf("write demo config %s: %w", dst, err)
	}
	return nil
}

// ensureEmptyDir errors when dir exists and contains anything. A missing dir
// is created.
func ensureEmptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, 0o755)
	}
	if err != nil {
		return fmt.Errorf("inspect data dir: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("data dir %s is not empty; demo seeds a fresh directory only", dir)
	}
	return nil
}
