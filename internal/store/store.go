// Package store persists the device registry and detected change records in a
// SQLite database. It is the single source of truth for what Cutsheet monitors
// and what it has observed; config contents themselves live in the snapshot
// repository, not here.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a requested device or change does not exist.
var ErrNotFound = errors.New("not found")

// Device is a monitored network device in the registry.
type Device struct {
	ID                  string
	Name                string
	Vendor              string // configdiff parser mode, e.g. "cisco-ios", "unifi-json", "auto"
	Address             string
	CollectorType       string // e.g. "file", "ssh", "unifi"
	CollectorConfig     string // collector-specific JSON
	PollIntervalSeconds int    // 0 = manual snapshots only
	Enabled             bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Change is one detected configuration change on a device.
type Change struct {
	ID             int64
	DeviceID       string
	DetectedAt     time.Time
	CommitHash     string
	PrevCommitHash string
	Summary        string
	MaxSeverity    string // none, low, medium, high
	AnalysisJSON   string // serialized configdiff.Analysis
	ReportDir      string
	Findings       []Finding
}

// Finding is one risk finding attached to a change.
type Finding struct {
	ID             int64
	ChangeID       int64
	FindingID      string // e.g. RISK-001
	Severity       string
	Category       string
	Title          string
	Recommendation string
}

// ListChangesOptions filters and pages ListChanges. A zero value lists all
// changes, newest first, without a limit.
type ListChangesOptions struct {
	DeviceID string
	Limit    int
	Offset   int
	// MinSeverity keeps only changes at or above this severity on the
	// none < low < medium < high ladder. Empty or "none" means no filter.
	MinSeverity string
}

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and applies
// any pending migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// modernc.org/sqlite serializes writes itself, but keeping a single
	// connection avoids SQLITE_BUSY churn between pooled connections.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	names, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(names)
	for _, name := range names {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&n); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if n > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, name, formatTime(time.Now())); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

const timeLayout = time.RFC3339Nano

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(timeLayout, s)
}

// CreateDevice inserts a new device. CreatedAt/UpdatedAt are set by the store.
func (s *Store) CreateDevice(ctx context.Context, d Device) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO devices (id, name, vendor, address, collector_type, collector_config, poll_interval_seconds, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.Name, d.Vendor, d.Address, d.CollectorType, d.CollectorConfig, d.PollIntervalSeconds, boolToInt(d.Enabled), now, now)
	if err != nil {
		return fmt.Errorf("create device %q: %w", d.ID, err)
	}
	return nil
}

// GetDevice returns the device with the given id, or ErrNotFound.
func (s *Store) GetDevice(ctx context.Context, id string) (Device, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, vendor, address, collector_type, collector_config, poll_interval_seconds, enabled, created_at, updated_at
		FROM devices WHERE id = ?`, id)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, fmt.Errorf("device %q: %w", id, ErrNotFound)
	}
	if err != nil {
		return Device{}, fmt.Errorf("get device %q: %w", id, err)
	}
	return d, nil
}

// ListDevices returns all devices ordered by id.
func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, vendor, address, collector_type, collector_config, poll_interval_seconds, enabled, created_at, updated_at
		FROM devices ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("list devices: %w", err)
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return devices, nil
}

// UpdateDevice updates all mutable fields of a device. UpdatedAt is set by the
// store; CreatedAt is never changed.
func (s *Store) UpdateDevice(ctx context.Context, d Device) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE devices
		SET name = ?, vendor = ?, address = ?, collector_type = ?, collector_config = ?, poll_interval_seconds = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		d.Name, d.Vendor, d.Address, d.CollectorType, d.CollectorConfig, d.PollIntervalSeconds, boolToInt(d.Enabled), formatTime(time.Now()), d.ID)
	if err != nil {
		return fmt.Errorf("update device %q: %w", d.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update device %q: %w", d.ID, err)
	}
	if n == 0 {
		return fmt.Errorf("device %q: %w", d.ID, ErrNotFound)
	}
	return nil
}

// DeleteDevice removes a device and (via foreign keys) its changes/findings.
func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete device %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete device %q: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("device %q: %w", id, ErrNotFound)
	}
	return nil
}

// RecordChange inserts a change and its findings in one transaction and
// returns the new change id. DetectedAt defaults to now if zero.
func (s *Store) RecordChange(ctx context.Context, c Change) (int64, error) {
	detectedAt := c.DetectedAt
	if detectedAt.IsZero() {
		detectedAt = time.Now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("record change: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO changes (device_id, detected_at, commit_hash, prev_commit_hash, summary, max_severity, analysis_json, report_dir)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.DeviceID, formatTime(detectedAt), c.CommitHash, c.PrevCommitHash, c.Summary, c.MaxSeverity, c.AnalysisJSON, c.ReportDir)
	if err != nil {
		return 0, fmt.Errorf("record change for device %q: %w", c.DeviceID, err)
	}
	changeID, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("record change for device %q: %w", c.DeviceID, err)
	}
	for _, f := range c.Findings {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO risk_findings (change_id, finding_id, severity, category, title, recommendation)
			VALUES (?, ?, ?, ?, ?, ?)`,
			changeID, f.FindingID, f.Severity, f.Category, f.Title, f.Recommendation); err != nil {
			return 0, fmt.Errorf("record finding %q: %w", f.FindingID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("record change for device %q: %w", c.DeviceID, err)
	}
	return changeID, nil
}

// GetChange returns one change with its findings, or ErrNotFound.
func (s *Store) GetChange(ctx context.Context, id int64) (Change, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, device_id, detected_at, commit_hash, prev_commit_hash, summary, max_severity, analysis_json, report_dir
		FROM changes WHERE id = ?`, id)
	c, err := scanChange(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Change{}, fmt.Errorf("change %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return Change{}, fmt.Errorf("get change %d: %w", id, err)
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, change_id, finding_id, severity, category, title, recommendation
		FROM risk_findings WHERE change_id = ? ORDER BY id`, id)
	if err != nil {
		return Change{}, fmt.Errorf("get change %d findings: %w", id, err)
	}
	defer rows.Close()
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.ChangeID, &f.FindingID, &f.Severity, &f.Category, &f.Title, &f.Recommendation); err != nil {
			return Change{}, fmt.Errorf("get change %d findings: %w", id, err)
		}
		c.Findings = append(c.Findings, f)
	}
	if err := rows.Err(); err != nil {
		return Change{}, fmt.Errorf("get change %d findings: %w", id, err)
	}
	return c, nil
}

// ListChanges returns changes newest first, optionally filtered by device and
// paged with Limit/Offset. Findings are not populated; use GetChange.
func (s *Store) ListChanges(ctx context.Context, opts ListChangesOptions) ([]Change, error) {
	query := `
		SELECT id, device_id, detected_at, commit_hash, prev_commit_hash, summary, max_severity, analysis_json, report_dir
		FROM changes`
	var conds []string
	var args []any
	if opts.DeviceID != "" {
		conds = append(conds, `device_id = ?`)
		args = append(args, opts.DeviceID)
	}
	if minRank := SeverityRank(opts.MinSeverity); minRank > 0 {
		// SQL cannot call SeverityRank, so expand the ladder into the set of
		// severities at or above the floor. Unknown stored severities rank as
		// none and are therefore excluded by any real floor, consistent with
		// SeverityRank semantics.
		var allowed []string
		for _, sev := range []string{"low", "medium", "high"} {
			if SeverityRank(sev) >= minRank {
				allowed = append(allowed, sev)
			}
		}
		placeholders := ""
		for i, sev := range allowed {
			if i > 0 {
				placeholders += ", "
			}
			placeholders += "?"
			args = append(args, sev)
		}
		conds = append(conds, `max_severity IN (`+placeholders+`)`)
	}
	for i, cond := range conds {
		if i == 0 {
			query += ` WHERE ` + cond
		} else {
			query += ` AND ` + cond
		}
	}
	query += ` ORDER BY detected_at DESC, id DESC`
	if opts.Limit > 0 {
		query += ` LIMIT ? OFFSET ?`
		args = append(args, opts.Limit, opts.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list changes: %w", err)
	}
	defer rows.Close()

	var changes []Change
	for rows.Next() {
		c, err := scanChange(rows)
		if err != nil {
			return nil, fmt.Errorf("list changes: %w", err)
		}
		changes = append(changes, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list changes: %w", err)
	}
	return changes, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDevice(row scanner) (Device, error) {
	var d Device
	var enabled int
	var createdAt, updatedAt string
	if err := row.Scan(&d.ID, &d.Name, &d.Vendor, &d.Address, &d.CollectorType, &d.CollectorConfig,
		&d.PollIntervalSeconds, &enabled, &createdAt, &updatedAt); err != nil {
		return Device{}, err
	}
	d.Enabled = enabled != 0
	var err error
	if d.CreatedAt, err = parseTime(createdAt); err != nil {
		return Device{}, fmt.Errorf("parse created_at: %w", err)
	}
	if d.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return Device{}, fmt.Errorf("parse updated_at: %w", err)
	}
	return d, nil
}

func scanChange(row scanner) (Change, error) {
	var c Change
	var detectedAt string
	if err := row.Scan(&c.ID, &c.DeviceID, &detectedAt, &c.CommitHash, &c.PrevCommitHash,
		&c.Summary, &c.MaxSeverity, &c.AnalysisJSON, &c.ReportDir); err != nil {
		return Change{}, err
	}
	var err error
	if c.DetectedAt, err = parseTime(detectedAt); err != nil {
		return Change{}, fmt.Errorf("parse detected_at: %w", err)
	}
	return c, nil
}

// SeverityRank returns the position of severity on the ladder
// none < low < medium < high (0..3). It is the canonical ordering for
// Change.MaxSeverity and Finding.Severity values; unknown severities rank
// with none so a new configdiff severity can never crash a rollup or
// filter, it just sorts low until callers learn it.
func SeverityRank(severity string) int {
	switch severity {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
