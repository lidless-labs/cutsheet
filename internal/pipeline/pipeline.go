// Package pipeline turns a detected snapshot change into a recorded,
// risk-analyzed change: it diffs the previous and current configs with
// pkg/configdiff, writes the report bundle under the reports root, and
// persists the change row plus its findings in one store call.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/lidless-labs/cutsheet/internal/snapshots"
	"github.com/lidless-labs/cutsheet/internal/store"
	"github.com/lidless-labs/cutsheet/pkg/configdiff"
)

// Pipeline analyzes snapshot changes and records the results.
type Pipeline struct {
	store       *store.Store
	reportsRoot string
	logger      *slog.Logger
}

// New builds a Pipeline. Report bundles are written under reportsRoot, one
// directory per change.
func New(st *store.Store, reportsRoot string, logger *slog.Logger) *Pipeline {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pipeline{store: st, reportsRoot: reportsRoot, logger: logger}
}

// HandleChange records the change described by result. A first snapshot
// (result.PrevContent == nil) is recorded as-is with no analysis; any later
// change is diffed with configdiff.Explain, which also writes the report
// bundle (markdown, report.html, diff-analysis.json) to the change's report
// directory. changedBy is optional attribution from a syslog audit event.
func (p *Pipeline) HandleChange(ctx context.Context, device store.Device, result snapshots.SaveResult, currentContent []byte, changedBy string) (store.Change, error) {
	if result.PrevContent == nil {
		return p.recordInitial(ctx, device, result, changedBy)
	}
	return p.analyzeAndRecord(ctx, device, result, currentContent, changedBy)
}

func (p *Pipeline) recordInitial(ctx context.Context, device store.Device, result snapshots.SaveResult, changedBy string) (store.Change, error) {
	change := store.Change{
		DeviceID:     device.ID,
		DetectedAt:   time.Now(),
		CommitHash:   result.CommitHash,
		Summary:      "initial snapshot",
		MaxSeverity:  "none",
		AnalysisJSON: "{}",
		ChangedBy:    changedBy,
	}
	id, err := p.store.RecordChange(ctx, change)
	if err != nil {
		return store.Change{}, fmt.Errorf("record initial snapshot for device %q: %w", device.ID, err)
	}
	change.ID = id
	return change, nil
}

func (p *Pipeline) analyzeAndRecord(ctx context.Context, device store.Device, result snapshots.SaveResult, currentContent []byte, changedBy string) (store.Change, error) {
	// configdiff.Explain takes file paths; bridge the in-memory contents
	// through a throwaway temp dir. The report dir, in contrast, is the
	// product artifact and is kept.
	tmpDir, err := os.MkdirTemp("", "cutsheet-diff-")
	if err != nil {
		return store.Change{}, fmt.Errorf("create temp dir for device %q: %w", device.ID, err)
	}
	defer os.RemoveAll(tmpDir)

	beforePath := filepath.Join(tmpDir, "before.cfg")
	afterPath := filepath.Join(tmpDir, "after.cfg")
	if err := os.WriteFile(beforePath, result.PrevContent, 0o600); err != nil {
		return store.Change{}, fmt.Errorf("write before config for device %q: %w", device.ID, err)
	}
	if err := os.WriteFile(afterPath, currentContent, 0o600); err != nil {
		return store.Change{}, fmt.Errorf("write after config for device %q: %w", device.ID, err)
	}

	vendor := device.Vendor
	if vendor == "" {
		vendor = "auto"
	}
	detectedAt := time.Now()
	reportDir := filepath.Join(p.reportsRoot, device.ID,
		detectedAt.UTC().Format("20060102-150405")+"-"+shortHash(result.CommitHash))

	res, err := configdiff.Explain(configdiff.Options{
		BeforePath: beforePath,
		AfterPath:  afterPath,
		Vendor:     vendor,
		OutDir:     reportDir,
	})
	if err != nil {
		return store.Change{}, fmt.Errorf("analyze change for device %q: %w", device.ID, err)
	}

	analysisJSON, err := json.Marshal(res.Analysis)
	if err != nil {
		return store.Change{}, fmt.Errorf("marshal analysis for device %q: %w", device.ID, err)
	}

	findings := make([]store.Finding, 0, len(res.Analysis.RiskFindings))
	for _, f := range res.Analysis.RiskFindings {
		findings = append(findings, store.Finding{
			FindingID:      f.ID,
			Severity:       f.Severity,
			Category:       f.Category,
			Title:          f.Title,
			Recommendation: f.Recommendation,
		})
	}

	change := store.Change{
		DeviceID:       device.ID,
		DetectedAt:     detectedAt,
		CommitHash:     result.CommitHash,
		PrevCommitHash: result.PrevCommitHash,
		Summary:        summarize(res.Analysis),
		MaxSeverity:    maxSeverity(res.Analysis.RiskFindings),
		AnalysisJSON:   string(analysisJSON),
		ReportDir:      reportDir,
		ChangedBy:      changedBy,
		Findings:       findings,
	}
	id, err := p.store.RecordChange(ctx, change)
	if err != nil {
		return store.Change{}, fmt.Errorf("record change for device %q: %w", device.ID, err)
	}
	change.ID = id
	for i := range change.Findings {
		change.Findings[i].ChangeID = id
	}
	return change, nil
}

// maxSeverity returns the highest severity across findings, or "none" when
// there are no findings. The ladder itself is canonical in store.SeverityRank.
func maxSeverity(findings []configdiff.RiskFinding) string {
	max := "none"
	for _, f := range findings {
		if store.SeverityRank(f.Severity) > store.SeverityRank(max) {
			max = f.Severity
		}
	}
	return max
}

// summarize builds the one-line change summary, e.g.
// "3 findings (1 high) - 5 blocks changed".
func summarize(a configdiff.Analysis) string {
	blocks := plural(len(a.BlockChanges), "block")
	if len(a.RiskFindings) == 0 {
		return fmt.Sprintf("no findings - %s changed", blocks)
	}
	max := maxSeverity(a.RiskFindings)
	atMax := 0
	for _, f := range a.RiskFindings {
		if f.Severity == max {
			atMax++
		}
	}
	return fmt.Sprintf("%s (%d %s) - %s changed", plural(len(a.RiskFindings), "finding"), atMax, max, blocks)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// shortHash abbreviates a commit hash for report directory names.
func shortHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}
