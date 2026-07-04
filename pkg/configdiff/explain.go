package configdiff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AnalyzeContent parses and analyzes two configs entirely in memory, with no
// file or report I/O. It is the pure core shared by Explain (which persists a
// report) and pre-flight (which evaluates a candidate config before it is
// applied, without persisting anything). Splitting it out is what lets a
// candidate config be "forked" and inspected the way ActiveGraph evaluates a
// branch before committing it. See docs/design/activegraph-inspiration.md.
func AnalyzeContent(beforeContent, afterContent, vendor string) (Analysis, error) {
	if vendor == "" {
		vendor = "auto"
	}
	parser, err := selectParser(vendor, beforeContent+"\n"+afterContent)
	if err != nil {
		return Analysis{}, err
	}
	before := parser.Parse(beforeContent, vendor)
	after := parser.Parse(afterContent, vendor)
	return analyze(before, after, vendor), nil
}

func Explain(opts Options) (Result, error) {
	if opts.Vendor == "" {
		opts.Vendor = "auto"
	}

	beforeBytes, err := os.ReadFile(opts.BeforePath)
	if err != nil {
		return Result{}, fmt.Errorf("read before config: %w", err)
	}
	afterBytes, err := os.ReadFile(opts.AfterPath)
	if err != nil {
		return Result{}, fmt.Errorf("read after config: %w", err)
	}

	analysis, err := AnalyzeContent(string(beforeBytes), string(afterBytes), opts.Vendor)
	if err != nil {
		return Result{}, err
	}

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("create output directory: %w", err)
	}
	jsonBytes, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("marshal analysis: %w", err)
	}
	if err := os.WriteFile(filepath.Join(opts.OutDir, "diff-analysis.json"), append(jsonBytes, '\n'), 0o600); err != nil {
		return Result{}, fmt.Errorf("write diff-analysis.json: %w", err)
	}
	if err := writeMarkdownReports(opts.OutDir, analysis); err != nil {
		return Result{}, err
	}
	if err := writeHTMLReport(opts.OutDir, analysis); err != nil {
		return Result{}, err
	}

	return Result{OutDir: opts.OutDir, Analysis: analysis}, nil
}
