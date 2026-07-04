package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/solomonneas/cutsheet/pkg/configdiff"
)

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
	case "explain":
		fs := flag.NewFlagSet("explain", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		before := fs.String("before", "", "path to the before config")
		after := fs.String("after", "", "path to the after config")
		vendor := fs.String("vendor", "auto", "vendor parser mode: auto or generic")
		out := fs.String("out", "", "output report directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *before == "" || *after == "" || *out == "" {
			return fmt.Errorf("explain requires --before, --after, and --out")
		}

		result, err := configdiff.Explain(configdiff.Options{
			BeforePath: *before,
			AfterPath:  *after,
			Vendor:     *vendor,
			OutDir:     *out,
		})
		if err != nil {
			return err
		}
		fmt.Printf("Wrote config diff report to %s\n", result.OutDir)
		return nil
	case "preflight":
		fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		current := fs.String("current", "", "path to the current (live) config")
		candidate := fs.String("candidate", "", "path to the candidate config to pre-flight")
		vendor := fs.String("vendor", "auto", "vendor parser mode: auto or generic")
		asJSON := fs.Bool("json", false, "emit the full analysis as JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *current == "" || *candidate == "" {
			return fmt.Errorf("preflight requires --current and --candidate")
		}
		return preflight(*current, *candidate, *vendor, *asJSON)
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return usageError()
	}
}

func usageError() error {
	printUsage()
	return fmt.Errorf("expected command: explain or preflight")
}

// preflight analyzes a candidate config against the current one and prints the
// blast radius (risk findings + rollback) WITHOUT writing a report or touching
// any store or git history. It is the "cut sheet" made safe: see the impact of
// a change before you apply it. ActiveGraph-inspired fork of a candidate branch.
func preflight(currentPath, candidatePath, vendor string, asJSON bool) error {
	currentBytes, err := os.ReadFile(currentPath)
	if err != nil {
		return fmt.Errorf("read current config: %w", err)
	}
	candidateBytes, err := os.ReadFile(candidatePath)
	if err != nil {
		return fmt.Errorf("read candidate config: %w", err)
	}
	analysis, err := configdiff.AnalyzeContent(string(currentBytes), string(candidateBytes), vendor)
	if err != nil {
		return err
	}

	if asJSON {
		out, err := json.MarshalIndent(analysis, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal analysis: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("Pre-flight: %s (%s)\n", analysis.DetectedPlatform.Parser, analysis.DetectedPlatform.DetectedVendor)
	fmt.Printf("Risk findings: %d\n", len(analysis.RiskFindings))
	for _, finding := range analysis.RiskFindings {
		fmt.Printf("  [%s] %s (%s)\n", finding.Severity, finding.Title, finding.Category)
	}
	fmt.Printf("Rollback confidence: %s\n", analysis.Rollback.Confidence)
	fmt.Println("No report written; nothing persisted.")
	return nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  cutsheet explain --before ./before.cfg --after ./after.cfg --vendor auto --out ./reports/change-001")
	fmt.Fprintln(os.Stderr, "  cutsheet preflight --current ./running.cfg --candidate ./proposed.cfg --vendor auto [--json]")
}
