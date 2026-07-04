package configdiff

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAnalyzeContentMatchesExplain proves the pure in-memory analysis (used by
// pre-flight) produces the same result as the file+report path (Explain),
// without writing anything.
func TestAnalyzeContentMatchesExplain(t *testing.T) {
	before, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample-before.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sample-after.cfg"))
	if err != nil {
		t.Fatal(err)
	}

	analysis, err := AnalyzeContent(string(before), string(after), "auto")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if analysis.DetectedPlatform.Parser == "" {
		t.Fatal("expected a detected parser")
	}
	if len(analysis.BlockChanges) == 0 {
		t.Fatal("expected block changes for a changed config pair")
	}
	if analysis.DetectedPlatform.RequestedVendor != "auto" {
		t.Fatalf("requested vendor = %q, want auto", analysis.DetectedPlatform.RequestedVendor)
	}

	// Same inputs through the persisting path must yield the same analysis.
	out := t.TempDir()
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "sample-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "sample-after.cfg"),
		Vendor:     "auto",
		OutDir:     out,
	})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(result.Analysis.BlockChanges) != len(analysis.BlockChanges) {
		t.Fatalf("AnalyzeContent and Explain disagree: %d vs %d block changes",
			len(analysis.BlockChanges), len(result.Analysis.BlockChanges))
	}
	if len(result.Analysis.RiskFindings) != len(analysis.RiskFindings) {
		t.Fatalf("risk finding counts differ: %d vs %d",
			len(analysis.RiskFindings), len(result.Analysis.RiskFindings))
	}
}
