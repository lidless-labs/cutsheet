package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPreflightRunsWithoutPersisting confirms the preflight command analyzes a
// candidate and never writes a report directory or any file into the working
// tree.
func TestPreflightRunsWithoutPersisting(t *testing.T) {
	before := filepath.Join("..", "..", "testdata", "sample-before.cfg")
	after := filepath.Join("..", "..", "testdata", "sample-after.cfg")

	work := t.TempDir()
	beforeEntries, _ := os.ReadDir(work)

	// Run from an empty working dir so any stray output would be visible.
	prev, _ := os.Getwd()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	if err := run([]string{"preflight", "--current", filepath.Join(prev, before), "--candidate", filepath.Join(prev, after)}); err != nil {
		t.Fatalf("preflight text: %v", err)
	}
	if err := run([]string{"preflight", "--current", filepath.Join(prev, before), "--candidate", filepath.Join(prev, after), "--json"}); err != nil {
		t.Fatalf("preflight json: %v", err)
	}

	afterEntries, _ := os.ReadDir(work)
	if len(afterEntries) != len(beforeEntries) {
		t.Fatalf("preflight wrote %d new entries into the working dir; it must not persist", len(afterEntries)-len(beforeEntries))
	}
}

func TestPreflightRequiresBothPaths(t *testing.T) {
	if err := run([]string{"preflight", "--current", "x"}); err == nil {
		t.Fatal("expected an error when --candidate is missing")
	}
}
