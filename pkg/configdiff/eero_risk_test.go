package configdiff

import (
	"path/filepath"
	"testing"
)

func TestEeroMeshNodeRemovedRisk(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "eero-node-before.json"),
		AfterPath:  filepath.Join("..", "..", "testdata", "eero-node-after.json"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}

	finding := riskByTitle(result.Analysis.RiskFindings, "Eero mesh node removed")
	if finding == nil {
		t.Fatalf("missing eero mesh node removed risk in %#v", result.Analysis.RiskFindings)
	}
	if finding.Severity != "medium" {
		t.Fatalf("severity = %q, want medium", finding.Severity)
	}
	if finding.Category != "availability" {
		t.Fatalf("category = %q, want availability", finding.Category)
	}
}

func TestEeroReservationRemovedWithRetainedForwardRisk(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "eero-reservation-forward-before.json"),
		AfterPath:  filepath.Join("..", "..", "testdata", "eero-reservation-forward-after.json"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}

	finding := riskByTitle(result.Analysis.RiskFindings, "Eero reservation removed while port forward still targets it")
	if finding == nil {
		t.Fatalf("missing eero reservation/forward risk in %#v", result.Analysis.RiskFindings)
	}
	if finding.Severity != "high" {
		t.Fatalf("severity = %q, want high", finding.Severity)
	}
	if finding.Category != "nat" {
		t.Fatalf("category = %q, want nat", finding.Category)
	}
	if !containsString(finding.Evidence, "nat port-forward tcp gateway_port 8443 client 198.18.50.30 client_port 443 enabled true") {
		t.Fatalf("expected retained forward evidence in %#v", finding.Evidence)
	}
}

func riskByTitle(findings []RiskFinding, title string) *RiskFinding {
	for i := range findings {
		if findings[i].Title == title {
			return &findings[i]
		}
	}
	return nil
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
