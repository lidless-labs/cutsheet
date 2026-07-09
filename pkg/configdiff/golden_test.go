package configdiff

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenSummary struct {
	Parser             string   `json:"parser"`
	DetectedVendor     string   `json:"detected_vendor"`
	DeviceType         string   `json:"device_type"`
	BlockChanges       int      `json:"block_changes"`
	TouchedInterfaces  int      `json:"touched_interfaces"`
	TouchedVLANs       int      `json:"touched_vlans"`
	TouchedRoutes      int      `json:"touched_routes"`
	TouchedRules       int      `json:"touched_rules"`
	TouchedNAT         int      `json:"touched_nat"`
	TouchedVPN         int      `json:"touched_vpn"`
	SwitchingChanges   int      `json:"switching_changes"`
	RollbackConfidence string   `json:"rollback_confidence"`
	RiskTitles         []string `json:"risk_titles"`
}

func TestGoldenSummaries(t *testing.T) {
	tests := []struct {
		name       string
		beforePath string
		afterPath  string
		goldenPath string
	}{
		{
			name:       "cisco",
			beforePath: filepath.Join("..", "..", "testdata", "sample-before.cfg"),
			afterPath:  filepath.Join("..", "..", "testdata", "sample-after.cfg"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "cisco-summary.json"),
		},
		{
			name:       "junos",
			beforePath: filepath.Join("..", "..", "testdata", "junos-before.cfg"),
			afterPath:  filepath.Join("..", "..", "testdata", "junos-after.cfg"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "junos-summary.json"),
		},
		{
			name:       "catalyst",
			beforePath: filepath.Join("..", "..", "testdata", "catalyst-before.cfg"),
			afterPath:  filepath.Join("..", "..", "testdata", "catalyst-after.cfg"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "catalyst-summary.json"),
		},
		{
			name:       "edgeswitch",
			beforePath: filepath.Join("..", "..", "testdata", "edgeswitch-before.cfg"),
			afterPath:  filepath.Join("..", "..", "testdata", "edgeswitch-after.cfg"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "edgeswitch-summary.json"),
		},
		{
			name:       "edgeos",
			beforePath: filepath.Join("..", "..", "testdata", "edgeos-before.cfg"),
			afterPath:  filepath.Join("..", "..", "testdata", "edgeos-after.cfg"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "edgeos-summary.json"),
		},
		{
			name:       "panos",
			beforePath: filepath.Join("..", "..", "testdata", "panos-before.cfg"),
			afterPath:  filepath.Join("..", "..", "testdata", "panos-after.cfg"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "panos-summary.json"),
		},
		{
			name:       "unifi",
			beforePath: filepath.Join("..", "..", "testdata", "unifi-before.json"),
			afterPath:  filepath.Join("..", "..", "testdata", "unifi-after.json"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "unifi-summary.json"),
		},
		{
			name:       "eero-forward-added",
			beforePath: filepath.Join("..", "..", "testdata", "eero-forward-before.json"),
			afterPath:  filepath.Join("..", "..", "testdata", "eero-forward-after.json"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "eero-forward-summary.json"),
		},
		{
			name:       "eero-reservation-removed",
			beforePath: filepath.Join("..", "..", "testdata", "eero-reservation-before.json"),
			afterPath:  filepath.Join("..", "..", "testdata", "eero-reservation-after.json"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "eero-reservation-summary.json"),
		},
		{
			name:       "eero-node-removed",
			beforePath: filepath.Join("..", "..", "testdata", "eero-node-before.json"),
			afterPath:  filepath.Join("..", "..", "testdata", "eero-node-after.json"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "eero-node-summary.json"),
		},
		{
			name:       "eero-no-change",
			beforePath: filepath.Join("..", "..", "testdata", "eero-no-change-before.json"),
			afterPath:  filepath.Join("..", "..", "testdata", "eero-no-change-after.json"),
			goldenPath: filepath.Join("..", "..", "testdata", "golden", "eero-no-change-summary.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Explain(Options{
				BeforePath: tt.beforePath,
				AfterPath:  tt.afterPath,
				Vendor:     "auto",
				OutDir:     t.TempDir(),
			})
			if err != nil {
				t.Fatalf("Explain returned error: %v", err)
			}

			gotBytes, err := json.MarshalIndent(toGoldenSummary(result.Analysis), "", "  ")
			if err != nil {
				t.Fatalf("marshal summary: %v", err)
			}
			gotBytes = append(gotBytes, '\n')

			wantBytes, err := os.ReadFile(tt.goldenPath)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Fatalf("golden mismatch for %s\nwant:\n%s\ngot:\n%s", tt.name, wantBytes, gotBytes)
			}
		})
	}
}

func toGoldenSummary(a Analysis) goldenSummary {
	return goldenSummary{
		Parser:             a.DetectedPlatform.Parser,
		DetectedVendor:     a.DetectedPlatform.DetectedVendor,
		DeviceType:         a.DetectedPlatform.DeviceType,
		BlockChanges:       len(a.BlockChanges),
		TouchedInterfaces:  len(a.TouchedInterfaces),
		TouchedVLANs:       len(a.TouchedVLANs),
		TouchedRoutes:      len(a.TouchedRoutes),
		TouchedRules:       len(a.TouchedACLFirewallRules),
		TouchedNAT:         len(a.TouchedNATObjects),
		TouchedVPN:         len(a.TouchedVPNObjects),
		SwitchingChanges:   len(a.SwitchingChanges),
		RollbackConfidence: a.Rollback.Confidence,
		RiskTitles:         riskTitles(a.RiskFindings),
	}
}

func riskTitles(findings []RiskFinding) []string {
	titles := make([]string, 0, len(findings))
	for _, finding := range findings {
		titles = append(titles, finding.Title)
	}
	return titles
}
