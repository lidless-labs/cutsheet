package configdiff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplainProducesStructuredAnalysisAndReports(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "report")
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "sample-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "sample-after.cfg"),
		Vendor:     "auto",
		OutDir:     outDir,
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}

	if result.Analysis.SchemaVersion != "1.3" {
		t.Fatalf("schema version = %q, want 1.3", result.Analysis.SchemaVersion)
	}
	if result.Analysis.DetectedPlatform.Parser != "cisco-ios" {
		t.Fatalf("parser = %q, want cisco-ios", result.Analysis.DetectedPlatform.Parser)
	}
	if result.Analysis.DetectedPlatform.DetectedVendor != "cisco" {
		t.Fatalf("detected vendor = %q, want cisco", result.Analysis.DetectedPlatform.DetectedVendor)
	}
	if len(result.Analysis.BlockChanges) == 0 {
		t.Fatal("expected block changes")
	}
	assertTouched(t, len(result.Analysis.TouchedInterfaces) > 0, "interfaces")
	assertTouched(t, len(result.Analysis.TouchedVLANs) > 0, "vlans")
	assertTouched(t, len(result.Analysis.TouchedRoutes) > 0, "routes")
	assertTouched(t, routeNextHopChanged(result.Analysis.TouchedRoutes), "route next-hop changes")
	assertTouched(t, len(result.Analysis.TouchedACLFirewallRules) > 0, "acl/firewall rules")
	assertTouched(t, parsedACLFields(result.Analysis.TouchedACLFirewallRules), "parsed ACL fields")
	assertTouched(t, len(result.Analysis.TouchedNATObjects) > 0, "nat objects")
	assertTouched(t, len(result.Analysis.TouchedVPNObjects) > 0, "vpn objects")
	assertTouched(t, len(result.Analysis.ManagementPlaneChanges) > 0, "management changes")
	assertTouched(t, len(result.Analysis.AAAChanges) > 0, "aaa changes")
	assertTouched(t, len(result.Analysis.LoggingSNMPNTPDNSChanges) > 0, "observability changes")

	wantRisks := []string{
		"Default route changed",
		"Route removed",
		"ACL or firewall rule appears broadened",
		"Management service may be exposed",
		"Interface VLAN assignment changed",
		"Trunk allowed VLAN list changed",
		"Interface shutdown state changed",
		"NAT configuration changed",
		"VPN peer or tunnel configuration changed",
		"AAA or authentication changed",
		"Management access changed",
		"Logging or monitoring may be reduced",
	}
	for _, title := range wantRisks {
		if !hasRisk(result.Analysis.RiskFindings, title) {
			t.Fatalf("missing risk finding %q in %#v", title, result.Analysis.RiskFindings)
		}
	}
	if result.Analysis.Rollback.Confidence != "risky" {
		t.Fatalf("rollback confidence = %q, want risky", result.Analysis.Rollback.Confidence)
	}
	if len(result.Analysis.Rollback.Snippets) == 0 {
		t.Fatal("expected rollback snippets")
	}
	if !hasRollbackCommands(result.Analysis.Rollback.Snippets) {
		t.Fatal("expected parser-specific rollback command candidates")
	}

	reportFiles := []string{
		"diff-analysis.json",
		"change-summary.md",
		"risk-analysis.md",
		"touched-objects.md",
		"rollback-plan.md",
		"validation-plan.md",
		"operator-checklist.md",
		"stakeholder-brief.md",
		"report.html",
	}
	for _, name := range reportFiles {
		path := filepath.Join(outDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected report file %s: %v", name, err)
		}
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "diff-analysis.json"))
	if err != nil {
		t.Fatalf("read diff-analysis.json: %v", err)
	}
	var decoded Analysis
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("diff-analysis.json is not valid JSON: %v", err)
	}
}

func TestNoisyCommentsAndOrderOnlyChangesAreIgnored(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "report")
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "order-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "order-after.cfg"),
		Vendor:     "auto",
		OutDir:     outDir,
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if len(result.Analysis.BlockChanges) != 0 {
		t.Fatalf("expected no effective block changes, got %#v", result.Analysis.BlockChanges)
	}
	if result.Analysis.Rollback.Confidence != "clean" {
		t.Fatalf("rollback confidence = %q, want clean", result.Analysis.Rollback.Confidence)
	}
}

func TestUnsupportedVendorModeFailsClearly(t *testing.T) {
	_, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "sample-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "sample-after.cfg"),
		Vendor:     "unknown-vendor",
		OutDir:     t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected unsupported vendor error")
	}
}

func TestExplicitGenericVendorKeepsGenericParser(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "sample-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "sample-after.cfg"),
		Vendor:     "generic",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if result.Analysis.DetectedPlatform.Parser != "generic" {
		t.Fatalf("parser = %q, want generic", result.Analysis.DetectedPlatform.Parser)
	}
}

func TestCiscoVLANRangesAreExpanded(t *testing.T) {
	before := parsedConfig{Blocks: []configBlock{{
		ID:     "interface:gigabitethernet0/9",
		Kind:   "interface",
		Header: "interface GigabitEthernet0/9",
		Lines:  []string{"interface GigabitEthernet0/9", "switchport trunk allowed vlan 10-12,20"},
	}}}
	after := parsedConfig{Blocks: []configBlock{{
		ID:     "interface:gigabitethernet0/9",
		Kind:   "interface",
		Header: "interface GigabitEthernet0/9",
		Lines:  []string{"interface GigabitEthernet0/9", "switchport trunk allowed vlan 10-11,20,30"},
	}}}
	analysis := analyze(before, after, "cisco-ios")
	for _, want := range []string{"10", "11", "12", "20", "30"} {
		if !hasTouchedVLAN(analysis.TouchedVLANs, want) {
			t.Fatalf("expected touched VLAN %s in %#v", want, analysis.TouchedVLANs)
		}
	}
	if !hasRisk(analysis.RiskFindings, "Trunk allowed VLAN list changed") {
		t.Fatal("expected trunk allowed VLAN risk")
	}
}

func TestHTMLReportContainsInteractiveSectionsAndEscapesContent(t *testing.T) {
	analysis := Analysis{
		DetectedPlatform: DetectedPlatform{
			Parser:         "cisco-ios",
			DetectedVendor: "cisco",
			DeviceType:     "switch",
			Confidence:     0.88,
		},
		BlockChanges: []BlockChange{{
			ID:          "acl:mgmt",
			Kind:        "acl",
			ChangeType:  "changed",
			Header:      "ip access-list extended MGMT<IN>",
			BeforeLines: []string{"permit tcp 192.0.2.0 0.0.0.255 any eq 22"},
			AfterLines:  []string{"permit tcp any any eq 22"},
		}},
		RiskFindings: []RiskFinding{{
			ID:             "RISK-001",
			Severity:       "high",
			Category:       "acl_firewall",
			Title:          "ACL broadened <check>",
			Recommendation: "Review scope before allowing the change.",
			Details:        []string{"Before < after"},
			Evidence:       []string{"permit tcp any any eq 22"},
		}},
		Rollback: RollbackAnalysis{
			Confidence: "risky",
			Summary:    "Review before applying.",
		},
	}

	html := renderHTMLReport(analysis)
	for _, want := range []string{
		`id="risks"`,
		`id="changes"`,
		`id="touched"`,
		`id="rollback"`,
		`id="validation"`,
		`id="risk-search"`,
		`id="change-search"`,
		`data-risk`,
		`data-change`,
		`MGMT&lt;IN&gt;`,
		`ACL broadened &lt;check&gt;`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("renderHTMLReport missing %q in:\n%s", want, html)
		}
	}
	if strings.Contains(html, "MGMT<IN>") || strings.Contains(html, "ACL broadened <check>") {
		t.Fatalf("renderHTMLReport did not escape HTML content:\n%s", html)
	}
}

func TestJunosAutoParser(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "junos-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "junos-after.cfg"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if result.Analysis.DetectedPlatform.Parser != "junos" {
		t.Fatalf("parser = %q, want junos", result.Analysis.DetectedPlatform.Parser)
	}
	if result.Analysis.DetectedPlatform.DetectedVendor != "juniper" {
		t.Fatalf("vendor = %q, want juniper", result.Analysis.DetectedPlatform.DetectedVendor)
	}
	assertTouched(t, len(result.Analysis.TouchedRoutes) > 0, "junos routes")
	assertTouched(t, len(result.Analysis.TouchedVLANs) > 0, "junos vlans")
	assertTouched(t, len(result.Analysis.TouchedVPNObjects) > 0, "junos vpn")
	assertTouched(t, len(result.Analysis.TouchedNATObjects) > 0, "junos nat")
	assertTouched(t, len(result.Analysis.ManagementPlaneChanges) > 0, "junos management")
	assertTouched(t, len(result.Analysis.AAAChanges) > 0, "junos aaa")
	if !hasRisk(result.Analysis.RiskFindings, "Default route changed") {
		t.Fatal("expected Junos default route risk")
	}
	if !hasRollbackCommands(result.Analysis.Rollback.Snippets) {
		t.Fatal("expected Junos rollback command candidates")
	}
}

func TestAdvancedCiscoFixtures(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "cisco-advanced-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "cisco-advanced-after.cfg"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if result.Analysis.DetectedPlatform.Parser != "cisco-ios" {
		t.Fatalf("parser = %q, want cisco-ios", result.Analysis.DetectedPlatform.Parser)
	}
	for _, want := range []string{"10", "11", "12", "20", "30"} {
		if !hasTouchedVLAN(result.Analysis.TouchedVLANs, want) {
			t.Fatalf("expected touched VLAN %s in %#v", want, result.Analysis.TouchedVLANs)
		}
	}
	if !routeNextHopChanged(result.Analysis.TouchedRoutes) {
		t.Fatal("expected route next-hop change")
	}
	if !hasRuleService(result.Analysis.TouchedACLFirewallRules, "443") {
		t.Fatalf("expected parsed ACL service 443 in %#v", result.Analysis.TouchedACLFirewallRules)
	}
	if !hasInterface(result.Analysis.TouchedInterfaces, "port-channel1") {
		t.Fatalf("expected touched port-channel interface in %#v", result.Analysis.TouchedInterfaces)
	}
	if !hasManualReview(result.Analysis.Rollback.Snippets) {
		t.Fatal("expected rollback snippets requiring manual review")
	}
}

func TestAdvancedJunosFixtures(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "junos-advanced-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "junos-advanced-after.cfg"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if result.Analysis.DetectedPlatform.Parser != "junos" {
		t.Fatalf("parser = %q, want junos", result.Analysis.DetectedPlatform.Parser)
	}
	if !routeNextHopChanged(result.Analysis.TouchedRoutes) {
		t.Fatal("expected Junos route next-hop change")
	}
	assertTouched(t, len(result.Analysis.TouchedACLFirewallRules) > 0, "Junos security policy or address-book rule")
	assertTouched(t, len(result.Analysis.TouchedNATObjects) > 0, "Junos NAT pool")
	if !hasRisk(result.Analysis.RiskFindings, "ACL or firewall rule appears broadened") {
		t.Fatal("expected Junos policy broadening risk")
	}
	if !hasManualReview(result.Analysis.Rollback.Snippets) {
		t.Fatal("expected rollback snippets requiring manual review")
	}
}

func TestFortinetAutoParser(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "fortinet-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "fortinet-after.cfg"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}
	if result.Analysis.DetectedPlatform.Parser != "fortinet" {
		t.Fatalf("parser = %q, want fortinet", result.Analysis.DetectedPlatform.Parser)
	}
	if result.Analysis.DetectedPlatform.DetectedVendor != "fortinet" {
		t.Fatalf("detected vendor = %q, want fortinet", result.Analysis.DetectedPlatform.DetectedVendor)
	}
	assertTouched(t, len(result.Analysis.TouchedRoutes) > 0, "fortinet static routes")
	assertTouched(t, routeNextHopChanged(result.Analysis.TouchedRoutes), "fortinet route next-hop")
	assertTouched(t, len(result.Analysis.TouchedACLFirewallRules) > 0, "fortinet firewall policy")
	assertTouched(t, len(result.Analysis.TouchedNATObjects) > 0, "fortinet NAT objects")
	assertTouched(t, len(result.Analysis.TouchedVPNObjects) > 0, "fortinet VPN objects")
	assertTouched(t, len(result.Analysis.ManagementPlaneChanges) > 0, "fortinet management")
	assertTouched(t, len(result.Analysis.AAAChanges) > 0, "fortinet admin auth")
	assertTouched(t, len(result.Analysis.LoggingSNMPNTPDNSChanges) > 0, "fortinet logging")
	if !hasRisk(result.Analysis.RiskFindings, "ACL or firewall rule appears broadened") {
		t.Fatal("expected Fortinet policy broadening risk")
	}
	if !hasRisk(result.Analysis.RiskFindings, "Default route changed") {
		t.Fatal("expected Fortinet default route risk")
	}
	if !hasRollbackCommands(result.Analysis.Rollback.Snippets) {
		t.Fatal("expected Fortinet rollback command candidates")
	}
}

func assertTouched(t *testing.T, ok bool, name string) {
	t.Helper()
	if !ok {
		t.Fatalf("expected touched %s", name)
	}
}

func hasRisk(findings []RiskFinding, title string) bool {
	for _, finding := range findings {
		if finding.Title == title {
			return true
		}
	}
	return false
}

func routeNextHopChanged(routes []TouchedRoute) bool {
	for _, route := range routes {
		if route.BeforeNextHop != "" && route.AfterNextHop != "" && route.BeforeNextHop != route.AfterNextHop {
			return true
		}
	}
	return false
}

func parsedACLFields(rules []TouchedRule) bool {
	for _, rule := range rules {
		if rule.Action != "" && rule.Protocol != "" && rule.Source != "" && rule.Destination != "" {
			return true
		}
	}
	return false
}

func hasRollbackCommands(snippets []RollbackSnippet) bool {
	for _, snippet := range snippets {
		if len(snippet.CandidateCommands) > 0 {
			return true
		}
	}
	return false
}

func hasTouchedVLAN(vlans []TouchedVLAN, id string) bool {
	for _, vlan := range vlans {
		if vlan.ID == id {
			return true
		}
	}
	return false
}

func hasRuleService(rules []TouchedRule, service string) bool {
	for _, rule := range rules {
		if rule.Service == service {
			return true
		}
	}
	return false
}

func hasInterface(interfaces []TouchedInterface, name string) bool {
	for _, item := range interfaces {
		if item.Name == name {
			return true
		}
	}
	return false
}

func hasManualReview(snippets []RollbackSnippet) bool {
	for _, snippet := range snippets {
		if snippet.ManualReviewRequired {
			return true
		}
	}
	return false
}
