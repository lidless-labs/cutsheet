package configdiff

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPANOSCrossZonePermitAndCollapse(t *testing.T) {
	before := `
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set rulebase security rules ALLOW-WEB from untrust
set rulebase security rules ALLOW-WEB to trust
set rulebase security rules ALLOW-WEB source 198.18.0.0/8
set rulebase security rules ALLOW-WEB destination 198.19.1.10
set rulebase security rules ALLOW-WEB application web-browsing
set rulebase security rules ALLOW-WEB action allow
`
	after := `
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set zone trust network layer3 ethernet1/3
set rulebase security rules ALLOW-WEB from untrust
set rulebase security rules ALLOW-WEB to trust
set rulebase security rules ALLOW-WEB source any
set rulebase security rules ALLOW-WEB destination any
set rulebase security rules ALLOW-WEB application ssh
set rulebase security rules ALLOW-WEB action allow
set rulebase security rules ALLOW-MGMT from untrust
set rulebase security rules ALLOW-MGMT to mgmt
set rulebase security rules ALLOW-MGMT source any
set rulebase security rules ALLOW-MGMT destination any
set rulebase security rules ALLOW-MGMT application ssh
set rulebase security rules ALLOW-MGMT action allow
`
	analysis, err := AnalyzeContent(before, after, "panos")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}

	boundaries := indexSecurityBoundaries(analysis.TouchedSecurityBoundaries)
	assertBoundary(t, boundaries, "zone_flow|allow-web", "changed", "untrust", "trust", "ALLOW-WEB")
	assertBoundary(t, boundaries, "zone_flow|allow-mgmt", "added", "untrust", "mgmt", "ALLOW-MGMT")
	assertBoundary(t, boundaries, "zone_membership|trust|ethernet1/3", "added", "", "", "")

	wantRisks := []string{
		"Newly permitted cross-zone flow",
		"Trust boundary collapsed",
		"Management access crosses segments",
		"Security zone membership changed",
	}
	for _, title := range wantRisks {
		finding := riskByTitle(analysis.RiskFindings, title)
		if finding == nil {
			t.Fatalf("missing risk %q in %#v", title, analysis.RiskFindings)
		}
		if title == "Security zone membership changed" {
			if finding.Severity != "medium" || finding.Category != "security_boundary" {
				t.Fatalf("%s: severity=%q category=%q", title, finding.Severity, finding.Category)
			}
			continue
		}
		if finding.Severity != "high" || finding.Category != "security_boundary" {
			t.Fatalf("%s: severity=%q category=%q", title, finding.Severity, finding.Category)
		}
	}

	rules := indexTouchedRules(analysis.TouchedACLFirewallRules)
	web := rules["allow-web"]
	if web.SourceZone != "untrust" || web.DestinationZone != "trust" || web.Policy != "ALLOW-WEB" {
		t.Fatalf("ALLOW-WEB zone enrichment wrong: %#v", web)
	}
}

func TestJunosCrossZonePolicyAdded(t *testing.T) {
	before := `
set security policies from-zone trust to-zone untrust policy WEB match source-address LAB-USERS
set security policies from-zone trust to-zone untrust policy WEB match destination-address WEB-SERVER
set security policies from-zone trust to-zone untrust policy WEB match application junos-https
set security policies from-zone trust to-zone untrust policy WEB then permit
`
	after := `
set security policies from-zone trust to-zone untrust policy WEB match source-address LAB-USERS
set security policies from-zone trust to-zone untrust policy WEB match destination-address WEB-SERVER
set security policies from-zone trust to-zone untrust policy WEB match application junos-https
set security policies from-zone trust to-zone untrust policy WEB then permit
set security policies from-zone untrust to-zone trust policy INBOUND-SSH match source-address any
set security policies from-zone untrust to-zone trust policy INBOUND-SSH match destination-address any
set security policies from-zone untrust to-zone trust policy INBOUND-SSH match application junos-ssh
set security policies from-zone untrust to-zone trust policy INBOUND-SSH then permit
`
	analysis, err := AnalyzeContent(before, after, "junos")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}

	boundaries := indexSecurityBoundaries(analysis.TouchedSecurityBoundaries)
	assertBoundary(t, boundaries, "zone_flow|inbound-ssh", "added", "untrust", "trust", "INBOUND-SSH")

	for _, title := range []string{"Newly permitted cross-zone flow", "Management access crosses segments"} {
		finding := riskByTitle(analysis.RiskFindings, title)
		if finding == nil {
			t.Fatalf("missing risk %q in %#v", title, analysis.RiskFindings)
		}
		if finding.Severity != "high" || finding.Category != "security_boundary" {
			t.Fatalf("%s: severity=%q category=%q", title, finding.Severity, finding.Category)
		}
	}
}

func TestFortinetCrossZoneIntfChange(t *testing.T) {
	before := `
config firewall policy
    edit 100
        set name "LAB-WEB"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LAB-USERS"
        set dstaddr "WEB-SERVER"
        set action accept
        set service "HTTPS"
    next
end
`
	after := `
config firewall policy
    edit 100
        set name "LAB-WEB"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "SSH"
    next
end
`
	analysis, err := AnalyzeContent(before, after, "fortinet")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}

	boundaries := indexSecurityBoundaries(analysis.TouchedSecurityBoundaries)
	assertBoundary(t, boundaries, "zone_flow|lab-web", "changed", "any", "any", "LAB-WEB")

	if riskByTitle(analysis.RiskFindings, "Trust boundary collapsed") == nil {
		t.Fatalf("expected trust boundary collapsed: %#v", analysis.RiskFindings)
	}
	if riskByTitle(analysis.RiskFindings, "Management access crosses segments") == nil {
		t.Fatalf("expected management crosses segments: %#v", analysis.RiskFindings)
	}

	rules := indexTouchedRules(analysis.TouchedACLFirewallRules)
	web := rules["config-firewall-policy-100"]
	if web.SourceZone != "any" || web.DestinationZone != "any" || web.Policy != "LAB-WEB" {
		t.Fatalf("Fortinet zone enrichment wrong: %#v", web)
	}
}

func TestSecurityBoundariesUnchangedAreSilent(t *testing.T) {
	cfg := `
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
set rulebase security rules ALLOW-WEB from untrust
set rulebase security rules ALLOW-WEB to trust
set rulebase security rules ALLOW-WEB source 198.18.0.0/8
set rulebase security rules ALLOW-WEB destination 198.19.1.10
set rulebase security rules ALLOW-WEB application web-browsing
set rulebase security rules ALLOW-WEB action allow
`
	analysis, err := AnalyzeContent(cfg, cfg, "panos")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if len(analysis.TouchedSecurityBoundaries) != 0 {
		t.Fatalf("unchanged boundaries must not appear: %#v", analysis.TouchedSecurityBoundaries)
	}
	for _, title := range []string{
		"Newly permitted cross-zone flow",
		"Trust boundary collapsed",
		"Management access crosses segments",
		"Security zone membership changed",
	} {
		if hasRisk(analysis.RiskFindings, title) {
			t.Fatalf("unchanged config must not emit %q", title)
		}
	}
}

func TestSecurityBoundariesWithoutZonesAreSilent(t *testing.T) {
	before := `
hostname lab-r1
ip access-list extended MGMT
 permit tcp any any eq 22
`
	after := `
hostname lab-r1
ip access-list extended MGMT
 permit tcp any any eq 22
 permit tcp any any eq 443
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if len(analysis.TouchedSecurityBoundaries) != 0 {
		t.Fatalf("ACLs without zone context must not emit boundaries: %#v", analysis.TouchedSecurityBoundaries)
	}
	for _, title := range []string{
		"Newly permitted cross-zone flow",
		"Trust boundary collapsed",
		"Management access crosses segments",
	} {
		if hasRisk(analysis.RiskFindings, title) {
			t.Fatalf("zone-less ACL must not emit %q", title)
		}
	}
}

func TestPANOSZoneFixtureGolden(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "panos-zones-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "panos-zones-after.cfg"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(result.Analysis.TouchedSecurityBoundaries) < 2 {
		t.Fatalf("expected at least 2 boundary changes, got %#v", result.Analysis.TouchedSecurityBoundaries)
	}
	for _, title := range []string{
		"Newly permitted cross-zone flow",
		"Trust boundary collapsed",
		"Management access crosses segments",
	} {
		if !hasRisk(result.Analysis.RiskFindings, title) {
			t.Fatalf("missing risk %q", title)
		}
	}
}

func TestParsePANOSZoneFlowFromLines(t *testing.T) {
	lines := []string{
		"set rulebase security rules ALLOW-WEB from untrust",
		"set rulebase security rules ALLOW-WEB to trust",
		"set rulebase security rules ALLOW-WEB source any",
		"set rulebase security rules ALLOW-WEB destination any",
		"set rulebase security rules ALLOW-WEB application ssh",
		"set rulebase security rules ALLOW-WEB action allow",
	}
	flows := parseZoneFlowsFromLines(lines, "set rulebase security rules ALLOW-WEB")
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1: %#v", len(flows), flows)
	}
	flow := flows["zone_flow|allow-web"]
	if flow.SourceZone != "untrust" || flow.DestinationZone != "trust" || flow.Action != "allow" {
		t.Fatalf("flow fields wrong: %#v", flow)
	}
	if !flow.AnySource || !flow.AnyDestination || !flow.Management {
		t.Fatalf("expected any+management markers: %#v", flow)
	}
}

func indexSecurityBoundaries(items []TouchedSecurityBoundary) map[string]TouchedSecurityBoundary {
	out := map[string]TouchedSecurityBoundary{}
	for _, item := range items {
		out[securityBoundaryIndexKey(item)] = item
	}
	return out
}

func securityBoundaryIndexKey(item TouchedSecurityBoundary) string {
	switch item.Kind {
	case "zone_membership":
		return item.Kind + "|" + strings.ToLower(item.Zone) + "|" + strings.ToLower(item.Member)
	default:
		if item.Policy != "" {
			return item.Kind + "|" + strings.ToLower(item.Policy)
		}
		return item.Kind + "|" + strings.ToLower(item.SourceZone) + "|" + strings.ToLower(item.DestinationZone)
	}
}

func assertBoundary(t *testing.T, items map[string]TouchedSecurityBoundary, key, changeType, src, dst, policy string) {
	t.Helper()
	item, ok := items[key]
	if !ok {
		t.Fatalf("missing boundary %s in %#v", key, items)
	}
	if item.ChangeType != changeType {
		t.Fatalf("%s change_type=%q want %q", key, item.ChangeType, changeType)
	}
	if src != "" && item.SourceZone != src {
		t.Fatalf("%s source_zone=%q want %q", key, item.SourceZone, src)
	}
	if dst != "" && item.DestinationZone != dst {
		t.Fatalf("%s destination_zone=%q want %q", key, item.DestinationZone, dst)
	}
	if policy != "" && !strings.EqualFold(item.Policy, policy) {
		t.Fatalf("%s policy=%q want %q", key, item.Policy, policy)
	}
	if len(item.Evidence) == 0 {
		t.Fatalf("%s missing evidence", key)
	}
}

func indexTouchedRules(rules []TouchedRule) map[string]TouchedRule {
	out := map[string]TouchedRule{}
	for _, rule := range rules {
		out[strings.ToLower(rule.Name)] = rule
	}
	return out
}
