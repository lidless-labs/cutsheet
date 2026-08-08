package configdiff

import (
	"strings"
	"testing"
)

func TestUndefinedACLReferenceOnInterface(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 ip address 198.18.1.1 255.255.255.0
 no shutdown
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 ip address 198.18.1.1 255.255.255.0
 ip access-group FILTER_IN in
 no shutdown
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	finding := riskByTitle(analysis.RiskFindings, "Undefined ACL referenced on interface")
	if finding == nil {
		t.Fatalf("missing undefined ACL finding in %#v", analysis.RiskFindings)
	}
	if finding.Severity != "high" {
		t.Fatalf("severity = %q, want high", finding.Severity)
	}
	if finding.Category != "undefined_reference" {
		t.Fatalf("category = %q, want undefined_reference", finding.Category)
	}
	if !containsString(finding.Details, "ACL FILTER_IN on GigabitEthernet0/1 in") {
		t.Fatalf("expected dangling ACL detail in %#v", finding.Details)
	}
	if !containsString(finding.Evidence, "ip access-group FILTER_IN in") {
		t.Fatalf("expected access-group evidence in %#v", finding.Evidence)
	}
}

func TestUndefinedACLReferenceResolvedWhenDefined(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group FILTER_IN in
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group FILTER_IN in
ip access-list extended FILTER_IN
 permit ip any any
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if hasRisk(analysis.RiskFindings, "Undefined ACL referenced on interface") {
		t.Fatalf("did not expect undefined ACL finding when ACL is defined: %#v", analysis.RiskFindings)
	}
}

func TestUndefinedACLReferenceUnchangedDanglingIsSilent(t *testing.T) {
	cfg := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group MISSING in
 description unchanged-dangling
`
	analysis, err := AnalyzeContent(cfg, cfg, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if hasRisk(analysis.RiskFindings, "Undefined ACL referenced on interface") {
		t.Fatalf("unchanged dangling ACL must not emit a finding: %#v", analysis.RiskFindings)
	}
}

func TestUndefinedACLReferenceWhenDefinitionRemoved(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group FILTER_IN in
ip access-list extended FILTER_IN
 permit tcp any any eq 443
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group FILTER_IN in
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if !hasRisk(analysis.RiskFindings, "Undefined ACL referenced on interface") {
		t.Fatalf("expected undefined ACL finding after definition removal: %#v", analysis.RiskFindings)
	}
}

func TestUndefinedACLReferenceCaseNormalization(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 no shutdown
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group Filter_In in
 no shutdown
ip access-list extended FILTER_IN
 permit ip any any
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if hasRisk(analysis.RiskFindings, "Undefined ACL referenced on interface") {
		t.Fatalf("case-normalized ACL name should match definition: %#v", analysis.RiskFindings)
	}
}

func TestUndefinedACLReferenceRemovedIsSilent(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group MISSING in
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 description cleaned
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if hasRisk(analysis.RiskFindings, "Undefined ACL referenced on interface") {
		t.Fatalf("removed dangling reference must not emit a finding: %#v", analysis.RiskFindings)
	}
}

func TestUndefinedRouteMapReferenceOnInterface(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 ip address 198.18.1.1 255.255.255.0
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 ip address 198.18.1.1 255.255.255.0
 ip policy route-map PBR_MAP
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	finding := riskByTitle(analysis.RiskFindings, "Undefined route-map referenced on interface")
	if finding == nil {
		t.Fatalf("missing undefined route-map finding in %#v", analysis.RiskFindings)
	}
	if finding.Severity != "high" {
		t.Fatalf("severity = %q, want high", finding.Severity)
	}
	if !containsString(finding.Details, "route-map PBR_MAP on GigabitEthernet0/1") {
		t.Fatalf("expected dangling route-map detail in %#v", finding.Details)
	}
}

func TestUndefinedPrefixListReferencedByAppliedRouteMap(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 ip address 198.18.1.1 255.255.255.0
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 ip address 198.18.1.1 255.255.255.0
 ip policy route-map PBR_MAP
route-map PBR_MAP permit 10
 match ip address prefix-list PL_INTERNAL
 set ip next-hop 198.18.1.254
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if hasRisk(analysis.RiskFindings, "Undefined route-map referenced on interface") {
		t.Fatalf("defined route-map must not be reported undefined: %#v", analysis.RiskFindings)
	}
	finding := riskByTitle(analysis.RiskFindings, "Undefined prefix-list referenced on interface")
	if finding == nil {
		t.Fatalf("missing undefined prefix-list finding in %#v", analysis.RiskFindings)
	}
	if !containsString(finding.Details, "prefix-list PL_INTERNAL via route-map PBR_MAP on GigabitEthernet0/1") {
		t.Fatalf("expected prefix-list detail in %#v", finding.Details)
	}
}

func TestUndefinedReferenceParserEdgeCases(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 no shutdown
`
	after := `
hostname lab-r1
interface GigabitEthernet0/1
 ip access-group
 ip access-group FILTER_IN
 no ip access-group GONE out
 ip policy route-map
 no shutdown
access-list 101 permit ip any any
interface GigabitEthernet0/2
 ip access-group 101 in
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if hasRisk(analysis.RiskFindings, "Undefined ACL referenced on interface") {
		t.Fatalf("incomplete/no/defined ACL lines must not emit undefined ACL noise: %#v", analysis.RiskFindings)
	}
	if hasRisk(analysis.RiskFindings, "Undefined route-map referenced on interface") {
		t.Fatalf("incomplete route-map line must not emit finding: %#v", analysis.RiskFindings)
	}
}

func TestUndefinedEdgeOSFirewallReferenceOnInterface(t *testing.T) {
	before := `
set interfaces ethernet eth0 address 198.18.1.1/24
set firewall name WAN_IN default-action drop
`
	after := `
set interfaces ethernet eth0 address 198.18.1.1/24
set interfaces ethernet eth0 firewall in name WAN_IN
set interfaces ethernet eth0 firewall out name MISSING_OUT
set firewall name WAN_IN default-action drop
`
	analysis, err := AnalyzeContent(before, after, "edgeos")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	finding := riskByTitle(analysis.RiskFindings, "Undefined ACL referenced on interface")
	if finding == nil {
		t.Fatalf("missing EdgeOS undefined firewall finding in %#v", analysis.RiskFindings)
	}
	if !containsString(finding.Details, "ACL MISSING_OUT on eth0 out") {
		t.Fatalf("expected MISSING_OUT detail in %#v", finding.Details)
	}
	for _, detail := range finding.Details {
		if strings.Contains(detail, "WAN_IN") {
			t.Fatalf("defined WAN_IN must not appear in dangling details: %#v", finding.Details)
		}
	}
}

func TestUndefinedReferenceFindingsAreDeterministic(t *testing.T) {
	before := `
hostname lab-r1
interface GigabitEthernet0/1
 no shutdown
interface GigabitEthernet0/2
 no shutdown
`
	after := `
hostname lab-r1
interface GigabitEthernet0/2
 ip access-group Z_LAST in
 ip policy route-map RM_B
 no shutdown
interface GigabitEthernet0/1
 ip access-group A_FIRST in
 ip policy route-map RM_A
 no shutdown
`
	first, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	second, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	acl1 := riskByTitle(first.RiskFindings, "Undefined ACL referenced on interface")
	acl2 := riskByTitle(second.RiskFindings, "Undefined ACL referenced on interface")
	if acl1 == nil || acl2 == nil {
		t.Fatalf("expected ACL findings")
	}
	if strings.Join(acl1.Details, "|") != strings.Join(acl2.Details, "|") {
		t.Fatalf("ACL details not deterministic:\n%v\n%v", acl1.Details, acl2.Details)
	}
	if len(acl1.Details) < 2 || !strings.HasPrefix(acl1.Details[0], "ACL A_FIRST") {
		t.Fatalf("ACL details should be sorted; got %#v", acl1.Details)
	}
	rm1 := riskByTitle(first.RiskFindings, "Undefined route-map referenced on interface")
	if rm1 == nil || len(rm1.Details) < 2 || !strings.Contains(rm1.Details[0], "RM_A") {
		t.Fatalf("route-map details should be sorted; got %#v", rm1)
	}
}
