package configdiff

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEvaluatePolicyCiscoNegatedHTTPIsAbsent(t *testing.T) {
	input := PolicyEvaluationInput{
		CurrentContent: "no ip http server\nno ip http secure-server\n",
		Vendor:         "cisco-ios",
	}
	for _, test := range []struct {
		name       string
		policy     DesiredStatePolicy
		findings   int
		wantStatus string
	}{
		{"required", DesiredStatePolicy{Version: "2026.08", Required: PolicyFacts{ManagementServices: []string{"http"}}}, 1, "missing"},
		{"forbidden", DesiredStatePolicy{Version: "2026.08", Forbidden: PolicyFacts{ManagementServices: []string{"http"}}}, 0, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := EvaluatePolicy(test.policy, input)
			if err != nil {
				t.Fatalf("evaluate policy: %v", err)
			}
			if got := len(result.Current.Findings); got != test.findings {
				t.Fatalf("negated HTTP findings = %#v, want %d", result.Current.Findings, test.findings)
			}
			if test.wantStatus != "" && result.Current.Findings[0].Status != test.wantStatus {
				t.Fatalf("negated HTTP required status = %q, want %q", result.Current.Findings[0].Status, test.wantStatus)
			}
		})
	}
}

func TestIsManagementLineRejectsNegatedCommands(t *testing.T) {
	if isManagementLine("no ip http server") {
		t.Fatal("negated HTTP command must not be classified as an enabled management service")
	}
}

func TestFeatureEnabledDetectorsRejectNegatedCommands(t *testing.T) {
	if exposesManagementPort("no access-list 100 permit tcp any any eq 80") {
		t.Fatal("negated access list must not expose a management port")
	}
	if aclBroadeningLine("no access-list 100 permit ip any any") {
		t.Fatal("negated access list must not broaden policy")
	}
	if trunkCarriesAllVLANs(nil, []string{"no switchport trunk allowed vlan all"}) {
		t.Fatal("negated trunk configuration must not be treated as allowing all VLANs")
	}
}

func TestEvaluatePolicyRequiredForbiddenAndNegatedFacts(t *testing.T) {
	tests := []struct {
		name    string
		facts   func(*PolicyFacts) *[]string
		value   string
		present string
		absent  string
		negated string
	}{
		{"vlan", func(f *PolicyFacts) *[]string { return &f.VLANs }, "20", "vlan 20", "vlan 30", "no vlan 20"},
		{"route", func(f *PolicyFacts) *[]string { return &f.Routes }, "198.51.100.0/255.255.255.0", "ip route 198.51.100.0 255.255.255.0 192.0.2.1", "ip route 203.0.113.0 255.255.255.0 192.0.2.1", "no ip route 198.51.100.0 255.255.255.0 192.0.2.1"},
		{"management service", func(f *PolicyFacts) *[]string { return &f.ManagementServices }, "http", "ip http server", "ip http secure-server", "no ip http server"},
		{"aaa", func(f *PolicyFacts) *[]string { return &f.AAA }, "aaa new-model", "aaa new-model", "aaa authentication login default local", "no aaa new-model"},
		{"firewall property", func(f *PolicyFacts) *[]string { return &f.FirewallProperties }, "deny ip any any", "access-list MGMT deny ip any any", "access-list MGMT permit ip any any", "no access-list MGMT deny ip any any"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, scenario := range []struct {
				name         string
				content      string
				expectation  string
				wantFindings int
				wantStatus   string
			}{
				{"required present", tt.present, "required", 0, ""},
				{"required missing", tt.absent, "required", 1, "missing"},
				{"forbidden present", tt.present, "forbidden", 1, "present"},
				{"forbidden absent", tt.absent, "forbidden", 0, ""},
				{"negated command required", tt.negated, "required", 1, "missing"},
				{"negated command forbidden", tt.negated, "forbidden", 0, ""},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					policy := DesiredStatePolicy{Version: "2026.08"}
					*tt.facts(&policy.Required) = []string{tt.value}
					if scenario.expectation == "forbidden" {
						policy.Required = PolicyFacts{}
						*tt.facts(&policy.Forbidden) = []string{tt.value}
					}
					result, err := EvaluatePolicy(policy, PolicyEvaluationInput{CurrentContent: scenario.content, Vendor: "cisco-ios"})
					if err != nil {
						t.Fatalf("evaluate policy: %v", err)
					}
					if got := len(result.Current.Findings); got != scenario.wantFindings {
						t.Fatalf("findings = %#v, want %d", result.Current.Findings, scenario.wantFindings)
					}
					if scenario.wantStatus != "" && result.Current.Findings[0].Status != scenario.wantStatus {
						t.Fatalf("finding status = %q, want %q", result.Current.Findings[0].Status, scenario.wantStatus)
					}
					assertPolicyVersions(t, result)
				})
			}
		})
	}
}

func TestEvaluatePolicyCiscoNamedACLBodyFacts(t *testing.T) {
	input := PolicyEvaluationInput{
		CurrentContent: "ip access-list extended EDGE\n deny ip any any\n",
		Vendor:         "cisco-ios",
	}
	for _, policy := range []DesiredStatePolicy{
		{Version: "2026.08", Required: PolicyFacts{FirewallProperties: []string{"deny ip any any"}}},
		{Version: "2026.08", Forbidden: PolicyFacts{FirewallProperties: []string{"deny ip any any"}}},
	} {
		result, err := EvaluatePolicy(policy, input)
		if err != nil {
			t.Fatalf("evaluate policy: %v", err)
		}
		want := 0
		if policy.Forbidden.FirewallProperties != nil {
			want = 1
		}
		if got := len(result.Current.Findings); got != want {
			t.Fatalf("findings = %#v, want %d", result.Current.Findings, want)
		}
		if want == 1 && (len(result.Current.Findings[0].Evidence) != 1 || result.Current.Findings[0].Evidence[0] != "deny ip any any") {
			t.Fatalf("named ACL evidence = %#v, want body line", result.Current.Findings[0].Evidence)
		}
	}
}

func TestEvaluatePolicyNormalizesRequirementsBeforeDedupe(t *testing.T) {
	result, err := EvaluatePolicy(DesiredStatePolicy{
		Version:  "2026.08",
		Required: PolicyFacts{ManagementServices: []string{" HTTP ", "http", "Http"}},
	}, PolicyEvaluationInput{Vendor: "cisco-ios"})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if got := len(result.Current.Findings); got != 1 {
		t.Fatalf("normalized duplicate requirements emitted %d findings: %#v", got, result.Current.Findings)
	}
}

func TestEvaluatePolicyModelsPredecessorAndSelectedBaseline(t *testing.T) {
	result, err := EvaluatePolicy(DesiredStatePolicy{
		Version:  "2026.08",
		Required: PolicyFacts{VLANs: []string{"20"}},
	}, PolicyEvaluationInput{
		CurrentContent:     "vlan 20",
		PredecessorContent: "vlan 30",
		BaselineContent:    "vlan 20",
		Vendor:             "cisco-ios",
	})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if result.Current.Snapshot != "current" || result.Predecessor.Snapshot != "predecessor" || result.SelectedBaseline.Snapshot != "selected_baseline" {
		t.Fatalf("snapshot labels = %#v", result)
	}
	if len(result.Current.Findings) != 0 || len(result.Predecessor.Findings) != 1 || len(result.SelectedBaseline.Findings) != 0 {
		t.Fatalf("expected predecessor-only drift, got %#v", result)
	}
	assertPolicyVersions(t, result)
}

func TestEvaluatePolicyComparesCurrentAgainstPredecessorAndBaseline(t *testing.T) {
	result, err := EvaluatePolicy(DesiredStatePolicy{
		Version:  "2026.08",
		Required: PolicyFacts{VLANs: []string{"20"}},
	}, PolicyEvaluationInput{
		CurrentContent:     "vlan 30",
		PredecessorContent: "vlan 20",
		BaselineContent:    "vlan 30",
		Vendor:             "cisco-ios",
	})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if len(result.Comparisons) != 2 {
		t.Fatalf("comparisons = %#v, want predecessor and selected baseline", result.Comparisons)
	}
	predecessor := result.Comparisons[0]
	baseline := result.Comparisons[1]
	if predecessor.ReferenceLabel != "predecessor" || len(predecessor.IntroducedFindings) != 1 || len(predecessor.ResolvedFindings) != 0 {
		t.Fatalf("predecessor comparison = %#v", predecessor)
	}
	if baseline.ReferenceLabel != "selected_baseline" || len(baseline.IntroducedFindings) != 0 || len(baseline.ResolvedFindings) != 0 {
		t.Fatalf("baseline comparison = %#v", baseline)
	}
	assertPolicyVersions(t, result)
}

func TestEvaluatePolicyComparisonReportsResolutionAgainstBaseline(t *testing.T) {
	result, err := EvaluatePolicy(DesiredStatePolicy{
		Version:  "2026.08",
		Required: PolicyFacts{VLANs: []string{"20"}},
	}, PolicyEvaluationInput{
		CurrentContent:  "vlan 20",
		BaselineContent: "vlan 30",
		Vendor:          "cisco-ios",
	})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	baseline := result.Comparisons[1]
	if baseline.ReferenceLabel != "selected_baseline" || len(baseline.IntroducedFindings) != 0 || len(baseline.ResolvedFindings) != 1 {
		t.Fatalf("baseline resolution comparison = %#v", baseline)
	}
	assertPolicyVersions(t, result)
}

func TestPolicyComparisonIgnoresEvidenceOrder(t *testing.T) {
	finding := PolicyFinding{
		PolicyVersion: "2026.08",
		Category:      "firewall_property",
		Requirement:   "deny ip any any",
		Expectation:   "forbidden",
		Status:        "present",
	}
	current := finding
	current.Evidence = []string{"deny ip any any", "access-list EDGE deny ip any any"}
	reference := finding
	reference.Evidence = []string{"access-list EDGE deny ip any any", "deny ip any any"}
	comparison := comparePolicyFindings("2026.08", "predecessor", []PolicyFinding{current}, []PolicyFinding{reference})
	if len(comparison.IntroducedFindings) != 0 || len(comparison.ResolvedFindings) != 0 {
		t.Fatalf("evidence-only change must not affect comparison identity: %#v", comparison)
	}
}

func TestEvaluatePolicyJSONIsDeterministic(t *testing.T) {
	policy := DesiredStatePolicy{
		Version: "2026.08",
		Required: PolicyFacts{
			VLANs:              []string{"20", "10", "20"},
			ManagementServices: []string{"ssh", "http"},
		},
		Forbidden: PolicyFacts{Routes: []string{"203.0.113.0/255.255.255.0", "198.51.100.0/255.255.255.0"}},
	}
	input := PolicyEvaluationInput{
		CurrentContent: "ip http server\nip http server\nip route 198.51.100.0 255.255.255.0 192.0.2.1\nvlan 10\n",
		Vendor:         "cisco-ios",
	}
	first, err := EvaluatePolicy(policy, input)
	if err != nil {
		t.Fatalf("first evaluation: %v", err)
	}
	second, err := EvaluatePolicy(policy, input)
	if err != nil {
		t.Fatalf("second evaluation: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("policy JSON is not deterministic\nfirst: %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func assertPolicyVersions(t *testing.T, result PolicyEvaluationResult) {
	t.Helper()
	if result.PolicyVersion != "2026.08" {
		t.Fatalf("result policy version = %q", result.PolicyVersion)
	}
	for _, evaluation := range []PolicySnapshotEvaluation{result.Current, result.Predecessor, result.SelectedBaseline} {
		if evaluation.PolicyVersion != "2026.08" {
			t.Fatalf("evaluation policy version = %q", evaluation.PolicyVersion)
		}
		for _, finding := range evaluation.Findings {
			if finding.PolicyVersion != "2026.08" {
				t.Fatalf("finding policy version = %q", finding.PolicyVersion)
			}
		}
	}
	for _, comparison := range result.Comparisons {
		if comparison.PolicyVersion != "2026.08" {
			t.Fatalf("comparison policy version = %q", comparison.PolicyVersion)
		}
		for _, finding := range append(append([]PolicyFinding{}, comparison.IntroducedFindings...), comparison.ResolvedFindings...) {
			if finding.PolicyVersion != "2026.08" {
				t.Fatalf("comparison finding policy version = %q", finding.PolicyVersion)
			}
		}
	}
}
