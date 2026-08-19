package configdiff

import (
	"fmt"
	"sort"
	"strings"
)

// DesiredStatePolicy declares the versioned configuration facts a snapshot must
// contain or must not contain. Values are vendor-normalized strings: VLAN IDs,
// route prefixes, service names, AAA statements, and firewall property text.
type DesiredStatePolicy struct {
	Version   string      `json:"version"`
	Required  PolicyFacts `json:"required"`
	Forbidden PolicyFacts `json:"forbidden"`
}

// PolicyFacts groups desired facts by the configuration category that owns them.
type PolicyFacts struct {
	VLANs              []string `json:"vlans,omitempty"`
	Routes             []string `json:"routes,omitempty"`
	ManagementServices []string `json:"management_services,omitempty"`
	AAA                []string `json:"aaa,omitempty"`
	FirewallProperties []string `json:"firewall_properties,omitempty"`
}

// PolicyEvaluationInput supplies the current snapshot and its two explicit
// references. Empty predecessor or baseline content is evaluated as an empty
// snapshot, which makes missing required facts visible in that reference.
type PolicyEvaluationInput struct {
	CurrentContent     string
	PredecessorContent string
	BaselineContent    string
	Vendor             string
}

// PolicyEvaluationResult retains independent compliance evidence for the
// current, predecessor, and selected-baseline snapshots.
type PolicyEvaluationResult struct {
	PolicyVersion    string                   `json:"policy_version"`
	Current          PolicySnapshotEvaluation `json:"current"`
	Predecessor      PolicySnapshotEvaluation `json:"predecessor"`
	SelectedBaseline PolicySnapshotEvaluation `json:"selected_baseline"`
	Comparisons      []PolicyComparison       `json:"comparisons"`
}

// PolicySnapshotEvaluation is the policy result for one named snapshot.
type PolicySnapshotEvaluation struct {
	PolicyVersion string          `json:"policy_version"`
	Snapshot      string          `json:"snapshot"`
	Findings      []PolicyFinding `json:"findings"`
}

// PolicyFinding identifies an unmet desired-state requirement. Evidence is
// either the enabled config statement for a forbidden fact or a deterministic
// statement describing an absent required fact.
type PolicyFinding struct {
	PolicyVersion string   `json:"policy_version"`
	Category      string   `json:"category"`
	Requirement   string   `json:"requirement"`
	Expectation   string   `json:"expectation"`
	Status        string   `json:"status"`
	Evidence      []string `json:"evidence"`
}

// PolicyComparison describes the current policy state relative to one named
// reference snapshot. Findings are matched by policy meaning, not evidence.
type PolicyComparison struct {
	PolicyVersion      string          `json:"policy_version"`
	ReferenceLabel     string          `json:"reference_label"`
	IntroducedFindings []PolicyFinding `json:"introduced_findings"`
	ResolvedFindings   []PolicyFinding `json:"resolved_findings"`
}

// EvaluatePolicy evaluates versioned desired state against the current snapshot
// and the two references used for drift review. It has no I/O and does not
// change AnalyzeContent or Explain behavior.
func EvaluatePolicy(policy DesiredStatePolicy, input PolicyEvaluationInput) (PolicyEvaluationResult, error) {
	if strings.TrimSpace(policy.Version) == "" {
		return PolicyEvaluationResult{}, fmt.Errorf("policy version is required")
	}
	policy = normalizeDesiredStatePolicy(policy)
	vendor := input.Vendor
	if vendor == "" {
		vendor = "auto"
	}
	parser, err := selectParser(vendor, input.CurrentContent+"\n"+input.PredecessorContent+"\n"+input.BaselineContent)
	if err != nil {
		return PolicyEvaluationResult{}, err
	}
	current := evaluatePolicySnapshot(policy, "current", parser.Parse(input.CurrentContent, vendor))
	predecessor := evaluatePolicySnapshot(policy, "predecessor", parser.Parse(input.PredecessorContent, vendor))
	baseline := evaluatePolicySnapshot(policy, "selected_baseline", parser.Parse(input.BaselineContent, vendor))
	return PolicyEvaluationResult{
		PolicyVersion:    policy.Version,
		Current:          current,
		Predecessor:      predecessor,
		SelectedBaseline: baseline,
		Comparisons: []PolicyComparison{
			comparePolicyFindings(policy.Version, "predecessor", current.Findings, predecessor.Findings),
			comparePolicyFindings(policy.Version, "selected_baseline", current.Findings, baseline.Findings),
		},
	}, nil
}

type policyInventory map[string]map[string][]string

func evaluatePolicySnapshot(policy DesiredStatePolicy, snapshot string, parsed parsedConfig) PolicySnapshotEvaluation {
	inventory := extractPolicyFacts(parsed)
	findings := []PolicyFinding{}
	add := func(category, expectation, requirement string) {
		evidence, present := policyFactEvidence(inventory, category, requirement)
		if (expectation == "required" && present) || (expectation == "forbidden" && !present) {
			return
		}
		status := "missing"
		if expectation == "forbidden" {
			status = "present"
		}
		if len(evidence) == 0 {
			evidence = []string{"required " + category + " " + requirement + " is absent"}
		}
		findings = append(findings, PolicyFinding{
			PolicyVersion: policy.Version,
			Category:      category,
			Requirement:   requirement,
			Expectation:   expectation,
			Status:        status,
			Evidence:      sortedUnique(evidence),
		})
	}
	for _, requirement := range sortedPolicyValues(policy.Required.VLANs) {
		add("vlan", "required", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Required.Routes) {
		add("route", "required", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Required.ManagementServices) {
		add("management_service", "required", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Required.AAA) {
		add("aaa", "required", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Required.FirewallProperties) {
		add("firewall_property", "required", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Forbidden.VLANs) {
		add("vlan", "forbidden", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Forbidden.Routes) {
		add("route", "forbidden", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Forbidden.ManagementServices) {
		add("management_service", "forbidden", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Forbidden.AAA) {
		add("aaa", "forbidden", requirement)
	}
	for _, requirement := range sortedPolicyValues(policy.Forbidden.FirewallProperties) {
		add("firewall_property", "forbidden", requirement)
	}
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i].Category + "|" + findings[i].Expectation + "|" + findings[i].Requirement
		right := findings[j].Category + "|" + findings[j].Expectation + "|" + findings[j].Requirement
		return left < right
	})
	return PolicySnapshotEvaluation{PolicyVersion: policy.Version, Snapshot: snapshot, Findings: findings}
}

func extractPolicyFacts(parsed parsedConfig) policyInventory {
	inventory := policyInventory{
		"vlan":               {},
		"route":              {},
		"management_service": {},
		"aaa":                {},
		"firewall_property":  {},
	}
	add := func(category, value, evidence string) {
		value = normalizePolicyValue(value)
		if value == "" {
			return
		}
		inventory[category][value] = append(inventory[category][value], evidence)
	}
	for _, block := range parsed.Blocks {
		for _, raw := range block.Lines {
			line := normalizeLine(raw)
			if line == "" || isNegatedCommand(line) {
				continue
			}
			lower := strings.ToLower(line)
			for _, vlan := range vlanIDs(line) {
				add("vlan", vlan, line)
			}
			if strings.HasPrefix(lower, "vlan ") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					add("vlan", fields[1], line)
				}
			}
			if isRouteLine(lower) {
				add("route", routePrefix(line), line)
			}
			for _, service := range managementServices(line) {
				add("management_service", service, line)
			}
			if isAAAAuthLine(lower) {
				add("aaa", line, line)
			}
			if (block.Kind == "acl" || block.Kind == "firewall") && isFirewallFactLine(lower) {
				add("firewall_property", line, line)
			}
		}
	}
	return inventory
}

func isNegatedCommand(line string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "no ")
}

func managementServices(line string) []string {
	lower := strings.ToLower(line)
	services := []string{}
	if strings.Contains(lower, "ip http server") || strings.Contains(lower, "http server") {
		services = append(services, "http")
	}
	if strings.Contains(lower, "ip http secure-server") || strings.Contains(lower, "https server") {
		services = append(services, "https")
	}
	if strings.Contains(lower, "ssh") {
		services = append(services, "ssh")
	}
	if strings.Contains(lower, "telnet") {
		services = append(services, "telnet")
	}
	if strings.Contains(lower, "snmp") {
		services = append(services, "snmp")
	}
	return sortedUnique(services)
}

func isFirewallFactLine(lower string) bool {
	return !strings.HasPrefix(lower, "ip access-list ")
}

func policyFactEvidence(inventory policyInventory, category, requirement string) ([]string, bool) {
	requirement = normalizePolicyValue(requirement)
	if requirement == "" {
		return nil, false
	}
	values := inventory[category]
	if evidence, ok := values[requirement]; ok {
		return sortedUnique(evidence), true
	}
	if category == "firewall_property" {
		matches := []string{}
		for value, evidence := range values {
			if strings.Contains(value, requirement) {
				matches = append(matches, evidence...)
			}
		}
		return sortedUnique(matches), len(matches) > 0
	}
	return nil, false
}

func normalizePolicyValue(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func sortedPolicyValues(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = normalizePolicyValue(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func normalizeDesiredStatePolicy(policy DesiredStatePolicy) DesiredStatePolicy {
	policy.Required = normalizePolicyFacts(policy.Required)
	policy.Forbidden = normalizePolicyFacts(policy.Forbidden)
	return policy
}

func normalizePolicyFacts(facts PolicyFacts) PolicyFacts {
	facts.VLANs = sortedPolicyValues(facts.VLANs)
	facts.Routes = sortedPolicyValues(facts.Routes)
	facts.ManagementServices = sortedPolicyValues(facts.ManagementServices)
	facts.AAA = sortedPolicyValues(facts.AAA)
	facts.FirewallProperties = sortedPolicyValues(facts.FirewallProperties)
	return facts
}

func comparePolicyFindings(policyVersion, referenceLabel string, current, reference []PolicyFinding) PolicyComparison {
	currentByIdentity := map[string]PolicyFinding{}
	for _, finding := range current {
		currentByIdentity[policyFindingIdentity(finding)] = finding
	}
	referenceByIdentity := map[string]PolicyFinding{}
	for _, finding := range reference {
		referenceByIdentity[policyFindingIdentity(finding)] = finding
	}
	comparison := PolicyComparison{PolicyVersion: policyVersion, ReferenceLabel: referenceLabel, IntroducedFindings: []PolicyFinding{}, ResolvedFindings: []PolicyFinding{}}
	for identity, finding := range currentByIdentity {
		if _, found := referenceByIdentity[identity]; !found {
			comparison.IntroducedFindings = append(comparison.IntroducedFindings, finding)
		}
	}
	for identity, finding := range referenceByIdentity {
		if _, found := currentByIdentity[identity]; !found {
			comparison.ResolvedFindings = append(comparison.ResolvedFindings, finding)
		}
	}
	sortPolicyFindings(comparison.IntroducedFindings)
	sortPolicyFindings(comparison.ResolvedFindings)
	return comparison
}

func policyFindingIdentity(finding PolicyFinding) string {
	return strings.Join([]string{finding.Category, finding.Expectation, normalizePolicyValue(finding.Requirement), finding.Status}, "|")
}

func sortPolicyFindings(findings []PolicyFinding) {
	sort.Slice(findings, func(i, j int) bool { return policyFindingIdentity(findings[i]) < policyFindingIdentity(findings[j]) })
}

func sortedUnique(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
