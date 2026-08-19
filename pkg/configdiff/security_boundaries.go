package configdiff

import (
	"sort"
	"strings"
)

type zoneFlowFact struct {
	SourceZone      string
	DestinationZone string
	Action          string
	Protocol        string
	Service         string
	Policy          string
	VRF             string
	Tenant          string
	AnySource       bool
	AnyDestination  bool
	Management      bool
	Summary         string
	Evidence        []string
}

type zoneMembershipFact struct {
	Zone     string
	Member   string
	Summary  string
	Evidence []string
}

// securityBoundaryChanges extracts zone-flow and zone-membership facts from
// firewall/acl/zone block diffs without reshaping existing block IDs.
func securityBoundaryChanges(changes []BlockChange) []TouchedSecurityBoundary {
	beforeFlows := map[string]zoneFlowFact{}
	afterFlows := map[string]zoneFlowFact{}
	beforeMembers := map[string]zoneMembershipFact{}
	afterMembers := map[string]zoneMembershipFact{}

	for _, change := range changes {
		if !isSecurityBoundarySource(change) {
			continue
		}
		for key, flow := range parseZoneFlowsFromLines(change.BeforeLines, change.Header) {
			mergeZoneFlowFact(beforeFlows, key, flow)
		}
		for key, flow := range parseZoneFlowsFromLines(change.AfterLines, change.Header) {
			mergeZoneFlowFact(afterFlows, key, flow)
		}
		for key, member := range parseZoneMembershipFromLines(change.BeforeLines) {
			mergeZoneMembershipFact(beforeMembers, key, member)
		}
		for key, member := range parseZoneMembershipFromLines(change.AfterLines) {
			mergeZoneMembershipFact(afterMembers, key, member)
		}
	}

	out := []TouchedSecurityBoundary{}
	out = append(out, diffZoneFlows(beforeFlows, afterFlows)...)
	out = append(out, diffZoneMemberships(beforeMembers, afterMembers)...)
	sort.Slice(out, func(i, j int) bool {
		return securityBoundarySortKey(out[i]) < securityBoundarySortKey(out[j])
	})
	return out
}

func isSecurityBoundarySource(change BlockChange) bool {
	if change.Kind == "firewall" || change.Kind == "acl" {
		return true
	}
	lower := strings.ToLower(change.Header + " " + change.ID)
	if strings.Contains(lower, "zone") || strings.Contains(lower, "from-zone") || strings.Contains(lower, "srcintf") {
		return true
	}
	for _, line := range append(change.BeforeLines, change.AfterLines...) {
		if securityBoundaryLine(line) {
			return true
		}
	}
	return false
}

func securityBoundaryLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	switch {
	case strings.Contains(lower, " from-zone ") && strings.Contains(lower, " to-zone "):
		return true
	case strings.Contains(lower, " rules ") && (strings.Contains(lower, " from ") || strings.Contains(lower, " to ")):
		return true
	case strings.HasPrefix(lower, "set zone "),
		strings.HasPrefix(lower, "delete zone "):
		return true
	case strings.HasPrefix(lower, "set srcintf "),
		strings.HasPrefix(lower, "set dstintf "):
		return true
	default:
		return false
	}
}

func parseZoneFlowsFromLines(lines []string, header string) map[string]zoneFlowFact {
	out := map[string]zoneFlowFact{}
	if flow, ok := parsePANOSZoneFlow(lines, header); ok {
		mergeZoneFlowFact(out, zoneFlowKey(flow), flow)
	}
	if flow, ok := parseJunosZoneFlow(lines, header); ok {
		mergeZoneFlowFact(out, zoneFlowKey(flow), flow)
	}
	if flow, ok := parseFortinetZoneFlow(lines, header); ok {
		mergeZoneFlowFact(out, zoneFlowKey(flow), flow)
	}
	return out
}

func parsePANOSZoneFlow(lines []string, header string) (zoneFlowFact, bool) {
	flow := zoneFlowFact{}
	evidence := []string{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		fields := strings.Fields(trimmed)
		if !strings.Contains(lower, "rulebase security rules") {
			continue
		}
		evidence = append(evidence, trimmed)
		if name := tokenAfter(fields, "rules"); name != "" {
			flow.Policy = name
		}
		if from := tokenAfter(fields, "from"); from != "" {
			flow.SourceZone = from
		}
		if idx := indexOfFold(fields, "to"); idx >= 4 && idx+1 < len(fields) {
			flow.DestinationZone = fields[idx+1]
		}
		if action := tokenAfter(fields, "action"); action != "" {
			flow.Action = strings.ToLower(action)
		}
		if app := tokenAfter(fields, "application"); app != "" {
			flow.Service = app
			flow.Protocol = "application"
		}
		if service := tokenAfter(fields, "service"); service != "" && flow.Service == "" {
			flow.Service = service
		}
		if source := tokenAfter(fields, "source"); source != "" {
			flow.AnySource = isAnyScopeToken(source)
		}
		if dest := tokenAfter(fields, "destination"); dest != "" {
			flow.AnyDestination = isAnyScopeToken(dest)
		}
	}
	if flow.SourceZone == "" || flow.DestinationZone == "" {
		return zoneFlowFact{}, false
	}
	if flow.Policy == "" {
		flow.Policy = policyFromHeader(header)
	}
	flow.Management = isManagementService(flow.Service)
	flow.Evidence = uniquePreserve(evidence)
	flow.Summary = zoneFlowSummary(flow)
	return flow, true
}

func parseJunosZoneFlow(lines []string, header string) (zoneFlowFact, bool) {
	flow := zoneFlowFact{}
	evidence := []string{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		fields := strings.Fields(trimmed)
		if !(strings.Contains(lower, "security policies") && strings.Contains(lower, "from-zone") && strings.Contains(lower, "to-zone")) {
			continue
		}
		evidence = append(evidence, trimmed)
		if from := tokenAfter(fields, "from-zone"); from != "" {
			flow.SourceZone = from
		}
		if to := tokenAfter(fields, "to-zone"); to != "" {
			flow.DestinationZone = to
		}
		if policy := tokenAfter(fields, "policy"); policy != "" {
			flow.Policy = policy
		}
		if app := tokenAfter(fields, "application"); app != "" {
			flow.Service = app
			flow.Protocol = "application"
		}
		if source := tokenAfter(fields, "source-address"); source != "" {
			flow.AnySource = isAnyScopeToken(source)
		}
		if dest := tokenAfter(fields, "destination-address"); dest != "" {
			flow.AnyDestination = isAnyScopeToken(dest)
		}
		lowerFields := strings.Fields(lower)
		if containsFold(lowerFields, "permit") || containsFold(lowerFields, "accept") {
			flow.Action = "permit"
		}
		if containsFold(lowerFields, "deny") || containsFold(lowerFields, "reject") {
			flow.Action = "deny"
		}
	}
	if flow.SourceZone == "" || flow.DestinationZone == "" {
		return zoneFlowFact{}, false
	}
	if flow.Policy == "" {
		flow.Policy = policyFromHeader(header)
	}
	flow.Management = isManagementService(flow.Service)
	flow.Evidence = uniquePreserve(evidence)
	flow.Summary = zoneFlowSummary(flow)
	return flow, true
}

func parseFortinetZoneFlow(lines []string, header string) (zoneFlowFact, bool) {
	flow := zoneFlowFact{}
	evidence := []string{}
	hasPolicySignals := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "set srcintf "):
			flow.SourceZone = fortinetSetValue(trimmed, "set srcintf")
			evidence = append(evidence, trimmed)
			hasPolicySignals = true
		case strings.HasPrefix(lower, "set dstintf "):
			flow.DestinationZone = fortinetSetValue(trimmed, "set dstintf")
			evidence = append(evidence, trimmed)
			hasPolicySignals = true
		case strings.HasPrefix(lower, "set action "):
			flow.Action = strings.ToLower(fortinetSetValue(trimmed, "set action"))
			evidence = append(evidence, trimmed)
			hasPolicySignals = true
		case strings.HasPrefix(lower, "set service "):
			flow.Service = fortinetSetValue(trimmed, "set service")
			evidence = append(evidence, trimmed)
			hasPolicySignals = true
		case strings.HasPrefix(lower, "set name "):
			flow.Policy = fortinetSetValue(trimmed, "set name")
			evidence = append(evidence, trimmed)
			hasPolicySignals = true
		case strings.HasPrefix(lower, "set srcaddr "):
			flow.AnySource = isAnyScopeToken(fortinetSetValue(trimmed, "set srcaddr"))
			evidence = append(evidence, trimmed)
			hasPolicySignals = true
		case strings.HasPrefix(lower, "set dstaddr "):
			flow.AnyDestination = isAnyScopeToken(fortinetSetValue(trimmed, "set dstaddr"))
			evidence = append(evidence, trimmed)
			hasPolicySignals = true
		case strings.HasPrefix(lower, "edit "):
			if flow.Policy == "" {
				flow.Policy = unquoteToken(strings.TrimSpace(trimmed[len("edit "):]))
			}
			evidence = append(evidence, trimmed)
		}
	}
	if !hasPolicySignals || flow.SourceZone == "" || flow.DestinationZone == "" {
		return zoneFlowFact{}, false
	}
	if flow.Policy == "" {
		flow.Policy = policyFromHeader(header)
	}
	flow.Management = isManagementService(flow.Service)
	flow.Evidence = uniquePreserve(evidence)
	flow.Summary = zoneFlowSummary(flow)
	return flow, true
}

func parseZoneMembershipFromLines(lines []string) map[string]zoneMembershipFact {
	out := map[string]zoneMembershipFact{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		fields := strings.Fields(trimmed)
		// PAN-OS: set zone <name> network layer3 <iface>
		if len(fields) >= 6 && strings.EqualFold(fields[0], "set") && strings.EqualFold(fields[1], "zone") {
			zone := fields[2]
			member := ""
			if idx := indexOfFold(fields, "layer3"); idx >= 0 && idx+1 < len(fields) {
				member = fields[idx+1]
			} else if idx := indexOfFold(fields, "layer2"); idx >= 0 && idx+1 < len(fields) {
				member = fields[idx+1]
			}
			if zone == "" || member == "" {
				continue
			}
			fact := zoneMembershipFact{
				Zone:     zone,
				Member:   member,
				Summary:  zone + " member " + member,
				Evidence: []string{trimmed},
			}
			out[zoneMembershipKey(fact)] = fact
			continue
		}
		// Junos: set security zones security-zone <name> interfaces <iface>
		if strings.Contains(lower, "security zones security-zone") && strings.Contains(lower, " interfaces ") {
			zone := tokenAfter(fields, "security-zone")
			member := tokenAfter(fields, "interfaces")
			if zone == "" || member == "" {
				continue
			}
			fact := zoneMembershipFact{
				Zone:     zone,
				Member:   member,
				Summary:  zone + " member " + member,
				Evidence: []string{trimmed},
			}
			out[zoneMembershipKey(fact)] = fact
		}
	}
	return out
}

func diffZoneFlows(before, after map[string]zoneFlowFact) []TouchedSecurityBoundary {
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	sorted := make([]string, 0, len(keys))
	for key := range keys {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)

	out := []TouchedSecurityBoundary{}
	for _, key := range sorted {
		b, hadBefore := before[key]
		a, hasAfter := after[key]
		switch {
		case !hadBefore && hasAfter:
			out = append(out, touchedFromZoneFlow(a, "added", "", a.Summary))
		case hadBefore && !hasAfter:
			out = append(out, touchedFromZoneFlow(b, "removed", b.Summary, ""))
		case zoneFlowCoreChanged(b, a):
			fact := a
			if fact.Policy == "" {
				fact.Policy = b.Policy
			}
			out = append(out, touchedFromZoneFlow(fact, "changed", b.Summary, a.Summary))
		}
	}
	return out
}

func diffZoneMemberships(before, after map[string]zoneMembershipFact) []TouchedSecurityBoundary {
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	sorted := make([]string, 0, len(keys))
	for key := range keys {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)

	out := []TouchedSecurityBoundary{}
	for _, key := range sorted {
		b, hadBefore := before[key]
		a, hasAfter := after[key]
		switch {
		case !hadBefore && hasAfter:
			out = append(out, TouchedSecurityBoundary{
				Kind:       "zone_membership",
				Zone:       a.Zone,
				Member:     a.Member,
				ChangeType: "added",
				After:      a.Summary,
				Evidence:   append([]string{}, a.Evidence...),
			})
		case hadBefore && !hasAfter:
			out = append(out, TouchedSecurityBoundary{
				Kind:       "zone_membership",
				Zone:       b.Zone,
				Member:     b.Member,
				ChangeType: "removed",
				Before:     b.Summary,
				Evidence:   append([]string{}, b.Evidence...),
			})
		}
	}
	return out
}

func zoneFlowCoreChanged(before, after zoneFlowFact) bool {
	return before.Action != after.Action ||
		before.SourceZone != after.SourceZone ||
		before.DestinationZone != after.DestinationZone ||
		before.Service != after.Service ||
		before.AnySource != after.AnySource ||
		before.AnyDestination != after.AnyDestination ||
		before.Management != after.Management ||
		before.Summary != after.Summary
}

func touchedFromZoneFlow(flow zoneFlowFact, changeType, before, after string) TouchedSecurityBoundary {
	return TouchedSecurityBoundary{
		Kind:            "zone_flow",
		SourceZone:      flow.SourceZone,
		DestinationZone: flow.DestinationZone,
		Action:          flow.Action,
		Protocol:        flow.Protocol,
		Service:         flow.Service,
		Policy:          flow.Policy,
		VRF:             flow.VRF,
		Tenant:          flow.Tenant,
		ChangeType:      changeType,
		Before:          before,
		After:           after,
		Evidence:        append([]string{}, flow.Evidence...),
	}
}

func appendSecurityBoundaryFindings(add func(severity, category, title, recommendation string, evidence, details []string), boundaries []TouchedSecurityBoundary) {
	for _, boundary := range boundaries {
		switch boundary.Kind {
		case "zone_membership":
			add("medium", "security_boundary", "Security zone membership changed",
				"Confirm the interface or network still belongs in this security zone and that dependent policies remain correct.",
				boundary.Evidence,
				[]string{"Zone " + boundary.Zone + " membership " + boundary.ChangeType + " for " + boundary.Member + "."})
		case "zone_flow":
			crossZone := distinctZones(boundary.SourceZone, boundary.DestinationZone)
			allowing := isAllowAction(boundary.Action)
			collapsed := zoneFlowCollapsed(boundary)
			mgmt := isManagementService(boundary.Service) || boundaryLooksManagement(boundary)

			switch boundary.ChangeType {
			case "added":
				if allowing && crossZone {
					add("high", "security_boundary", "Newly permitted cross-zone flow",
						"Validate the new cross-zone permit against intended trust boundaries and least-privilege policy before relying on it.",
						boundary.Evidence,
						[]string{"Added permit from " + boundary.SourceZone + " to " + boundary.DestinationZone + policyDetail(boundary) + "."})
				}
			case "changed":
				if allowing && collapsed {
					add("high", "security_boundary", "Trust boundary collapsed",
						"A previously scoped zone pair now permits broad or any-to-any traffic; restore explicit sources/destinations or deny-by-default posture.",
						boundary.Evidence,
						[]string{"Collapsed trust boundary on " + boundary.SourceZone + " -> " + boundary.DestinationZone + policyDetail(boundary) + "."})
				}
				if allowing && crossZone && actionBecameAllow(boundary) {
					add("high", "security_boundary", "Newly permitted cross-zone flow",
						"Validate the new cross-zone permit against intended trust boundaries and least-privilege policy before relying on it.",
						boundary.Evidence,
						[]string{"Permit enabled from " + boundary.SourceZone + " to " + boundary.DestinationZone + policyDetail(boundary) + "."})
				}
			}
			if allowing && mgmt && (crossZone || collapsed) && (boundary.ChangeType == "added" || boundary.ChangeType == "changed") {
				add("high", "security_boundary", "Management access crosses segments",
					"Restrict management protocols to approved administration zones; do not allow SSH/HTTPS/SNMP across untrusted segment boundaries.",
					boundary.Evidence,
					[]string{"Management service " + managementLabel(boundary) + " permitted from " + boundary.SourceZone + " to " + boundary.DestinationZone + policyDetail(boundary) + "."})
			}
		}
	}
}

func zoneFlowCollapsed(boundary TouchedSecurityBoundary) bool {
	if isAnyScopeToken(boundary.SourceZone) || isAnyScopeToken(boundary.DestinationZone) {
		return true
	}
	blob := strings.ToLower(boundary.After + " " + strings.Join(boundary.Evidence, " "))
	hasAnySource := strings.Contains(blob, " source any") ||
		strings.Contains(blob, " source-address any") ||
		strings.Contains(blob, " source-address 0.0.0.0/0") ||
		strings.Contains(blob, `set srcaddr "all"`) ||
		strings.Contains(blob, "set srcaddr all") ||
		strings.Contains(blob, " any-source")
	hasAnyDest := strings.Contains(blob, " destination any") ||
		strings.Contains(blob, " destination-address any") ||
		strings.Contains(blob, " destination-address 0.0.0.0/0") ||
		strings.Contains(blob, `set dstaddr "all"`) ||
		strings.Contains(blob, "set dstaddr all") ||
		strings.Contains(blob, " any-destination")
	return hasAnySource && hasAnyDest
}

func actionBecameAllow(boundary TouchedSecurityBoundary) bool {
	before := strings.ToLower(boundary.Before)
	after := strings.ToLower(boundary.After)
	if !isAllowAction(boundary.Action) {
		return false
	}
	beforeAllow := strings.Contains(before, "allow") || strings.Contains(before, "permit") || strings.Contains(before, "accept")
	afterAllow := strings.Contains(after, "allow") || strings.Contains(after, "permit") || strings.Contains(after, "accept")
	return afterAllow && !beforeAllow
}

func boundaryLooksManagement(boundary TouchedSecurityBoundary) bool {
	blob := strings.ToLower(boundary.After + " " + strings.Join(boundary.Evidence, " "))
	return strings.Contains(blob, " application ssh") ||
		strings.Contains(blob, " application snmp") ||
		strings.Contains(blob, " application web-browsing") ||
		strings.Contains(blob, " application panos-web-interface") ||
		strings.Contains(blob, " application junos-ssh") ||
		strings.Contains(blob, " application junos-https") ||
		strings.Contains(blob, " application junos-telnet") ||
		strings.Contains(blob, `set service "ssh"`) ||
		strings.Contains(blob, "set service ssh") ||
		strings.Contains(blob, `set service "https"`) ||
		strings.Contains(blob, "set service https")
}

func enrichTouchedRuleZones(rule *TouchedRule, lines []string, header string) {
	if flow, ok := parsePANOSZoneFlow(lines, header); ok {
		applyZoneFlowToRule(rule, flow)
	}
	if flow, ok := parseJunosZoneFlow(lines, header); ok {
		applyZoneFlowToRule(rule, flow)
	}
	if flow, ok := parseFortinetZoneFlow(lines, header); ok {
		applyZoneFlowToRule(rule, flow)
	}
}

func applyZoneFlowToRule(rule *TouchedRule, flow zoneFlowFact) {
	if rule.SourceZone == "" {
		rule.SourceZone = flow.SourceZone
	}
	if rule.DestinationZone == "" {
		rule.DestinationZone = flow.DestinationZone
	}
	if rule.Policy == "" {
		rule.Policy = flow.Policy
	}
	if rule.VRF == "" {
		rule.VRF = flow.VRF
	}
	if rule.Tenant == "" {
		rule.Tenant = flow.Tenant
	}
	if rule.Action == "" {
		rule.Action = flow.Action
	}
	if rule.Service == "" {
		rule.Service = flow.Service
	}
	if rule.Protocol == "" {
		rule.Protocol = flow.Protocol
	}
}

func mergeZoneFlowFact(dst map[string]zoneFlowFact, key string, flow zoneFlowFact) {
	existing, ok := dst[key]
	if !ok {
		dst[key] = flow
		return
	}
	if existing.Action == "" {
		existing.Action = flow.Action
	}
	if existing.Service == "" {
		existing.Service = flow.Service
	}
	if existing.Protocol == "" {
		existing.Protocol = flow.Protocol
	}
	if existing.Policy == "" {
		existing.Policy = flow.Policy
	}
	if existing.SourceZone == "" {
		existing.SourceZone = flow.SourceZone
	}
	if existing.DestinationZone == "" {
		existing.DestinationZone = flow.DestinationZone
	}
	existing.AnySource = existing.AnySource || flow.AnySource
	existing.AnyDestination = existing.AnyDestination || flow.AnyDestination
	existing.Management = existing.Management || flow.Management
	if flow.Summary != "" {
		existing.Summary = zoneFlowSummary(existing)
	}
	existing.Evidence = uniquePreserve(append(existing.Evidence, flow.Evidence...))
	dst[key] = existing
}

func mergeZoneMembershipFact(dst map[string]zoneMembershipFact, key string, fact zoneMembershipFact) {
	existing, ok := dst[key]
	if !ok {
		dst[key] = fact
		return
	}
	existing.Evidence = uniquePreserve(append(existing.Evidence, fact.Evidence...))
	dst[key] = existing
}

func zoneFlowKey(flow zoneFlowFact) string {
	if flow.Policy != "" {
		return "zone_flow|" + strings.ToLower(flow.Policy)
	}
	return "zone_flow|" + strings.ToLower(flow.SourceZone) + "|" + strings.ToLower(flow.DestinationZone)
}

func zoneMembershipKey(fact zoneMembershipFact) string {
	return "zone_membership|" + strings.ToLower(fact.Zone) + "|" + strings.ToLower(fact.Member)
}

func zoneFlowSummary(flow zoneFlowFact) string {
	parts := []string{flow.SourceZone + " -> " + flow.DestinationZone}
	if flow.Action != "" {
		parts = append(parts, flow.Action)
	}
	if flow.Service != "" {
		parts = append(parts, flow.Service)
	}
	if flow.AnySource || flow.AnyDestination {
		scope := []string{}
		if flow.AnySource {
			scope = append(scope, "any-source")
		}
		if flow.AnyDestination {
			scope = append(scope, "any-destination")
		}
		parts = append(parts, strings.Join(scope, ","))
	}
	return strings.Join(parts, " ")
}

func securityBoundarySortKey(item TouchedSecurityBoundary) string {
	return item.Kind + "|" + strings.ToLower(item.SourceZone) + "|" + strings.ToLower(item.DestinationZone) + "|" + strings.ToLower(item.Zone) + "|" + strings.ToLower(item.Member) + "|" + strings.ToLower(item.Policy) + "|" + item.ChangeType
}

func policyFromHeader(header string) string {
	fields := strings.Fields(header)
	if name := tokenAfter(fields, "rules"); name != "" {
		return name
	}
	if name := tokenAfter(fields, "policy"); name != "" {
		return name
	}
	return ""
}

func fortinetSetValue(line, prefix string) string {
	lower := strings.ToLower(line)
	want := strings.ToLower(prefix)
	if !strings.HasPrefix(lower, want) {
		return ""
	}
	return unquoteToken(strings.TrimSpace(line[len(prefix):]))
}

func unquoteToken(value string) string {
	value = strings.TrimSpace(value)
	return strings.Trim(value, `"'`)
}

func isAnyScopeToken(value string) bool {
	switch strings.ToLower(unquoteToken(value)) {
	case "any", "all", "0.0.0.0/0", "::/0":
		return true
	default:
		return false
	}
}

func isAllowAction(action string) bool {
	switch strings.ToLower(action) {
	case "allow", "permit", "accept":
		return true
	default:
		return false
	}
}

func distinctZones(src, dst string) bool {
	if src == "" || dst == "" {
		return false
	}
	if isAnyScopeToken(src) && isAnyScopeToken(dst) {
		return false
	}
	if isAnyScopeToken(src) || isAnyScopeToken(dst) {
		return true
	}
	return !strings.EqualFold(src, dst)
}

func isManagementService(value string) bool {
	switch strings.ToLower(unquoteToken(value)) {
	case "ssh", "telnet", "https", "http", "snmp", "web-browsing", "panos-web-interface",
		"junos-ssh", "junos-https", "junos-telnet", "junos-http", "service-ssh", "service-https",
		"22", "23", "80", "443", "161":
		return true
	default:
		return false
	}
}

func managementLabel(boundary TouchedSecurityBoundary) string {
	if boundary.Service != "" {
		return boundary.Service
	}
	if boundary.Protocol != "" {
		return boundary.Protocol
	}
	return "management"
}

func policyDetail(boundary TouchedSecurityBoundary) string {
	if boundary.Policy == "" {
		return ""
	}
	return " (policy " + boundary.Policy + ")"
}
