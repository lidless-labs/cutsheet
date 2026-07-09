package configdiff

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

func analyze(before, after parsedConfig, requestedVendor string) Analysis {
	changes := diffBlocks(before.Blocks, after.Blocks)
	analysis := Analysis{
		SchemaVersion:            "1.1",
		DetectedPlatform:         after.Detection,
		BlockChanges:             changes,
		TouchedInterfaces:        touchedInterfaces(changes),
		TouchedVLANs:             touchedVLANs(changes),
		TouchedRoutes:            touchedRoutes(changes),
		TouchedACLFirewallRules:  touchedRules(changes),
		TouchedNATObjects:        touchedObjects(changes, "nat"),
		TouchedVPNObjects:        touchedObjects(changes, "vpn"),
		ManagementPlaneChanges:   categoryChanges(changes, "management"),
		AAAChanges:               categoryChanges(changes, "aaa"),
		LoggingSNMPNTPDNSChanges: categoryChanges(changes, "observability"),
		SwitchingChanges:         switchingChanges(changes),
	}
	analysis.DetectedPlatform.RequestedVendor = requestedVendor
	analysis.RiskFindings = riskFindings(changes, after.Blocks)
	analysis.Rollback = rollbackAnalysis(changes, analysis.RiskFindings, analysis.DetectedPlatform.Parser)
	return analysis
}

func diffBlocks(before, after []configBlock) []BlockChange {
	beforeMap := map[string]configBlock{}
	afterMap := map[string]configBlock{}
	ids := map[string]bool{}
	for _, block := range before {
		beforeMap[block.ID] = block
		ids[block.ID] = true
	}
	for _, block := range after {
		afterMap[block.ID] = block
		ids[block.ID] = true
	}

	sortedIDs := make([]string, 0, len(ids))
	for id := range ids {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	changes := []BlockChange{}
	for _, id := range sortedIDs {
		b, hadBefore := beforeMap[id]
		a, hasAfter := afterMap[id]
		switch {
		case !hadBefore && hasAfter:
			changes = append(changes, BlockChange{ID: id, Kind: a.Kind, ChangeType: "added", Header: a.Header, AfterLines: a.Lines})
		case hadBefore && !hasAfter:
			changes = append(changes, BlockChange{ID: id, Kind: b.Kind, ChangeType: "removed", Header: b.Header, BeforeLines: b.Lines})
		case blockFingerprint(b) != blockFingerprint(a):
			changes = append(changes, BlockChange{ID: id, Kind: a.Kind, ChangeType: "changed", Header: a.Header, BeforeLines: b.Lines, AfterLines: a.Lines})
		}
	}
	return changes
}

func touchedInterfaces(changes []BlockChange) []TouchedInterface {
	out := []TouchedInterface{}
	seen := map[string]bool{}
	for _, change := range changes {
		names := []string{}
		if change.Kind == "interface" && strings.HasPrefix(change.ID, "interface:") {
			names = append(names, strings.TrimPrefix(change.ID, "interface:"))
		}
		for _, line := range append(change.BeforeLines, change.AfterLines...) {
			names = append(names, interfaceNames(line)...)
		}
		for _, name := range names {
			key := name + "|" + change.ChangeType
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, TouchedInterface{
				Name:        name,
				ChangeType:  change.ChangeType,
				BeforeLines: change.BeforeLines,
				AfterLines:  change.AfterLines,
			})
		}
	}
	return out
}

func touchedVLANs(changes []BlockChange) []TouchedVLAN {
	seen := map[string]bool{}
	out := []TouchedVLAN{}
	for _, change := range changes {
		for _, line := range append(change.BeforeLines, change.AfterLines...) {
			for _, vlan := range vlanIDs(line) {
				key := vlan + "|" + change.ChangeType
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, TouchedVLAN{ID: vlan, ChangeType: change.ChangeType, Evidence: evidenceForLine(line)})
			}
		}
		if change.Kind == "vlan" {
			id := strings.TrimPrefix(change.ID, "vlan:")
			key := id + "|" + change.ChangeType
			if !seen[key] {
				seen[key] = true
				out = append(out, TouchedVLAN{ID: id, ChangeType: change.ChangeType, Evidence: combinedEvidence(change)})
			}
		}
	}
	return out
}

func touchedRoutes(changes []BlockChange) []TouchedRoute {
	seen := map[string]bool{}
	out := []TouchedRoute{}
	for _, change := range changes {
		beforeRoutes := matchingLines(change.BeforeLines, func(line string) bool { return isRouteLine(strings.ToLower(line)) })
		afterRoutes := matchingLines(change.AfterLines, func(line string) bool { return isRouteLine(strings.ToLower(line)) })
		if change.Kind == "route" && len(beforeRoutes) == 0 && len(afterRoutes) == 0 {
			allLines := append(append([]string{}, change.BeforeLines...), change.AfterLines...)
			prefix := fortinetRoutePrefix(allLines)
			beforeNextHop := fortinetRouteNextHop(change.BeforeLines)
			afterNextHop := fortinetRouteNextHop(change.AfterLines)
			if prefix == "" {
				prefix = panosRoutePrefix(allLines)
				beforeNextHop = panosRouteNextHop(change.BeforeLines)
				afterNextHop = panosRouteNextHop(change.AfterLines)
			}
			if prefix == "" {
				continue
			}
			key := prefix + "|" + change.ChangeType
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, TouchedRoute{
				Prefix:        prefix,
				ChangeType:    change.ChangeType,
				BeforeNextHop: beforeNextHop,
				AfterNextHop:  afterNextHop,
				Evidence:      combinedEvidence(change),
			})
			continue
		}
		for _, line := range append(append([]string{}, beforeRoutes...), afterRoutes...) {
			if isRouteLine(strings.ToLower(line)) {
				prefix := routePrefix(line)
				key := prefix + "|" + change.ChangeType
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, TouchedRoute{
					Prefix:        prefix,
					ChangeType:    change.ChangeType,
					BeforeNextHop: firstRouteNextHopForPrefix(beforeRoutes, prefix),
					AfterNextHop:  firstRouteNextHopForPrefix(afterRoutes, prefix),
					Evidence:      uniquePreserve(append(beforeRoutes, afterRoutes...)),
				})
			}
		}
	}
	return out
}

func touchedRules(changes []BlockChange) []TouchedRule {
	seen := map[string]bool{}
	out := []TouchedRule{}
	for _, change := range changes {
		if change.Kind != "acl" && change.Kind != "firewall" {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(change.ID, "acl:"), "firewall:")
		parsed := TouchedRule{}
		for _, line := range append(change.BeforeLines, change.AfterLines...) {
			rule := parseACLRule(line)
			if betterRuleParse(rule, parsed) {
				parsed = rule
			}
		}
		key := name + "|" + change.ChangeType
		if seen[key] {
			continue
		}
		seen[key] = true
		parsed.Name = name
		parsed.ChangeType = change.ChangeType
		parsed.Evidence = combinedEvidence(change)
		out = append(out, parsed)
	}
	return out
}

func touchedObjects(changes []BlockChange, kind string) []TouchedObject {
	seen := map[string]bool{}
	out := []TouchedObject{}
	for _, change := range changes {
		if change.Kind != kind {
			continue
		}
		name := strings.TrimPrefix(change.ID, kind+":")
		name = strings.TrimPrefix(name, kind+"-object:")
		key := name + "|" + change.ChangeType
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, TouchedObject{Name: name, Kind: kind, ChangeType: change.ChangeType, Evidence: combinedEvidence(change)})
	}
	return out
}

func categoryChanges(changes []BlockChange, kind string) []CategoryChange {
	out := []CategoryChange{}
	for _, change := range changes {
		if change.Kind != kind {
			continue
		}
		category := kind
		if kind == "observability" {
			category = "logging_snmp_ntp_dns"
		}
		out = append(out, CategoryChange{Category: category, ChangeType: change.ChangeType, Evidence: combinedEvidence(change)})
	}
	return out
}

func riskFindings(changes []BlockChange, afterBlocks []configBlock) []RiskFinding {
	findings := []RiskFinding{}
	add := func(severity, category, title, recommendation string, evidence []string, details []string) {
		key := severity + "|" + category + "|" + title + "|" + recommendation
		for i := range findings {
			existingKey := findings[i].Severity + "|" + findings[i].Category + "|" + findings[i].Title + "|" + findings[i].Recommendation
			if existingKey == key {
				findings[i].Evidence = uniquePreserve(append(findings[i].Evidence, evidence...))
				findings[i].Details = uniquePreserve(append(findings[i].Details, details...))
				return
			}
		}
		findings = append(findings, RiskFinding{Severity: severity, Category: category, Title: title, Details: uniquePreserve(details), Evidence: uniquePreserve(evidence), Recommendation: recommendation})
	}

	eeroForwardsByIP := eeroForwardBlocksByClientIP(afterBlocks)
	for _, change := range changes {
		beforeLines := change.BeforeLines
		afterLines := change.AfterLines
		allLines := append(append([]string{}, beforeLines...), afterLines...)

		if eeroMeshNodeRemoved(change) {
			add("medium", "availability", "Eero mesh node removed", "Confirm mesh coverage, backhaul redundancy, and client reachability before accepting the removed node.", beforeLines, []string{"Removed eero node block: " + change.Header})
		}
		if change.ChangeType == "removed" && change.Kind == "reservation" {
			for _, ip := range eeroReservationIPs(beforeLines) {
				for _, forward := range eeroForwardsByIP[ip] {
					evidence := uniquePreserve(append(append([]string{}, beforeLines...), forward.Lines...))
					details := []string{
						"Removed reservation IP: " + ip,
						"Retained eero forward: " + forward.Header,
					}
					add("high", "nat", "Eero reservation removed while port forward still targets it", "Restore the reservation, retarget the forward to a stable host, or remove the forward before relying on inbound reachability.", evidence, details)
				}
			}
		}
		if anyLine(allLines, isDefaultRouteLine) {
			add("high", "routing", "Default route changed", "Confirm upstream reachability, failover behavior, and expected next hop before committing.", combinedEvidence(change), beforeAfterDetails("Default route", beforeLines, afterLines, isDefaultRouteLine))
		}
		if change.ChangeType == "removed" && (change.Kind == "route" || anyLine(beforeLines, func(line string) bool { return isRouteLine(strings.ToLower(line)) })) {
			routeLines := matchingLines(beforeLines, func(line string) bool { return isRouteLine(strings.ToLower(line)) })
			if len(routeLines) == 0 {
				routeLines = beforeLines
			}
			add("medium", "routing", "Route removed", "Validate dependent prefixes and confirm no traffic still relies on the removed route.", beforeLines, prefixedDetails("Removed route", routeLines))
		}
		if change.Kind == "acl" || change.Kind == "firewall" {
			if aclOrFirewallBroadening(afterLines) {
				add("high", "acl_firewall", "ACL or firewall rule appears broadened", "Review source, destination, and service scope before allowing the change.", afterLines, aclBroadeningDetails(afterLines))
			}
			if exposesManagementPath(afterLines) {
				add("high", "management", "Management service may be exposed", "Restrict management access to known administration networks.", afterLines, prefixedDetails("Management exposure candidate", matchingLines(afterLines, exposesManagementPort)))
			}
		}
		if change.Kind == "vlan" && change.ChangeType == "removed" {
			add("medium", "switching", "VLAN removed", "Confirm no access ports, trunks, SVIs, or downstream devices still depend on this VLAN.", beforeLines, []string{"Removed VLAN block: " + change.Header})
		}
		if anyLine(allLines, interfaceVLANLine) {
			add("medium", "switching", "Interface VLAN assignment changed", "Validate access VLAN, native VLAN, and downstream endpoint expectations.", combinedEvidence(change), vlanDeltaDetails(beforeLines, afterLines, interfaceVLANLine))
		}
		if anyLine(allLines, trunkAllowedVLANLine) {
			add("medium", "switching", "Trunk allowed VLAN list changed", "Compare allowed VLANs against required downstream segments before activation.", combinedEvidence(change), vlanDeltaDetails(beforeLines, afterLines, trunkAllowedVLANLine))
		}
		if shutdownStateChanged(beforeLines, afterLines) {
			add("medium", "interface", "Interface shutdown state changed", "Confirm link state, maintenance window impact, and expected neighbor behavior.", combinedEvidence(change), []string{"Shutdown state changed from " + shutdownState(beforeLines) + " to " + shutdownState(afterLines) + "."})
		}
		if change.Kind == "nat" {
			add("medium", "nat", "NAT configuration changed", "Validate translated source/destination behavior and session impact.", combinedEvidence(change), beforeAfterDetails("NAT", beforeLines, afterLines, func(line string) bool { return isNATLine(strings.ToLower(line)) }))
		}
		if change.Kind == "vpn" {
			add("medium", "vpn", "VPN peer or tunnel configuration changed", "Validate peer reachability, proposals, selectors, and tunnel establishment.", combinedEvidence(change), beforeAfterDetails("VPN", beforeLines, afterLines, func(line string) bool {
				return isVPNLine(strings.ToLower(line)) || strings.Contains(strings.ToLower(line), "peer")
			}))
		}
		if change.Kind == "aaa" {
			add("high", "aaa_auth", "AAA or authentication changed", "Confirm break-glass access and test login paths before closing the change.", combinedEvidence(change), beforeAfterDetails("AAA/auth", beforeLines, afterLines, func(string) bool { return true }))
		}
		if change.Kind == "management" {
			add("medium", "management", "Management access changed", "Validate SSH/SNMP/HTTP access from approved networks only.", combinedEvidence(change), beforeAfterDetails("Management", beforeLines, afterLines, func(string) bool { return true }))
		}
		if change.Kind == "observability" && (change.ChangeType == "removed" || anyLine(afterLines, noLoggingLine)) {
			add("medium", "monitoring", "Logging or monitoring may be reduced", "Confirm telemetry, NTP, DNS, and alerting still meet operational requirements.", combinedEvidence(change), beforeAfterDetails("Monitoring", beforeLines, afterLines, func(string) bool { return true }))
		}
		appendSwitchingFindings(add, change)
	}
	for i := range findings {
		findings[i].ID = fmt.Sprintf("RISK-%03d", i+1)
	}
	return findings
}

func eeroMeshNodeRemoved(change BlockChange) bool {
	return change.ChangeType == "removed" &&
		change.Kind == "interface" &&
		strings.HasPrefix(change.ID, "interface:eero-") &&
		anyLine(change.BeforeLines, func(line string) bool { return strings.HasPrefix(line, "eero[") })
}

func eeroReservationIPs(lines []string) []string {
	ips := []string{}
	for _, line := range lines {
		if !strings.HasPrefix(line, "reservation[") || !strings.Contains(line, "].ip = ") {
			continue
		}
		_, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		if _, err := netip.ParseAddr(value); err != nil {
			continue
		}
		ips = append(ips, value)
	}
	return uniquePreserve(ips)
}

func eeroForwardBlocksByClientIP(blocks []configBlock) map[string][]configBlock {
	out := map[string][]configBlock{}
	for _, block := range blocks {
		if block.Kind != "nat" || !strings.HasPrefix(block.ID, "nat:/2.2/networks/") {
			continue
		}
		for _, ip := range eeroForwardClientIPs(block.Lines) {
			out[ip] = append(out[ip], block)
		}
	}
	return out
}

func eeroForwardClientIPs(lines []string) []string {
	ips := []string{}
	for _, line := range lines {
		if strings.HasPrefix(line, "nat port-forward ") {
			fields := strings.Fields(line)
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "client" {
					if _, err := netip.ParseAddr(fields[i+1]); err == nil {
						ips = append(ips, fields[i+1])
					}
				}
			}
			continue
		}
		if !strings.HasPrefix(line, "forward[") || !strings.Contains(line, "].ip = ") {
			continue
		}
		_, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		if _, err := netip.ParseAddr(value); err != nil {
			continue
		}
		ips = append(ips, value)
	}
	return uniquePreserve(ips)
}

func rollbackAnalysis(changes []BlockChange, risks []RiskFinding, parser string) RollbackAnalysis {
	if len(changes) == 0 {
		return RollbackAnalysis{Confidence: "clean", Summary: "No effective configuration changes were detected after normalization.", Snippets: []RollbackSnippet{}}
	}

	snippets := []RollbackSnippet{}
	hasAddition := false
	for _, change := range changes {
		switch change.ChangeType {
		case "changed", "removed":
			candidateCommands, note := rollbackCommands(change, parser)
			snippets = append(snippets, RollbackSnippet{
				ChangeID:             change.ID,
				Kind:                 change.Kind,
				Header:               change.Header,
				Lines:                change.BeforeLines,
				ExactReapply:         change.BeforeLines,
				CandidateCommands:    candidateCommands,
				ManualReviewRequired: rollbackNeedsManualReview(change, candidateCommands),
				Note:                 note,
			})
		case "added":
			hasAddition = true
			candidateCommands, note := rollbackCommands(change, parser)
			snippets = append(snippets, RollbackSnippet{
				ChangeID:             change.ID,
				Kind:                 change.Kind,
				Header:               change.Header,
				Lines:                change.AfterLines,
				CandidateCommands:    candidateCommands,
				ManualReviewRequired: true,
				Note:                 note,
			})
		}
	}

	confidence := "clean"
	summary := "Rollback is deterministic for changed or removed blocks using captured before-config snippets."
	for _, risk := range risks {
		if risk.Severity == "high" {
			confidence = "risky"
			summary = "Rollback includes high-risk areas such as routing, management, firewall, or authentication changes. Validate out-of-band access and staged recovery before applying."
			return RollbackAnalysis{Confidence: confidence, Summary: summary, Snippets: snippets}
		}
	}
	if hasAddition {
		confidence = "partial"
		summary = "Rollback is partial because added blocks require platform-specific negation or removal syntax."
	}
	return RollbackAnalysis{Confidence: confidence, Summary: summary, Snippets: snippets}
}

func interfaceNames(line string) []string {
	re := regexp.MustCompile(`(?i)\b(?:interface|int)\s+([A-Za-z][A-Za-z0-9./_-]+)`)
	matches := re.FindAllStringSubmatch(line, -1)
	names := []string{}
	for _, match := range matches {
		names = append(names, strings.ToLower(match[1]))
	}
	return names
}

func vlanIDs(line string) []string {
	re := regexp.MustCompile(`(?i)\b(?:vlan|allowed vlan|access vlan|native vlan)\s+([0-9][0-9, -]*)`)
	matches := re.FindAllStringSubmatch(line, -1)
	ids := []string{}
	for _, match := range matches {
		for _, part := range regexp.MustCompile(`[,\s]+`).Split(match[1], -1) {
			part = strings.Trim(part, "- ")
			ids = append(ids, expandVLANPart(part)...)
		}
	}
	return uniquePreserve(ids)
}

func expandVLANPart(part string) []string {
	if part == "" {
		return nil
	}
	if !strings.Contains(part, "-") {
		return []string{part}
	}
	bounds := strings.SplitN(part, "-", 2)
	if len(bounds) != 2 {
		return []string{part}
	}
	start, okStart := parseSmallInt(bounds[0])
	end, okEnd := parseSmallInt(bounds[1])
	if !okStart || !okEnd || start > end || end-start > 256 {
		return []string{part}
	}
	out := []string{}
	for i := start; i <= end; i++ {
		out = append(out, fmt.Sprint(i))
	}
	return out
}

func parseSmallInt(value string) (int, bool) {
	total := 0
	if value == "" {
		return 0, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
		total = total*10 + int(r-'0')
	}
	return total, true
}

func combinedEvidence(change BlockChange) []string {
	return uniquePreserve(append(append([]string{}, change.BeforeLines...), change.AfterLines...))
}

func firstRouteNextHopForPrefix(lines []string, prefix string) string {
	for _, line := range lines {
		if routePrefix(line) == prefix {
			return routeNextHop(line)
		}
	}
	return ""
}

func fortinetRoutePrefix(lines []string) string {
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "set dst ") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "set dst ")), `"`)
		}
	}
	return ""
}

func fortinetRouteNextHop(lines []string) string {
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "set gateway ") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "set gateway ")), `"`)
		}
	}
	return ""
}

func rollbackCommands(change BlockChange, parser string) ([]string, string) {
	switch parser {
	case "cisco-ios":
		return ciscoRollbackCommands(change)
	case "junos":
		return junosRollbackCommands(change)
	case "edgeos":
		return edgeOSRollbackCommands(change)
	case "panos":
		return panosRollbackCommands(change)
	case "unifi-json":
		if change.ChangeType == "added" {
			return nil, "UniFi controller changes are applied via the controller UI/API, not a CLI. This object did not exist before; remove it through the controller or restore the prior backup after operator review."
		}
		return change.BeforeLines, "UniFi controller changes are applied via the controller UI/API, not a CLI. These are the before-state field values for this object; re-apply them through the controller or restore the prior backup after operator review."
	case "eero-json":
		if change.ChangeType == "added" {
			return nil, "Eero network changes are applied through the eero app or cloud API, not a device CLI. This object did not exist before; remove it through eero or restore the prior snapshot after operator review."
		}
		return change.BeforeLines, "Eero network changes are applied through the eero app or cloud API, not a device CLI. These are the before-state field values for this object; re-apply them through eero or restore the prior snapshot after operator review."
	case "fortinet":
		return fortinetRollbackCommands(change)
	default:
		if change.ChangeType == "added" {
			return nil, "This block did not exist before. Remove or negate these added lines using the target platform syntax."
		}
		return nil, "Reapply these before-config lines to restore the prior state for this block."
	}
}

func ciscoRollbackCommands(change BlockChange) ([]string, string) {
	switch change.ChangeType {
	case "changed":
		return change.BeforeLines, "Cisco IOS-style candidate commands: paste these before-config lines in configuration mode for this block after operator review."
	case "removed":
		return change.BeforeLines, "Cisco IOS-style candidate commands: reapply these removed lines in configuration mode after operator review."
	case "added":
		commands := []string{}
		for _, line := range change.AfterLines {
			if canSafelyNegateCiscoLine(line) {
				commands = append(commands, "no "+line)
			}
		}
		if len(commands) == 0 {
			return nil, "Added block requires operator review; no safe generic Cisco IOS negation was generated."
		}
		return commands, "Cisco IOS-style candidate commands: remove the added statements with these negation commands after operator review."
	default:
		return nil, "No rollback command candidate generated."
	}
}

func canSafelyNegateCiscoLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "ip route ") ||
		strings.HasPrefix(lower, "ipv6 route ") ||
		strings.HasPrefix(lower, "access-list ") ||
		strings.HasPrefix(lower, "ip http") ||
		strings.HasPrefix(lower, "logging ") ||
		strings.HasPrefix(lower, "snmp-server ") ||
		strings.HasPrefix(lower, "ntp ") ||
		strings.HasPrefix(lower, "ip name-server")
}

func junosRollbackCommands(change BlockChange) ([]string, string) {
	switch change.ChangeType {
	case "changed", "removed":
		commands := []string{}
		for _, line := range change.BeforeLines {
			if strings.HasPrefix(strings.ToLower(line), "set ") {
				commands = append(commands, line)
			}
		}
		return commands, "Junos candidate commands: reapply these set statements or use Junos commit rollback if available, after operator review."
	case "added":
		commands := []string{}
		for _, line := range change.AfterLines {
			if strings.HasPrefix(strings.ToLower(line), "set ") {
				commands = append(commands, "delete "+strings.TrimPrefix(line, "set "))
			}
		}
		return commands, "Junos candidate commands: delete the added set statements or use Junos commit rollback if available, after operator review."
	default:
		return nil, "No rollback command candidate generated."
	}
}

func edgeOSRollbackCommands(change BlockChange) ([]string, string) {
	switch change.ChangeType {
	case "changed", "removed":
		commands := []string{}
		for _, line := range change.BeforeLines {
			if strings.HasPrefix(strings.ToLower(line), "set ") {
				commands = append(commands, line)
			}
		}
		return commands, "EdgeOS/VyOS candidate commands: reapply these set statements in configuration mode, or use commit-confirm/rollback if available, after operator review."
	case "added":
		commands := []string{}
		for _, line := range change.AfterLines {
			if strings.HasPrefix(strings.ToLower(line), "set ") {
				commands = append(commands, "delete "+strings.TrimPrefix(line, "set "))
			}
		}
		return commands, "EdgeOS/VyOS candidate commands: delete the added set statements, or use commit-confirm/rollback if available, after operator review."
	default:
		return nil, "No rollback command candidate generated."
	}
}

func panosRollbackCommands(change BlockChange) ([]string, string) {
	switch change.ChangeType {
	case "changed", "removed":
		commands := []string{}
		for _, line := range change.BeforeLines {
			if strings.HasPrefix(strings.ToLower(line), "set ") {
				commands = append(commands, line)
			}
		}
		return commands, "PAN-OS candidate commands: reapply these set statements then commit, or load a saved config snapshot, after operator review."
	case "added":
		commands := []string{}
		for _, line := range change.AfterLines {
			if strings.HasPrefix(strings.ToLower(line), "set ") {
				commands = append(commands, "delete "+strings.TrimPrefix(line, "set "))
			}
		}
		return commands, "PAN-OS candidate commands: delete the added set statements then commit, or load a saved config snapshot, after operator review."
	default:
		return nil, "No rollback command candidate generated."
	}
}

func fortinetRollbackCommands(change BlockChange) ([]string, string) {
	switch change.ChangeType {
	case "changed", "removed":
		return change.BeforeLines, "FortiOS candidate commands: reapply this captured config/edit block after operator review, or use configuration revision rollback if available."
	case "added":
		section, editID := fortinetSectionAndEdit(change.AfterLines)
		if section == "" || editID == "" {
			return nil, "Added FortiOS block requires operator review; no safe delete candidate was generated."
		}
		return []string{section, "delete " + editID, "end"}, "FortiOS candidate commands: delete the added edit block after operator review."
	default:
		return nil, "No rollback command candidate generated."
	}
}

func fortinetSectionAndEdit(lines []string) (section, editID string) {
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "config ") {
			section = line
		}
		if strings.HasPrefix(lower, "edit ") {
			editID = strings.TrimSpace(strings.TrimPrefix(line, "edit "))
		}
	}
	return section, editID
}

func rollbackNeedsManualReview(change BlockChange, candidateCommands []string) bool {
	if change.ChangeType == "added" {
		return true
	}
	if len(candidateCommands) == 0 {
		return true
	}
	switch change.Kind {
	case "route", "acl", "firewall", "nat", "vpn", "aaa", "management":
		return true
	default:
		return false
	}
}

func evidenceForLine(line string) []string {
	if line == "" {
		return nil
	}
	return []string{line}
}

func matchingLines(lines []string, fn func(string) bool) []string {
	matches := []string{}
	for _, line := range lines {
		if fn(line) {
			matches = append(matches, line)
		}
	}
	return matches
}

func prefixedDetails(prefix string, lines []string) []string {
	details := []string{}
	for _, line := range lines {
		details = append(details, prefix+": "+line)
	}
	return details
}

func beforeAfterDetails(label string, beforeLines, afterLines []string, fn func(string) bool) []string {
	before := matchingLines(beforeLines, fn)
	after := matchingLines(afterLines, fn)
	details := []string{}
	if len(before) > 0 {
		details = append(details, label+" before: "+strings.Join(before, " | "))
	}
	if len(after) > 0 {
		details = append(details, label+" after: "+strings.Join(after, " | "))
	}
	return details
}

func aclBroadeningDetails(lines []string) []string {
	details := []string{}
	for _, line := range matchingLines(lines, aclBroadeningLine) {
		lower := strings.ToLower(line)
		reason := "broad permit"
		if strings.Contains(lower, "any any") {
			reason = "permits from any source to any destination"
		} else if strings.Contains(lower, "0.0.0.0/0") || strings.Contains(lower, "0.0.0.0 255.255.255.255") {
			reason = "uses an all-networks CIDR or wildcard"
		}
		details = append(details, "Broadening candidate: "+reason+" in `"+line+"`")
	}
	if junosBroadeningLines(lines) {
		details = append(details, "Broadening candidate: Junos policy/filter allows traffic from 0.0.0.0/0.")
	}
	if fortinetBroadeningLines(lines) {
		details = append(details, "Broadening candidate: FortiOS policy accepts traffic with all source, destination, or service scope.")
	}
	if edgeOSBroadeningLines(lines) {
		details = append(details, "Broadening candidate: EdgeOS/VyOS firewall rule accepts traffic from any source (0.0.0.0/0).")
	}
	if panosBroadeningLines(lines) {
		details = append(details, "Broadening candidate: PAN-OS security rule allows traffic with any source, destination, application, or service scope.")
	}
	return details
}

func vlanDeltaDetails(beforeLines, afterLines []string, fn func(string) bool) []string {
	before := matchingLines(beforeLines, fn)
	after := matchingLines(afterLines, fn)
	details := []string{}
	if len(before) > 0 {
		details = append(details, "Before VLAN statement: "+strings.Join(before, " | "))
	}
	if len(after) > 0 {
		details = append(details, "After VLAN statement: "+strings.Join(after, " | "))
	}
	removed, added := stringSetDelta(vlanIDs(strings.Join(before, " ")), vlanIDs(strings.Join(after, " ")))
	if len(removed) > 0 {
		details = append(details, "VLANs removed from statement: "+strings.Join(removed, ", "))
	}
	if len(added) > 0 {
		details = append(details, "VLANs added to statement: "+strings.Join(added, ", "))
	}
	return details
}

func stringSetDelta(before, after []string) (removed []string, added []string) {
	beforeSet := map[string]bool{}
	afterSet := map[string]bool{}
	for _, value := range before {
		beforeSet[value] = true
	}
	for _, value := range after {
		afterSet[value] = true
	}
	for value := range beforeSet {
		if !afterSet[value] {
			removed = append(removed, value)
		}
	}
	for value := range afterSet {
		if !beforeSet[value] {
			added = append(added, value)
		}
	}
	sort.Strings(removed)
	sort.Strings(added)
	return removed, added
}

func anyLine(lines []string, fn func(string) bool) bool {
	for _, line := range lines {
		if fn(line) {
			return true
		}
	}
	return false
}

func isDefaultRouteLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "0.0.0.0 0.0.0.0") ||
		strings.Contains(lower, "0.0.0.0/0") ||
		strings.Contains(lower, "::/0") ||
		strings.Contains(lower, "default-route")
}

func aclBroadeningLine(line string) bool {
	lower := strings.ToLower(line)
	return (strings.HasPrefix(lower, "permit ") || strings.Contains(lower, " permit ")) &&
		(strings.Contains(lower, " any any") ||
			strings.Contains(lower, " 0.0.0.0/0") ||
			strings.Contains(lower, " 0.0.0.0 255.255.255.255"))
}

func aclOrFirewallBroadening(lines []string) bool {
	return anyLine(lines, aclBroadeningLine) || junosBroadeningLines(lines) || fortinetBroadeningLines(lines) || edgeOSBroadeningLines(lines) || panosBroadeningLines(lines)
}

// panosBroadeningLines detects a PAN-OS security rule that allows traffic with any source,
// destination, application, or service scope. PAN-OS rule attributes are separate
// `set ... rules <NAME> <attr> <value>` lines collapsed into one block.
func panosBroadeningLines(lines []string) bool {
	hasAny := false
	hasAllow := false
	for _, line := range lines {
		lower := " " + strings.ToLower(line)
		if strings.Contains(lower, " source any") || strings.Contains(lower, " destination any") || strings.Contains(lower, " application any") || strings.Contains(lower, " service any") {
			hasAny = true
		}
		if strings.Contains(lower, " action allow") {
			hasAllow = true
		}
	}
	return hasAny && hasAllow
}

// edgeOSBroadeningLines detects EdgeOS/VyOS firewall rules that accept traffic from any
// source. EdgeOS uses space-separated `source address 0.0.0.0/0` and `action accept`
// rather than the hyphenated Junos or Fortinet spellings.
func edgeOSBroadeningLines(lines []string) bool {
	hasAnySource := false
	hasAccept := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "source address 0.0.0.0/0") || strings.Contains(lower, "source address ::/0") {
			hasAnySource = true
		}
		if strings.Contains(lower, "action accept") {
			hasAccept = true
		}
	}
	return hasAnySource && hasAccept
}

func junosBroadeningLines(lines []string) bool {
	hasAnySource := false
	hasAccept := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, " source-address 0.0.0.0/0") || strings.Contains(lower, " source-address any") {
			hasAnySource = true
		}
		if strings.Contains(lower, " then accept") || strings.Contains(lower, " permit") {
			hasAccept = true
		}
	}
	return hasAnySource && hasAccept
}

func fortinetBroadeningLines(lines []string) bool {
	hasAllSource := false
	hasAllDestination := false
	hasAllService := false
	hasAccept := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "set srcaddr \"all\"") || strings.Contains(lower, "set srcaddr all") {
			hasAllSource = true
		}
		if strings.Contains(lower, "set dstaddr \"all\"") || strings.Contains(lower, "set dstaddr all") {
			hasAllDestination = true
		}
		if strings.Contains(lower, "set service \"all\"") || strings.Contains(lower, "set service all") {
			hasAllService = true
		}
		if strings.Contains(lower, "set action accept") {
			hasAccept = true
		}
	}
	return hasAccept && (hasAllSource || hasAllDestination || hasAllService)
}

func exposesManagementPort(line string) bool {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "permit") && !strings.Contains(lower, "allow") {
		return false
	}
	return strings.Contains(lower, " eq 22") ||
		strings.Contains(lower, " ssh") ||
		strings.Contains(lower, " eq 23") ||
		strings.Contains(lower, " telnet") ||
		strings.Contains(lower, " eq 80") ||
		strings.Contains(lower, " http") ||
		strings.Contains(lower, " eq 443") ||
		strings.Contains(lower, " https") ||
		strings.Contains(lower, " eq 161") ||
		strings.Contains(lower, " snmp")
}

func exposesManagementPath(lines []string) bool {
	if anyLine(lines, exposesManagementPort) {
		return true
	}
	if edgeOSExposesManagement(lines) {
		return true
	}
	if panosExposesManagement(lines) {
		return true
	}
	hasAnySource := false
	hasMgmtPort := false
	hasAccept := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, " source-address 0.0.0.0/0") || strings.Contains(lower, " source-address any") {
			hasAnySource = true
		}
		if strings.Contains(lower, " destination-port 22") ||
			strings.Contains(lower, " destination-port ssh") ||
			strings.Contains(lower, " destination-port 23") ||
			strings.Contains(lower, " destination-port telnet") ||
			strings.Contains(lower, " destination-port 80") ||
			strings.Contains(lower, " destination-port http") ||
			strings.Contains(lower, " destination-port 443") ||
			strings.Contains(lower, " destination-port https") ||
			strings.Contains(lower, " destination-port 161") ||
			strings.Contains(lower, " destination-port snmp") {
			hasMgmtPort = true
		}
		if strings.Contains(lower, " then accept") || strings.Contains(lower, " permit") {
			hasAccept = true
		}
	}
	return hasAnySource && hasMgmtPort && hasAccept
}

// edgeOSExposesManagement detects an EdgeOS/VyOS firewall rule that accepts traffic from
// any source to a management port (SSH/Telnet/HTTP/HTTPS/SNMP), using EdgeOS space-separated
// spelling (`source address 0.0.0.0/0`, `destination port 22`, `action accept`).
func edgeOSExposesManagement(lines []string) bool {
	hasAnySource := false
	hasMgmtPort := false
	hasAccept := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "source address 0.0.0.0/0") || strings.Contains(lower, "source address any") {
			hasAnySource = true
		}
		if strings.Contains(lower, "destination port 22") ||
			strings.Contains(lower, "destination port 23") ||
			strings.Contains(lower, "destination port 80") ||
			strings.Contains(lower, "destination port 443") ||
			strings.Contains(lower, "destination port 161") {
			hasMgmtPort = true
		}
		if strings.Contains(lower, "action accept") {
			hasAccept = true
		}
	}
	return hasAnySource && hasMgmtPort && hasAccept
}

// panosExposesManagement detects a PAN-OS security rule that allows a management application
// or service (ssh, https/web, snmp) from any source. PAN-OS identifies services by
// application name rather than port number.
func panosExposesManagement(lines []string) bool {
	hasAnySource := false
	hasMgmtApp := false
	hasAllow := false
	for _, line := range lines {
		lower := " " + strings.ToLower(line)
		if strings.Contains(lower, " source any") {
			hasAnySource = true
		}
		if strings.Contains(lower, " application ssh") ||
			strings.Contains(lower, " application snmp") ||
			strings.Contains(lower, " application web-browsing") ||
			strings.Contains(lower, " application panos-web-interface") ||
			strings.Contains(lower, " service service-ssh") ||
			strings.Contains(lower, " service service-https") {
			hasMgmtApp = true
		}
		if strings.Contains(lower, " action allow") {
			hasAllow = true
		}
	}
	return hasAnySource && hasMgmtApp && hasAllow
}

func panosRoutePrefix(lines []string) string {
	for _, line := range lines {
		if !strings.Contains(strings.ToLower(line), "static-route") {
			continue
		}
		if prefix := tokenAfter(strings.Fields(line), "destination"); prefix != "" {
			return prefix
		}
	}
	return ""
}

func panosRouteNextHop(lines []string) string {
	for _, line := range lines {
		if hop := tokenAfter(strings.Fields(line), "ip-address"); hop != "" {
			return hop
		}
	}
	return ""
}

func interfaceVLANLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "switchport access vlan") ||
		strings.Contains(lower, "switchport trunk native vlan") ||
		strings.HasPrefix(lower, "interface vlan") ||
		strings.Contains(lower, " family inet address ")
}

func trunkAllowedVLANLine(line string) bool {
	return strings.Contains(strings.ToLower(line), "trunk allowed vlan")
}

func shutdownLine(line string) bool {
	lower := strings.ToLower(line)
	return lower == "shutdown" || lower == "no shutdown" || strings.HasSuffix(lower, " shutdown") || strings.HasSuffix(lower, " no shutdown")
}

func shutdownStateChanged(beforeLines, afterLines []string) bool {
	beforeState := shutdownState(beforeLines)
	afterState := shutdownState(afterLines)
	return beforeState != "" && afterState != "" && beforeState != afterState
}

func shutdownState(lines []string) string {
	state := ""
	for _, line := range lines {
		lower := strings.ToLower(line)
		switch {
		case lower == "no shutdown" || strings.HasSuffix(lower, " no shutdown"):
			state = "no shutdown"
		case lower == "shutdown" || strings.HasSuffix(lower, " shutdown"):
			state = "shutdown"
		}
	}
	return state
}

func noLoggingLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "no logging") || strings.HasPrefix(lower, "no snmp-server") || strings.HasPrefix(lower, "no ntp")
}
