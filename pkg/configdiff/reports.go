package configdiff

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func writeMarkdownReports(outDir string, analysis Analysis) error {
	reports, err := deterministicProvider{}.Render(analysis)
	if err != nil {
		return err
	}
	for name, content := range reports {
		if err := os.WriteFile(filepath.Join(outDir, name), []byte(content), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func renderChangeSummary(a Analysis) string {
	var b strings.Builder
	writeTitle(&b, "Change Summary")
	fmt.Fprintf(&b, "Parser: `%s`, detected vendor: `%s`, device type: `%s`, confidence: %.2f.\n\n", a.DetectedPlatform.Parser, a.DetectedPlatform.DetectedVendor, a.DetectedPlatform.DeviceType, a.DetectedPlatform.Confidence)
	fmt.Fprintf(&b, "Detected %d changed configuration block(s): %d added, %d removed, %d changed.\n\n", len(a.BlockChanges), countChanges(a.BlockChanges, "added"), countChanges(a.BlockChanges, "removed"), countChanges(a.BlockChanges, "changed"))
	if len(a.BlockChanges) == 0 {
		b.WriteString("No effective configuration changes were detected after normalization.\n")
		return b.String()
	}
	b.WriteString("## Changed Blocks\n\n")
	for _, change := range a.BlockChanges {
		fmt.Fprintf(&b, "- `%s` `%s` %s\n", change.ChangeType, change.Kind, change.Header)
	}
	return b.String()
}

func renderRiskAnalysis(a Analysis) string {
	var b strings.Builder
	writeTitle(&b, "Risk Analysis")
	if len(a.RiskFindings) == 0 {
		b.WriteString("No deterministic risk findings were detected. This does not prove the change is safe; it means no v1 heuristic matched.\n")
		return b.String()
	}
	for _, risk := range a.RiskFindings {
		fmt.Fprintf(&b, "## %s - %s\n\n", risk.ID, risk.Title)
		fmt.Fprintf(&b, "- Severity: `%s`\n", risk.Severity)
		fmt.Fprintf(&b, "- Category: `%s`\n", risk.Category)
		fmt.Fprintf(&b, "- Recommendation: %s\n", risk.Recommendation)
		if len(risk.Details) > 0 {
			b.WriteString("- Details:\n")
			for _, detail := range risk.Details {
				fmt.Fprintf(&b, "  - %s\n", detail)
			}
		}
		if len(risk.Evidence) > 0 {
			b.WriteString("- Evidence:\n")
			for _, line := range risk.Evidence {
				fmt.Fprintf(&b, "  - `%s`\n", line)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderTouchedObjects(a Analysis) string {
	var b strings.Builder
	writeTitle(&b, "Touched Objects")
	writeInterfaces(&b, a.TouchedInterfaces)
	writeVLANs(&b, a.TouchedVLANs)
	writeRoutes(&b, a.TouchedRoutes)
	writeRules(&b, a.TouchedACLFirewallRules)
	writeObjects(&b, "NAT Objects", a.TouchedNATObjects)
	writeObjects(&b, "VPN Objects", a.TouchedVPNObjects)
	writeSwitching(&b, a.SwitchingChanges)
	writeRoutingPeers(&b, a.TouchedRoutingPeers)
	writeSecurityBoundaries(&b, a.TouchedSecurityBoundaries)
	writeCategory(&b, "Management Plane", a.ManagementPlaneChanges)
	writeCategory(&b, "AAA And Authentication", a.AAAChanges)
	writeCategory(&b, "Logging, SNMP, NTP, DNS", a.LoggingSNMPNTPDNSChanges)
	return b.String()
}

func renderRollbackPlan(a Analysis) string {
	var b strings.Builder
	writeTitle(&b, "Rollback Plan")
	fmt.Fprintf(&b, "Rollback confidence: `%s`.\n\n%s\n\n", a.Rollback.Confidence, a.Rollback.Summary)
	if len(a.Rollback.Snippets) == 0 {
		b.WriteString("No rollback snippets are required.\n")
		return b.String()
	}
	for _, snippet := range a.Rollback.Snippets {
		fmt.Fprintf(&b, "## %s\n\n", snippet.ChangeID)
		fmt.Fprintf(&b, "Kind: `%s`\n\n%s\n\n", snippet.Kind, snippet.Note)
		b.WriteString("```text\n")
		for _, line := range snippet.Lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		b.WriteString("```\n\n")
		fmt.Fprintf(&b, "Manual review required: `%t`\n\n", snippet.ManualReviewRequired)
		if len(snippet.ExactReapply) > 0 {
			b.WriteString("Exact reapply snippet:\n\n")
			b.WriteString("```text\n")
			for _, line := range snippet.ExactReapply {
				b.WriteString(line)
				b.WriteByte('\n')
			}
			b.WriteString("```\n\n")
		}
		if len(snippet.CandidateCommands) > 0 {
			b.WriteString("Candidate commands, operator review required:\n\n")
			b.WriteString("```text\n")
			for _, command := range snippet.CandidateCommands {
				b.WriteString(command)
				b.WriteByte('\n')
			}
			b.WriteString("```\n\n")
		}
	}
	return b.String()
}

func renderValidationPlan(a Analysis) string {
	var b strings.Builder
	writeTitle(&b, "Validation Plan")
	b.WriteString("- Confirm management access through approved paths before and after the change.\n")
	b.WriteString("- Capture pre-change route table, interface status, neighbor status, and relevant session counters.\n")
	if len(a.TouchedRoutes) > 0 {
		b.WriteString("- Validate reachability for touched route prefixes and default route behavior.\n")
	}
	if len(a.TouchedInterfaces) > 0 {
		b.WriteString("- Check touched interfaces for link state, errors, VLAN membership, and expected neighbors.\n")
	}
	if len(a.TouchedACLFirewallRules) > 0 {
		b.WriteString("- Test allowed and denied traffic paths for changed ACL or firewall rules.\n")
	}
	if len(a.SwitchingChanges) > 0 {
		b.WriteString("- Verify spanning-tree topology and root bridge, EtherChannel bundling, VTP domain/mode, and trunk/native VLAN scope for touched switching constructs.\n")
	}
	if len(a.TouchedRoutingPeers) > 0 {
		b.WriteString("- Verify BGP and OSPF neighbor state, AS/area membership, and prefix exchange for touched routing peers.\n")
	}
	if len(a.TouchedSecurityBoundaries) > 0 {
		b.WriteString("- Validate security-zone and microsegmentation boundaries for newly permitted cross-zone flows, collapsed trust boundaries, and management access across segments.\n")
	}
	if len(a.TouchedNATObjects) > 0 {
		b.WriteString("- Validate NAT translations and session setup for affected flows.\n")
	}
	if len(a.TouchedVPNObjects) > 0 {
		b.WriteString("- Validate tunnel establishment, selectors, and encrypted traffic counters.\n")
	}
	if len(a.AAAChanges) > 0 {
		b.WriteString("- Test administrative login with primary and fallback authentication paths.\n")
	}
	if len(a.LoggingSNMPNTPDNSChanges) > 0 {
		b.WriteString("- Confirm logs, SNMP polling/traps, NTP sync, and DNS resolution remain healthy.\n")
	}
	b.WriteString("- Compare post-change facts against the pre-change baseline and rollback if critical checks fail.\n")
	return b.String()
}

func renderOperatorChecklist(a Analysis) string {
	var b strings.Builder
	writeTitle(&b, "Operator Checklist")
	b.WriteString("## Before Change\n\n")
	b.WriteString("- Confirm out-of-band or break-glass access is available.\n")
	b.WriteString("- Save the current running configuration and relevant operational state.\n")
	b.WriteString("- Capture route, interface, neighbor, session, VPN, NAT, ACL, logging, and authentication baselines as applicable.\n")
	b.WriteString("- Confirm the rollback owner and rollback decision point.\n\n")

	b.WriteString("## During Change\n\n")
	b.WriteString("- Apply the change in the documented order.\n")
	b.WriteString("- Watch for management session loss, route churn, interface state changes, and unexpected denies.\n")
	if highestSeverity(a.RiskFindings) == "high" {
		b.WriteString("- Pause after high-risk sections and validate reachability before continuing.\n")
	}
	b.WriteString("\n")

	b.WriteString("## After Change\n\n")
	b.WriteString("- Run the validation plan and compare results against the pre-change baseline.\n")
	b.WriteString("- Confirm monitoring, logging, NTP, DNS, and authentication remain healthy.\n")
	b.WriteString("- Confirm stakeholders agree that service behavior is acceptable.\n\n")

	b.WriteString("## Rollback Trigger\n\n")
	fmt.Fprintf(&b, "- Roll back if critical reachability, management access, authentication, or security policy validation fails. Current rollback confidence: `%s`.\n", a.Rollback.Confidence)
	return b.String()
}

func renderStakeholderBrief(a Analysis) string {
	var b strings.Builder
	writeTitle(&b, "Stakeholder Brief")
	fmt.Fprintf(&b, "This change touches %d configuration block(s) on a `%s` profile parsed by the offline `%s` parser.\n\n", len(a.BlockChanges), a.DetectedPlatform.DeviceType, a.DetectedPlatform.Parser)
	counts := severityCounts(a.RiskFindings)
	fmt.Fprintf(&b, "Risk finding counts: high `%d`, medium `%d`, low `%d`.\n\n", counts["high"], counts["medium"], counts["low"])
	highest := highestSeverity(a.RiskFindings)
	if highest == "" {
		b.WriteString("No deterministic high-risk conditions were found, but operator validation is still required.\n\n")
	} else {
		fmt.Fprintf(&b, "Highest deterministic risk severity: `%s`.\n\n", highest)
	}
	if len(a.RiskFindings) > 0 {
		b.WriteString("Top risks:\n\n")
		for _, risk := range topRisks(a.RiskFindings, 5) {
			fmt.Fprintf(&b, "- `%s` %s: %s\n", risk.Severity, risk.Category, risk.Title)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Rollback confidence is `%s`. The rollback plan includes captured snippets from the before config where available.\n\n", a.Rollback.Confidence)
	b.WriteString("Primary review focus: changed reachability, management access, authentication, monitoring, and security policy scope.\n")
	return b.String()
}

func writeTitle(b *strings.Builder, title string) {
	fmt.Fprintf(b, "# %s\n\n", title)
}

func writeInterfaces(b *strings.Builder, items []TouchedInterface) {
	b.WriteString("## Interfaces\n\n")
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	for _, item := range items {
		fmt.Fprintf(b, "- `%s` %s\n", item.Name, item.ChangeType)
	}
	b.WriteString("\n")
}

func writeVLANs(b *strings.Builder, items []TouchedVLAN) {
	b.WriteString("## VLANs\n\n")
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	b.WriteString("| VLAN | Change | Evidence |\n")
	b.WriteString("| --- | --- | --- |\n")
	for _, item := range items {
		fmt.Fprintf(b, "| `%s` | `%s` | %s |\n", item.ID, item.ChangeType, inlineEvidence(item.Evidence))
	}
	b.WriteString("\n")
}

func writeRoutes(b *strings.Builder, items []TouchedRoute) {
	b.WriteString("## Routes\n\n")
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	b.WriteString("| Prefix | Change | Before next hop | After next hop |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, item := range items {
		fmt.Fprintf(b, "| `%s` | `%s` | `%s` | `%s` |\n", item.Prefix, item.ChangeType, item.BeforeNextHop, item.AfterNextHop)
	}
	b.WriteString("\n")
}

func writeRules(b *strings.Builder, items []TouchedRule) {
	b.WriteString("## ACL And Firewall Rules\n\n")
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	b.WriteString("| Rule | Change | Action | Protocol | Source | Destination | Service | Source Zone | Dest Zone | Policy |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, item := range items {
		fmt.Fprintf(b, "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %s | %s | %s |\n",
			item.Name, item.ChangeType, item.Action, item.Protocol, item.Source, item.Destination, item.Service,
			switchingCell(item.SourceZone), switchingCell(item.DestinationZone), switchingCell(item.Policy))
	}
	b.WriteString("\n")
}

func writeObjects(b *strings.Builder, title string, items []TouchedObject) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	for _, item := range items {
		fmt.Fprintf(b, "- `%s` %s\n", item.Name, item.ChangeType)
	}
	b.WriteString("\n")
}

func writeSwitching(b *strings.Builder, items []SwitchingChange) {
	b.WriteString("## Switching / L2\n\n")
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	b.WriteString("| Category | Subject | Change | Before | After |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, item := range items {
		fmt.Fprintf(b, "| `%s` | `%s` | `%s` | %s | %s |\n", item.Category, item.Subject, item.ChangeType, switchingCell(item.Before), switchingCell(item.After))
	}
	b.WriteString("\n")
}

func writeRoutingPeers(b *strings.Builder, items []TouchedRoutingPeer) {
	b.WriteString("## Routing Peers\n\n")
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	b.WriteString("| Protocol | Peer | Change | Local AS | Remote AS | Area | Before | After |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, item := range items {
		fmt.Fprintf(b, "| `%s` | `%s` | `%s` | %s | %s | %s | %s | %s |\n",
			item.Protocol,
			item.Peer,
			item.ChangeType,
			switchingCell(item.LocalAS),
			switchingCell(item.RemoteAS),
			switchingCell(item.Area),
			switchingCell(item.Before),
			switchingCell(item.After),
		)
	}
	b.WriteString("\n")
}

func writeSecurityBoundaries(b *strings.Builder, items []TouchedSecurityBoundary) {
	b.WriteString("## Security Boundaries\n\n")
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	b.WriteString("| Kind | Change | Source Zone | Dest Zone | Zone | Member | Action | Service | Policy | Before | After |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, item := range items {
		fmt.Fprintf(b, "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			item.Kind,
			item.ChangeType,
			switchingCell(item.SourceZone),
			switchingCell(item.DestinationZone),
			switchingCell(item.Zone),
			switchingCell(item.Member),
			switchingCell(item.Action),
			switchingCell(item.Service),
			switchingCell(item.Policy),
			switchingCell(item.Before),
			switchingCell(item.After),
		)
	}
	b.WriteString("\n")
}

func switchingCell(value string) string {
	if value == "" {
		return ""
	}
	return "`" + strings.ReplaceAll(value, "|", "\\|") + "`"
}

func writeCategory(b *strings.Builder, title string, items []CategoryChange) {
	fmt.Fprintf(b, "## %s\n\n", title)
	if len(items) == 0 {
		b.WriteString("None detected.\n\n")
		return
	}
	for _, item := range items {
		fmt.Fprintf(b, "- `%s` %s\n", item.Category, item.ChangeType)
	}
	b.WriteString("\n")
}

func countChanges(changes []BlockChange, changeType string) int {
	total := 0
	for _, change := range changes {
		if change.ChangeType == changeType {
			total++
		}
	}
	return total
}

func highestSeverity(risks []RiskFinding) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	highest := ""
	for _, risk := range risks {
		if rank[risk.Severity] > rank[highest] {
			highest = risk.Severity
		}
	}
	return highest
}

func severityCounts(risks []RiskFinding) map[string]int {
	counts := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, risk := range risks {
		counts[risk.Severity]++
	}
	return counts
}

func topRisks(risks []RiskFinding, limit int) []RiskFinding {
	if len(risks) <= limit {
		return risks
	}
	return risks[:limit]
}

func inlineEvidence(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		values = append(values, "`"+strings.ReplaceAll(line, "|", "\\|")+"`")
	}
	return strings.Join(values, "<br>")
}
