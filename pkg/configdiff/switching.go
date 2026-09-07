package configdiff

import "strings"

// switchingChanges extracts Layer 2 switching facts from the diffed blocks. Interface
// scoped constructs (switchport mode, trunk, native VLAN, per-port spanning-tree,
// EtherChannel, storm-control) are read from each changed interface block. Global
// constructs (spanning-tree mode/priority, VTP) are aggregated across all blocks because
// single-line global statements diff as a removed line plus an added line rather than a
// single changed block.
func switchingChanges(changes []BlockChange) []SwitchingChange {
	out := []SwitchingChange{}
	seen := map[string]bool{}
	add := func(sc SwitchingChange) {
		key := sc.Category + "|" + sc.Subject + "|" + sc.ChangeType + "|" + sc.Before + "|" + sc.After
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, sc)
	}

	for _, change := range changes {
		if !strings.HasPrefix(change.ID, "interface:") {
			continue
		}
		subject := strings.TrimPrefix(change.ID, "interface:")
		before := change.BeforeLines
		after := change.AfterLines

		if bMode, aMode := switchportMode(firstMatch(before, isSwitchportModeLine)), switchportMode(firstMatch(after, isSwitchportModeLine)); bMode != aMode && (bMode != "" || aMode != "") {
			add(SwitchingChange{Category: "switchport_mode", Subject: subject, ChangeType: change.ChangeType, Before: firstMatch(before, isSwitchportModeLine), After: firstMatch(after, isSwitchportModeLine), Evidence: nonEmptyLines(firstMatch(before, isSwitchportModeLine), firstMatch(after, isSwitchportModeLine))})
		}
		if b, a := firstMatch(before, isTrunkAllowedLine), firstMatch(after, isTrunkAllowedLine); b != a && (b != "" || a != "") {
			add(SwitchingChange{Category: "trunk", Subject: subject, ChangeType: change.ChangeType, Before: b, After: a, Evidence: nonEmptyLines(b, a)})
		}
		if b, a := firstMatch(before, isNativeVlanLine), firstMatch(after, isNativeVlanLine); b != a && (b != "" || a != "") {
			add(SwitchingChange{Category: "native_vlan", Subject: subject, ChangeType: change.ChangeType, Before: b, After: a, Evidence: nonEmptyLines(b, a)})
		}
		for _, feature := range []func(string) bool{isPortfastCommandLine, isBpduGuardCommandLine, isStpGuardCommandLine} {
			b, a := firstMatch(before, feature), firstMatch(after, feature)
			if b != a && (b != "" || a != "") {
				add(SwitchingChange{Category: "spanning_tree", Subject: subject, ChangeType: change.ChangeType, Before: b, After: a, Evidence: nonEmptyLines(b, a)})
			}
		}
		if b, a := firstMatch(before, isChannelGroupLine), firstMatch(after, isChannelGroupLine); b != a && (b != "" || a != "") {
			add(SwitchingChange{Category: "etherchannel", Subject: subject, ChangeType: change.ChangeType, Before: b, After: a, Evidence: nonEmptyLines(b, a)})
		}
		if b, a := firstMatch(before, isStormControlLine), firstMatch(after, isStormControlLine); b != a && (b != "" || a != "") {
			add(SwitchingChange{Category: "storm_control", Subject: subject, ChangeType: change.ChangeType, Before: b, After: a, Evidence: nonEmptyLines(b, a)})
		}
	}

	for _, sc := range globalSwitchingChanges(changes) {
		add(sc)
	}
	return out
}

// globalSwitchingChanges aggregates spanning-tree mode/priority and VTP statements across
// every block, bucketed by a normalized key, so a value change that diffs as remove+add is
// reported as a single changed fact.
func globalSwitchingChanges(changes []BlockChange) []SwitchingChange {
	type pair struct{ before, after string }
	buckets := map[string]*pair{}
	order := []string{}
	record := func(key, line string, isAfter bool) {
		p, ok := buckets[key]
		if !ok {
			p = &pair{}
			buckets[key] = p
			order = append(order, key)
		}
		if isAfter {
			p.after = line
		} else {
			p.before = line
		}
	}
	for _, change := range changes {
		for _, line := range change.BeforeLines {
			if key := globalSwitchingKey(line); key != "" {
				record(key, line, false)
			}
		}
		for _, line := range change.AfterLines {
			if key := globalSwitchingKey(line); key != "" {
				record(key, line, true)
			}
		}
	}

	out := []SwitchingChange{}
	for _, key := range order {
		p := buckets[key]
		if p.before == p.after {
			continue
		}
		category := "spanning_tree"
		if strings.HasPrefix(key, "vtp:") {
			category = "vtp"
		}
		changeType := "changed"
		switch {
		case p.before == "":
			changeType = "added"
		case p.after == "":
			changeType = "removed"
		}
		out = append(out, SwitchingChange{Category: category, Subject: "global", ChangeType: changeType, Before: p.before, After: p.after, Evidence: nonEmptyLines(p.before, p.after)})
	}
	return out
}

func globalSwitchingKey(line string) string {
	lower := strings.ToLower(line)
	fields := strings.Fields(lower)
	switch {
	case strings.HasPrefix(lower, "spanning-tree mode"):
		return "stp:mode"
	case strings.HasPrefix(lower, "spanning-tree vlan") && len(fields) >= 3 && (strings.Contains(lower, "priority") || strings.Contains(lower, "root")):
		return "stp:vlan:" + fields[2]
	case strings.HasPrefix(lower, "vtp mode"):
		return "vtp:mode"
	case strings.HasPrefix(lower, "vtp domain"):
		return "vtp:domain"
	case strings.HasPrefix(lower, "vtp version"):
		return "vtp:version"
	case strings.HasPrefix(lower, "vtp pruning"):
		return "vtp:pruning"
	}
	return ""
}

// appendSwitchingFindings adds switching risk findings for a single changed block using
// the shared add closure from riskFindings so dedup and ID numbering stay consistent.
func appendSwitchingFindings(add func(severity, category, title, recommendation string, evidence, details []string), change BlockChange) {
	before := change.BeforeLines
	after := change.AfterLines
	all := append(append([]string{}, before...), after...)

	if strings.HasPrefix(change.ID, "interface:") {
		subject := strings.TrimPrefix(change.ID, "interface:")
		if bMode, aMode := switchportMode(firstMatch(before, isSwitchportModeLine)), switchportMode(firstMatch(after, isSwitchportModeLine)); bMode != "" && aMode != "" && bMode != aMode {
			add("high", "switching", "Switchport mode changed", "Confirm the port role change is intended; trunking a former access port can create loops or expose VLANs.", combinedEvidence(change), []string{"Switchport mode changed from " + bMode + " to " + aMode + " on " + subject + "."})
		}
		if trunkCarriesAllVLANs(before, after) {
			add("medium", "switching", "Trunk carries all VLANs", "Prune the trunk to required VLANs; carrying all VLANs widens the L2 fault and security domain.", combinedEvidence(change), []string{"Trunk on " + subject + " now allows all VLANs."})
		}
		if b, a := firstMatch(before, isNativeVlanLine), firstMatch(after, isNativeVlanLine); b != a && (b != "" || a != "") {
			add("medium", "switching", "Trunk native VLAN changed", "Validate native VLAN consistency on both ends to avoid VLAN hopping and trunk mismatch.", combinedEvidence(change), beforeAfterDetails("Native VLAN", before, after, isNativeVlanLine))
		}
		if bpduProtectionReducedOrPortfastTrunk(before, after) {
			add("high", "spanning_tree", "BPDU protection reduced or PortFast on trunk", "Re-evaluate STP edge protection; removing BPDU guard or enabling PortFast on a trunk risks loops.", combinedEvidence(change), portfastBpduDetails(before, after))
		}
		if b, a := firstMatch(before, isChannelGroupLine), firstMatch(after, isChannelGroupLine); b != a && (b != "" || a != "") {
			add("medium", "etherchannel", "EtherChannel membership or mode changed", "Confirm channel-group mode matches the peer; mismatched LACP/PAgP modes can err-disable the bundle.", combinedEvidence(change), beforeAfterDetails("channel-group", before, after, isChannelGroupLine))
		}
		if b, a := firstMatch(before, isStormControlLine), firstMatch(after, isStormControlLine); b != a && (b != "" || a != "") {
			add("low", "switching", "Storm-control reduced or removed", "Confirm storm-control thresholds still protect against broadcast and multicast storms.", combinedEvidence(change), beforeAfterDetails("storm-control", before, after, isStormControlLine))
		}
	}

	if anyLine(all, isStpModeLine) {
		add("high", "spanning_tree", "Spanning-tree mode changed", "A spanning-tree mode change triggers a network-wide reconvergence; schedule it and validate the resulting topology.", combinedEvidence(change), beforeAfterDetails("STP mode", before, after, isStpModeLine))
	}
	if anyLine(all, isStpVlanPriorityLine) {
		add("high", "spanning_tree", "Spanning-tree root or priority changed", "Confirm the intended root bridge and priorities; a priority shift moves the L2 topology.", combinedEvidence(change), beforeAfterDetails("STP vlan", before, after, isStpVlanPriorityLine))
	}
	if anyLine(all, isVtpModeOrDomainLine) {
		add("high", "vtp", "VTP mode or domain changed", "VTP mode or domain changes can overwrite the VLAN database network-wide; validate revision numbers and prefer transparent mode.", combinedEvidence(change), beforeAfterDetails("VTP", before, after, isVtpModeOrDomainLine))
	}
}

func trunkCarriesAllVLANs(before, after []string) bool {
	b := strings.ToLower(firstMatch(before, isTrunkAllowedLine))
	a := strings.ToLower(firstMatch(after, isTrunkAllowedLine))
	return !isNegatedCommand(a) && strings.Contains(a, "allowed vlan all") && !strings.Contains(b, "allowed vlan all")
}

func bpduProtectionReducedOrPortfastTrunk(before, after []string) bool {
	bpduBefore := anyLine(before, isBpduGuardEnableLine)
	bpduAfter := anyLine(after, isBpduGuardEnableLine)
	if bpduBefore && !bpduAfter {
		return true
	}
	if anyLine(after, isPortfastLine) && switchportMode(firstMatch(after, isSwitchportModeLine)) == "trunk" {
		return true
	}
	return false
}

func portfastBpduDetails(before, after []string) []string {
	details := []string{}
	details = append(details, beforeAfterDetails("PortFast", before, after, isPortfastCommandLine)...)
	details = append(details, beforeAfterDetails("BPDU guard", before, after, isBpduGuardCommandLine)...)
	if len(details) == 0 {
		details = append(details, "Spanning-tree edge protection changed on this interface.")
	}
	return details
}

func switchportMode(line string) string {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "switchport mode ")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(lower[idx+len("switchport mode "):])
}

func firstMatch(lines []string, fn func(string) bool) string {
	for _, line := range lines {
		if fn(line) {
			return line
		}
	}
	return ""
}

func nonEmptyLines(values ...string) []string {
	out := []string{}
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func isSwitchportModeLine(line string) bool {
	return strings.HasPrefix(strings.ToLower(line), "switchport mode ")
}

func isTrunkAllowedLine(line string) bool {
	return strings.Contains(strings.ToLower(line), "switchport trunk allowed vlan")
}

func isNativeVlanLine(line string) bool {
	return strings.Contains(strings.ToLower(line), "switchport trunk native vlan")
}

func isChannelGroupLine(line string) bool {
	return strings.HasPrefix(strings.ToLower(line), "channel-group ")
}

func isStormControlLine(line string) bool {
	return strings.HasPrefix(strings.ToLower(line), "storm-control ")
}

func isPortfastLine(line string) bool {
	return !isNegatedCommand(line) && isPortfastCommandLine(line)
}

func isBpduGuardLine(line string) bool {
	return !isNegatedCommand(line) && isBpduGuardCommandLine(line)
}

func isBpduGuardEnableLine(line string) bool {
	return !isNegatedCommand(line) && strings.Contains(strings.ToLower(line), "spanning-tree bpduguard enable")
}

func isStpGuardLine(line string) bool {
	return !isNegatedCommand(line) && isStpGuardCommandLine(line)
}

func isPortfastCommandLine(line string) bool {
	return strings.Contains(strings.ToLower(line), "spanning-tree portfast")
}

func isBpduGuardCommandLine(line string) bool {
	return strings.Contains(strings.ToLower(line), "spanning-tree bpduguard")
}

func isStpGuardCommandLine(line string) bool {
	return strings.Contains(strings.ToLower(line), "spanning-tree guard ")
}

func isStpModeLine(line string) bool {
	return strings.HasPrefix(strings.ToLower(line), "spanning-tree mode")
}

func isStpVlanPriorityLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "spanning-tree vlan") && (strings.Contains(lower, "priority") || strings.Contains(lower, "root "))
}

func isVtpModeOrDomainLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "vtp mode") || strings.HasPrefix(lower, "vtp domain")
}
