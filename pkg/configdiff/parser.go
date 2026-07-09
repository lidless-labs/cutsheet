package configdiff

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type Parser interface {
	Parse(text string, requestedVendor string) parsedConfig
}

type genericParser struct{}
type ciscoIOSParser struct{}
type edgeSwitchParser struct{}
type edgeOSParser struct{}
type panosParser struct{}
type junosParser struct{}
type fortinetParser struct{}
type eeroJSONParser struct{}

var _ Parser = genericParser{}
var _ Parser = ciscoIOSParser{}
var _ Parser = edgeSwitchParser{}
var _ Parser = edgeOSParser{}
var _ Parser = panosParser{}
var _ Parser = junosParser{}
var _ Parser = fortinetParser{}
var _ Parser = eeroJSONParser{}

func selectParser(vendor string, text string) (Parser, error) {
	switch strings.ToLower(vendor) {
	case "generic":
		return genericParser{}, nil
	case "cisco-ios", "ios", "ios-xe", "cisco":
		return ciscoIOSParser{}, nil
	case "ubiquiti", "edgeswitch", "ubiquiti-edgeswitch", "ubiquitios", "edgeswitch-cli":
		return edgeSwitchParser{}, nil
	case "edgeos", "vyos", "ubiquiti-gateway", "usg", "udm", "edgerouter":
		return edgeOSParser{}, nil
	case "paloalto", "palo-alto", "panos", "pan-os", "pan":
		return panosParser{}, nil
	case "unifi", "unifi-json", "unifi-controller":
		return unifiJSONParser{}, nil
	case "eero", "eero-json":
		return eeroJSONParser{}, nil
	case "juniper", "junos":
		return junosParser{}, nil
	case "fortinet", "fortigate", "fortios":
		return fortinetParser{}, nil
	case "auto":
		if looksUnifiJSON(text) {
			return unifiJSONParser{}, nil
		}
		if looksEeroJSON(text) {
			return eeroJSONParser{}, nil
		}
		if looksFortinet(text) {
			return fortinetParser{}, nil
		}
		if looksPANOS(text) {
			return panosParser{}, nil
		}
		if looksEdgeSwitch(text) {
			return edgeSwitchParser{}, nil
		}
		if looksCiscoIOS(text) {
			return ciscoIOSParser{}, nil
		}
		if looksEdgeOS(text) {
			return edgeOSParser{}, nil
		}
		if looksJunos(text) {
			return junosParser{}, nil
		}
		return genericParser{}, nil
	default:
		return nil, fmt.Errorf("unsupported vendor mode %q; supported modes are auto, generic, cisco-ios, ios, ios-xe, cisco, ubiquiti, edgeswitch, ubiquiti-edgeswitch, ubiquitios, edgeswitch-cli, edgeos, vyos, ubiquiti-gateway, usg, udm, edgerouter, paloalto, palo-alto, panos, pan-os, pan, unifi, unifi-json, unifi-controller, eero, eero-json, juniper, junos, fortinet, fortigate, and fortios", vendor)
	}
}

func (genericParser) Parse(text string, requestedVendor string) parsedConfig {
	return parseGeneric(text, requestedVendor)
}

func (ciscoIOSParser) Parse(text string, requestedVendor string) parsedConfig {
	parsed := parseGeneric(text, requestedVendor)
	parsed.Detection.Parser = "cisco-ios"
	parsed.Detection.DetectedVendor = "cisco"
	if strings.EqualFold(requestedVendor, "auto") {
		parsed.Detection.Confidence = 0.78
	} else {
		parsed.Detection.Confidence = 0.88
	}
	parsed.Detection.Signals = appendSignal(parsed.Detection.Signals, "cisco ios-style syntax")
	return parsed
}

func (edgeSwitchParser) Parse(text string, requestedVendor string) parsedConfig {
	parsed := parseGeneric(text, requestedVendor)
	parsed.Detection.Parser = "cisco-ios"
	parsed.Detection.DetectedVendor = "ubiquiti"
	if strings.EqualFold(requestedVendor, "auto") {
		parsed.Detection.Confidence = 0.72
	} else {
		parsed.Detection.Confidence = 0.86
	}
	parsed.Detection.Signals = appendSignal(parsed.Detection.Signals, "ubiquiti edgeswitch ios-style syntax")
	return parsed
}

func (junosParser) Parse(text string, requestedVendor string) parsedConfig {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	blocks := []configBlock{}
	for _, raw := range lines {
		line := normalizeLine(raw)
		if line == "" {
			continue
		}
		kind, id, header := classifyJunosSetLine(line)
		blocks = append(blocks, configBlock{ID: id, Kind: kind, Header: header, Lines: []string{line}})
	}
	blocks = mergeRelatedBlocks(blocks)
	detection := detectPlatform(blocks, requestedVendor)
	detection.Parser = "junos"
	detection.DetectedVendor = "juniper"
	detection.Confidence = 0.80
	if !strings.EqualFold(requestedVendor, "auto") {
		detection.Confidence = 0.90
	}
	detection.Signals = appendSignal(detection.Signals, "junos set-style syntax")
	return parsedConfig{Detection: detection, Blocks: blocks}
}

func (edgeOSParser) Parse(text string, requestedVendor string) parsedConfig {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	blocks := []configBlock{}
	for _, raw := range lines {
		line := normalizeLine(raw)
		if line == "" {
			continue
		}
		kind, id, header := classifyEdgeOSSetLine(line)
		blocks = append(blocks, configBlock{ID: id, Kind: kind, Header: header, Lines: []string{line}})
	}
	blocks = mergeRelatedBlocks(blocks)
	detection := detectPlatform(blocks, requestedVendor)
	detection.Parser = "edgeos"
	detection.DetectedVendor = "ubiquiti"
	detection.Confidence = 0.80
	if !strings.EqualFold(requestedVendor, "auto") {
		detection.Confidence = 0.90
	}
	detection.Signals = appendSignal(detection.Signals, "edgeos/vyos set-style syntax")
	return parsedConfig{Detection: detection, Blocks: blocks}
}

// classifyEdgeOSSetLine maps an EdgeOS/VyOS set-style statement onto an existing block
// kind. It mirrors classifyJunosSetLine: block IDs are verb-independent so a set in the
// before file and a delete/changed line in the after file land in the same block.
func classifyEdgeOSSetLine(line string) (kind, id, header string) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "generic", "line:" + stableID(line), line
	}
	verb := strings.ToLower(fields[0])
	if verb != "set" && verb != "delete" {
		if k, i, h, _ := classifyLine(line); k != "" {
			return k, i, h
		}
		return "generic", "line:" + stableID(line), line
	}
	rest := fields[1:]
	path := func(n int) string { return strings.Join(rest[:min(n, len(rest))], " ") }

	switch strings.ToLower(rest[0]) {
	case "interfaces":
		if tag := tokenAfter(rest, "vif"); isNumericToken(tag) {
			return "vlan", "vlan:" + tag, verb + " " + path(len(rest))
		}
		if tag := tokenAfter(rest, "vlan"); isNumericToken(tag) {
			return "vlan", "vlan:" + tag, verb + " " + path(len(rest))
		}
		if len(rest) >= 3 {
			name := strings.ToLower(rest[2])
			return "interface", "interface:" + name, verb + " interfaces " + strings.Join(rest[1:3], " ")
		}
		return "interface", "interface:" + stableID(path(len(rest))), verb + " " + path(len(rest))
	case "protocols":
		if len(rest) >= 4 && strings.EqualFold(rest[1], "static") && (strings.EqualFold(rest[2], "route") || strings.EqualFold(rest[2], "route6") || strings.EqualFold(rest[2], "interface-route")) {
			return "route", "route:" + rest[3], verb + " protocols static " + rest[2] + " " + rest[3]
		}
		if len(rest) >= 2 && (strings.EqualFold(rest[1], "ospf") || strings.EqualFold(rest[1], "bgp") || strings.EqualFold(rest[1], "rip")) {
			return "routing", "routing:" + strings.ToLower(rest[1]), verb + " protocols " + rest[1]
		}
	case "firewall":
		if len(rest) >= 3 && strings.EqualFold(rest[1], "name") {
			return "acl", "acl:" + strings.ToLower(rest[2]), verb + " firewall name " + rest[2]
		}
		if len(rest) >= 3 && strings.EqualFold(rest[1], "ipv6-name") {
			return "acl", "acl:" + strings.ToLower(rest[2]), verb + " firewall ipv6-name " + rest[2]
		}
		if len(rest) >= 3 && strings.EqualFold(rest[1], "group") {
			return "firewall", "firewall:group-" + strings.ToLower(rest[2]), verb + " firewall group " + rest[2]
		}
		return "firewall", "firewall:global-" + stableID(path(min(len(rest), 3))), verb + " firewall " + path(min(len(rest), 2))
	case "service":
		if len(rest) >= 2 {
			switch strings.ToLower(rest[1]) {
			case "nat":
				blockID := "nat:" + stableID(path(min(len(rest), 4)))
				if tag := tokenAfter(rest, "rule"); tag != "" {
					blockID = "nat:rule-" + tag
				}
				return "nat", blockID, verb + " service nat"
			case "ssh":
				return "management", "management:ssh", verb + " service ssh"
			case "gui", "https":
				return "management", "management:gui", verb + " service gui"
			case "telnet":
				return "management", "management:telnet", verb + " service telnet"
			case "snmp":
				return "observability", "observability:snmp", verb + " service snmp"
			case "dhcp-server", "dhcpv6-server":
				return "observability", "observability:dhcp-" + stableID(path(min(len(rest), 4))), verb + " service " + rest[1]
			}
		}
	case "vpn":
		if len(rest) >= 2 {
			return "vpn", "vpn:" + strings.ToLower(rest[1]) + "-" + stableID(path(min(len(rest), 5))), verb + " vpn " + rest[1]
		}
	case "system":
		if len(rest) >= 3 && strings.EqualFold(rest[1], "login") {
			if strings.EqualFold(rest[2], "user") && len(rest) >= 4 {
				return "aaa", "aaa:user-" + strings.ToLower(rest[3]), verb + " system login user " + rest[3]
			}
			return "aaa", "aaa:" + strings.ToLower(rest[2]) + "-" + stableID(path(min(len(rest), 5))), verb + " system login " + rest[2]
		}
		if len(rest) >= 2 {
			switch strings.ToLower(rest[1]) {
			case "host-name":
				return "management", "management:host-name", verb + " system host-name"
			case "name-server", "syslog", "ntp":
				return "observability", "observability:" + strings.ToLower(rest[1]) + "-" + stableID(path(min(len(rest), 5))), verb + " system " + rest[1]
			}
		}
	}

	if k, i, h, _ := classifyLine(line); k != "" {
		return k, i, h
	}
	return "generic", "line:" + stableID(line), line
}

func tokenAfter(fields []string, key string) string {
	for i := 0; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], key) {
			return fields[i+1]
		}
	}
	return ""
}

func isNumericToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (panosParser) Parse(text string, requestedVendor string) parsedConfig {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	blocks := []configBlock{}
	for _, raw := range lines {
		line := normalizeLine(raw)
		if line == "" {
			continue
		}
		kind, id, header := classifyPANOSSetLine(line)
		blocks = append(blocks, configBlock{ID: id, Kind: kind, Header: header, Lines: []string{line}})
	}
	blocks = mergeRelatedBlocks(blocks)
	detection := detectPlatform(blocks, requestedVendor)
	detection.Parser = "panos"
	detection.DetectedVendor = "paloalto"
	detection.DeviceType = "firewall"
	detection.Confidence = 0.82
	if !strings.EqualFold(requestedVendor, "auto") {
		detection.Confidence = 0.90
	}
	detection.Signals = appendSignal(detection.Signals, "pan-os set-style syntax")
	return parsedConfig{Detection: detection, Blocks: blocks}
}

// classifyPANOSSetLine maps a PAN-OS set-style statement onto an existing block kind. Block
// IDs key on the rule/object name so all attribute lines for one rule collapse into a single
// block where the broadening and management-exposure detectors can see them together.
func classifyPANOSSetLine(line string) (kind, id, header string) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "generic", "line:" + stableID(line), line
	}
	verb := strings.ToLower(fields[0])
	if verb != "set" && verb != "delete" {
		if k, i, h, _ := classifyLine(line); k != "" {
			return k, i, h
		}
		return "generic", "line:" + stableID(line), line
	}
	rest := fields[1:]
	lower := make([]string, len(rest))
	for i, f := range rest {
		lower[i] = strings.ToLower(f)
	}
	path := func(n int) string { return strings.Join(rest[:min(n, len(rest))], " ") }

	switch {
	case len(rest) >= 4 && lower[0] == "rulebase" && lower[1] == "security" && lower[2] == "rules":
		return "firewall", "firewall:" + strings.ToLower(rest[3]), verb + " rulebase security rules " + rest[3]
	case len(rest) >= 4 && lower[0] == "rulebase" && lower[1] == "nat" && lower[2] == "rules":
		return "nat", "nat:" + strings.ToLower(rest[3]), verb + " rulebase nat rules " + rest[3]
	case len(rest) >= 2 && lower[0] == "address":
		return "firewall", "firewall:addr-" + strings.ToLower(rest[1]), verb + " address " + rest[1]
	case len(rest) >= 2 && lower[0] == "address-group":
		return "firewall", "firewall:addrgrp-" + strings.ToLower(rest[1]), verb + " address-group " + rest[1]
	case len(rest) >= 2 && lower[0] == "service":
		return "firewall", "firewall:svc-" + strings.ToLower(rest[1]), verb + " service " + rest[1]
	case len(rest) >= 2 && lower[0] == "service-group":
		return "firewall", "firewall:svcgrp-" + strings.ToLower(rest[1]), verb + " service-group " + rest[1]
	case len(rest) >= 2 && lower[0] == "zone":
		return "interface", "interface:zone-" + strings.ToLower(rest[1]), verb + " zone " + rest[1]
	case len(rest) >= 4 && lower[0] == "network" && lower[1] == "interface":
		return "interface", "interface:" + strings.ToLower(rest[3]), verb + " network interface " + rest[2] + " " + rest[3]
	case len(rest) >= 3 && lower[0] == "network" && lower[1] == "virtual-router":
		if name := tokenAfter(rest, "static-route"); name != "" {
			return "route", "route:" + strings.ToLower(name), verb + " network virtual-router " + rest[2] + " static-route " + name
		}
		return "routing", "routing:vr-" + strings.ToLower(rest[2]), verb + " network virtual-router " + rest[2]
	case len(rest) >= 2 && lower[0] == "deviceconfig":
		joined := strings.Join(lower, " ")
		if strings.Contains(joined, "snmp") || strings.Contains(joined, "syslog") || strings.Contains(joined, "ntp") || strings.Contains(joined, "dns") {
			return "observability", "observability:" + stableID(path(4)), verb + " deviceconfig " + strings.Join(rest[1:min(3, len(rest))], " ")
		}
		return "management", "management:" + stableID(path(4)), verb + " deviceconfig " + strings.Join(rest[1:min(3, len(rest))], " ")
	case len(rest) >= 3 && lower[0] == "mgt-config" && lower[1] == "users":
		return "aaa", "aaa:user-" + strings.ToLower(rest[2]), verb + " mgt-config users " + rest[2]
	}

	if k, i, h, _ := classifyLine(line); k != "" {
		return k, i, h
	}
	return "generic", "line:" + stableID(line), line
}

func looksPANOS(text string) bool {
	score := 0
	hasStrong := false
	for _, raw := range strings.Split(strings.ToLower(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "set rulebase security rules"),
			strings.HasPrefix(line, "set rulebase nat"),
			strings.HasPrefix(line, "set deviceconfig"),
			strings.HasPrefix(line, "set mgt-config"),
			strings.HasPrefix(line, "set network virtual-router"),
			strings.HasPrefix(line, "set zone "):
			score += 2
			hasStrong = true
		case strings.HasPrefix(line, "set address "),
			strings.HasPrefix(line, "set address-group "),
			strings.HasPrefix(line, "set service "),
			strings.HasPrefix(line, "set service-group "):
			score++
		}
	}
	// Require a PAN-OS-exclusive structural head so weak tokens shared with EdgeOS/Junos
	// (notably "set service ") cannot classify a config as PAN-OS on their own.
	return hasStrong && score >= 3
}

func looksEdgeOS(text string) bool {
	score := 0
	for _, raw := range strings.Split(strings.ToLower(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "set interfaces ethernet eth"),
			strings.HasPrefix(line, "delete interfaces ethernet eth"),
			strings.HasPrefix(line, "set interfaces switch sw"),
			strings.HasPrefix(line, "set service gui"),
			strings.HasPrefix(line, "set service ssh"),
			strings.HasPrefix(line, "set service nat"),
			strings.HasPrefix(line, "set service dhcp-server"),
			strings.HasPrefix(line, "set protocols static route"),
			strings.HasPrefix(line, "set firewall name"):
			score++
		}
	}
	return score >= 3
}

func (fortinetParser) Parse(text string, requestedVendor string) parsedConfig {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	blocks := []configBlock{}
	section := ""
	var current *configBlock

	flush := func() {
		if current == nil {
			return
		}
		current.Lines = uniquePreserve(current.Lines)
		blocks = append(blocks, *current)
		current = nil
	}

	for _, raw := range lines {
		line := normalizeLine(raw)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "config ") {
			flush()
			section = line
			continue
		}
		if strings.HasPrefix(lower, "edit ") {
			flush()
			name := strings.TrimSpace(strings.TrimPrefix(line, "edit "))
			kind := fortinetSectionKind(section)
			id := kind + ":" + stableID(section+" "+name)
			current = &configBlock{ID: id, Kind: kind, Header: section + " " + line, Lines: []string{section, line}}
			continue
		}
		if lower == "next" {
			flush()
			continue
		}
		if lower == "end" {
			flush()
			section = ""
			continue
		}
		if current != nil {
			current.Lines = append(current.Lines, line)
			continue
		}
		kind, id, header, _ := classifyLine(line)
		if kind == "" {
			kind = fortinetSectionKind(section)
			id = kind + ":" + stableID(section+" "+line)
			header = line
		}
		blocks = append(blocks, configBlock{ID: id, Kind: kind, Header: header, Lines: []string{line}})
	}
	flush()

	blocks = mergeRelatedBlocks(blocks)
	detection := detectPlatform(blocks, requestedVendor)
	detection.Parser = "fortinet"
	detection.DetectedVendor = "fortinet"
	detection.DeviceType = "firewall"
	detection.Confidence = 0.82
	if !strings.EqualFold(requestedVendor, "auto") {
		detection.Confidence = 0.90
	}
	detection.Signals = appendSignal(detection.Signals, "fortios config/edit syntax")
	return parsedConfig{Detection: detection, Blocks: blocks}
}

func parseGeneric(text string, requestedVendor string) parsedConfig {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	blocks := make([]configBlock, 0)
	var current *configBlock

	flush := func() {
		if current == nil {
			return
		}
		current.Lines = uniquePreserve(current.Lines)
		blocks = append(blocks, *current)
		current = nil
	}

	for _, raw := range lines {
		leading := len(raw) - len(strings.TrimLeft(raw, " \t"))
		normalized := normalizeLine(raw)
		if normalized == "" {
			continue
		}
		if leading > 0 && current != nil {
			current.Lines = append(current.Lines, normalized)
			continue
		}

		kind, id, header, multiline := classifyLine(normalized)
		if multiline {
			flush()
			current = &configBlock{ID: id, Kind: kind, Header: header, Lines: []string{normalized}}
			continue
		}
		if kind != "" {
			flush()
			blocks = append(blocks, configBlock{ID: id, Kind: kind, Header: header, Lines: []string{normalized}})
			continue
		}

		flush()
		id = "line:" + stableID(normalized)
		blocks = append(blocks, configBlock{ID: id, Kind: "generic", Header: normalized, Lines: []string{normalized}})
	}
	flush()

	return parsedConfig{
		Detection: detectPlatform(blocks, requestedVendor),
		Blocks:    mergeRelatedBlocks(blocks),
	}
}

func looksCiscoIOS(text string) bool {
	score := 0
	for _, raw := range strings.Split(strings.ToLower(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "interface gigabitethernet"),
			strings.HasPrefix(line, "interface tengigabitethernet"),
			strings.HasPrefix(line, "interface fastethernet"),
			strings.HasPrefix(line, "interface vlan"),
			strings.HasPrefix(line, "interface port-channel"):
			score += 2
		case strings.HasPrefix(line, "switchport "),
			strings.HasPrefix(line, "ip access-list "),
			strings.HasPrefix(line, "access-list "),
			strings.HasPrefix(line, "ip route "),
			strings.HasPrefix(line, "aaa "),
			strings.HasPrefix(line, "line vty"),
			strings.HasPrefix(line, "crypto map "):
			score++
		}
	}
	return score >= 3
}

func looksEdgeSwitch(text string) bool {
	score := 0
	for _, raw := range strings.Split(strings.ToLower(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "vlan database"),
			strings.HasPrefix(line, "serviceport "),
			strings.HasPrefix(line, "network mgmt_vlan"),
			strings.HasPrefix(line, "network protocol"),
			strings.HasPrefix(line, "vlan participation"),
			strings.HasPrefix(line, "vlan pvid"),
			strings.HasPrefix(line, "vlan tagging"):
			score += 2
		case strings.HasPrefix(line, "no spanning-tree"),
			strings.HasPrefix(line, "set igmp"):
			score++
		}
	}
	return score >= 2
}

func looksFortinet(text string) bool {
	score := 0
	hasStructural := false
	for _, raw := range strings.Split(strings.ToLower(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "config firewall policy"),
			strings.HasPrefix(line, "config firewall address"),
			strings.HasPrefix(line, "config firewall vip"),
			strings.HasPrefix(line, "config firewall ippool"),
			strings.HasPrefix(line, "config router static"),
			strings.HasPrefix(line, "config vpn ipsec"),
			strings.HasPrefix(line, "config system interface"),
			strings.HasPrefix(line, "config system admin"):
			score += 2
			hasStructural = true
		case strings.HasPrefix(line, "set srcintf "),
			strings.HasPrefix(line, "set dstintf "),
			strings.HasPrefix(line, "set srcaddr "),
			strings.HasPrefix(line, "set dstaddr "),
			strings.HasPrefix(line, "set service "):
			score++
		}
	}
	// Require at least one FortiOS structural config block. The weak set-tokens
	// (notably "set service ") also appear in EdgeOS/VyOS service statements, so they
	// must not classify a config as FortiOS on their own.
	return hasStructural && score >= 4
}

func looksJunos(text string) bool {
	score := 0
	for _, raw := range strings.Split(strings.ToLower(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "set interfaces "),
			strings.HasPrefix(line, "set routing-options "),
			strings.HasPrefix(line, "set firewall "),
			strings.HasPrefix(line, "set security "),
			strings.HasPrefix(line, "set vlans "),
			strings.HasPrefix(line, "delete interfaces "),
			strings.HasPrefix(line, "delete routing-options "),
			strings.HasPrefix(line, "delete firewall "),
			strings.HasPrefix(line, "delete security "),
			strings.HasPrefix(line, "delete vlans "):
			score++
		}
	}
	return score >= 3
}

func fortinetSectionKind(section string) string {
	lower := strings.ToLower(section)
	switch {
	case strings.HasPrefix(lower, "config firewall vip"),
		strings.HasPrefix(lower, "config firewall ippool"),
		strings.HasPrefix(lower, "config firewall central-snat-map"):
		return "nat"
	case strings.HasPrefix(lower, "config firewall"):
		return "firewall"
	case strings.HasPrefix(lower, "config router static"):
		return "route"
	case strings.HasPrefix(lower, "config vpn"):
		return "vpn"
	case strings.HasPrefix(lower, "config system admin"):
		return "aaa"
	case strings.HasPrefix(lower, "config system interface"),
		strings.HasPrefix(lower, "config system global"),
		strings.HasPrefix(lower, "config system accprofile"):
		return "management"
	case strings.HasPrefix(lower, "config log"),
		strings.HasPrefix(lower, "config system dns"),
		strings.HasPrefix(lower, "config system ntp"),
		strings.HasPrefix(lower, "config system snmp"):
		return "observability"
	default:
		return "generic"
	}
}

func classifyJunosSetLine(line string) (kind, id, header string) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "generic", "line:" + stableID(line), line
	}
	verb := strings.ToLower(fields[0])
	if verb != "set" && verb != "delete" {
		return "generic", "line:" + stableID(line), line
	}
	if len(fields) >= 3 && strings.EqualFold(fields[1], "interfaces") {
		name := fields[2]
		return "interface", "interface:" + strings.ToLower(name), fields[0] + " interfaces " + name
	}
	if len(fields) >= 3 && strings.EqualFold(fields[1], "vlans") {
		name := fields[2]
		return "vlan", "vlan:" + strings.ToLower(name), fields[0] + " vlans " + name
	}
	if len(fields) >= 5 && strings.EqualFold(fields[1], "routing-options") && strings.EqualFold(fields[2], "static") && strings.EqualFold(fields[3], "route") {
		return "route", "route:" + fields[4], fields[0] + " routing-options static route " + fields[4]
	}
	if len(fields) >= 4 && strings.EqualFold(fields[1], "firewall") {
		return "acl", "acl:" + strings.ToLower(strings.Join(fields[2:4], "-")), fields[0] + " " + strings.Join(fields[1:4], " ")
	}
	if len(fields) >= 4 && strings.EqualFold(fields[1], "security") && strings.EqualFold(fields[2], "nat") {
		return "nat", "nat:" + stableID(strings.Join(fields[:min(len(fields), 6)], " ")), fields[0] + " security nat"
	}
	if len(fields) >= 4 && strings.EqualFold(fields[1], "security") && strings.EqualFold(fields[2], "address-book") {
		return "firewall", "firewall:" + stableID(strings.Join(fields[:min(len(fields), 7)], " ")), fields[0] + " security address-book"
	}
	if len(fields) >= 4 && strings.EqualFold(fields[1], "security") && strings.EqualFold(fields[2], "policies") {
		return "firewall", "firewall:" + stableID(strings.Join(fields[:min(len(fields), 8)], " ")), fields[0] + " security policies"
	}
	if len(fields) >= 4 && strings.EqualFold(fields[1], "security") && (strings.EqualFold(fields[2], "ike") || strings.EqualFold(fields[2], "ipsec")) {
		return "vpn", "vpn:" + stableID(strings.Join(fields[:min(len(fields), 6)], " ")), fields[0] + " " + strings.Join(fields[1:3], " ")
	}
	if len(fields) >= 3 && strings.EqualFold(fields[1], "system") {
		if isJunosManagementLine(fields) {
			return "management", "management:" + stableID(strings.Join(fields[:min(len(fields), 5)], " ")), fields[0] + " " + strings.Join(fields[1:min(len(fields), 4)], " ")
		}
		if isJunosAAALine(fields) {
			return "aaa", "aaa:" + stableID(strings.Join(fields[:min(len(fields), 5)], " ")), fields[0] + " " + strings.Join(fields[1:min(len(fields), 4)], " ")
		}
		if isJunosObservabilityLine(fields) {
			return "observability", "observability:" + stableID(strings.Join(fields[:min(len(fields), 5)], " ")), fields[0] + " " + strings.Join(fields[1:min(len(fields), 4)], " ")
		}
	}
	kind, id, header, _ = classifyLine(line)
	if kind != "" {
		return kind, id, header
	}
	return "generic", "line:" + stableID(line), line
}

func normalizeLine(line string) string {
	line = strings.TrimSpace(strings.ReplaceAll(line, "\t", " "))
	if line == "" {
		return ""
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "!") ||
		strings.HasPrefix(lower, "#") ||
		strings.HasPrefix(lower, "//") ||
		strings.HasPrefix(lower, ";") ||
		strings.HasPrefix(lower, "remark ") {
		return ""
	}
	return strings.Join(strings.Fields(line), " ")
}

func classifyLine(line string) (kind, id, header string, multiline bool) {
	lower := strings.ToLower(line)
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", "", false
	}

	switch {
	case strings.HasPrefix(lower, "interface ") && len(fields) >= 2:
		name := strings.Join(fields[1:], " ")
		return "interface", "interface:" + strings.ToLower(name), line, true
	case strings.HasPrefix(lower, "vlan ") && len(fields) >= 2:
		return "vlan", "vlan:" + fields[1], line, true
	case strings.HasPrefix(lower, "router ") && len(fields) >= 2:
		return "routing", "routing:" + strings.ToLower(strings.Join(fields[1:], " ")), line, true
	case strings.HasPrefix(lower, "ip access-list ") && len(fields) >= 4:
		return "acl", "acl:" + strings.ToLower(strings.Join(fields[3:], " ")), line, true
	case strings.HasPrefix(lower, "line ") && len(fields) >= 2:
		return "management", "management:" + strings.ToLower(strings.Join(fields[1:], " ")), line, true
	case strings.HasPrefix(lower, "object network ") && len(fields) >= 3:
		return "nat", "nat-object:" + strings.ToLower(strings.Join(fields[2:], " ")), line, true
	case strings.HasPrefix(lower, "crypto map ") || strings.HasPrefix(lower, "tunnel-group "):
		return "vpn", "vpn:" + stableID(line), line, true
	case strings.HasPrefix(lower, "config firewall ") || strings.HasPrefix(lower, "edit "):
		return "firewall", "firewall:" + stableID(line), line, true
	case isRouteLine(lower):
		return "route", "route:" + routePrefix(line), line, false
	case accessListName(line) != "":
		name := accessListName(line)
		return "acl", "acl:" + strings.ToLower(name), "access-list " + name, false
	case isNATLine(lower):
		return "nat", "nat:" + stableID(line), line, false
	case isVPNLine(lower):
		return "vpn", "vpn:" + stableID(line), line, false
	case isAAAAuthLine(lower):
		return "aaa", "aaa:" + aaaID(line), line, false
	case isManagementLine(lower):
		return "management", "management:" + stableID(line), line, false
	case isObservabilityLine(lower):
		return "observability", "observability:" + stableID(line), line, false
	}
	return "", "", "", false
}

func mergeRelatedBlocks(blocks []configBlock) []configBlock {
	merged := make([]configBlock, 0, len(blocks))
	indexByID := map[string]int{}
	for _, block := range blocks {
		if idx, ok := indexByID[block.ID]; ok {
			merged[idx].Lines = append(merged[idx].Lines, block.Lines...)
			continue
		}
		indexByID[block.ID] = len(merged)
		merged = append(merged, block)
	}
	for i := range merged {
		merged[i].Lines = uniquePreserve(merged[i].Lines)
	}
	return merged
}

func detectPlatform(blocks []configBlock, requestedVendor string) DetectedPlatform {
	score := map[string]int{}
	signals := []string{}
	for _, block := range blocks {
		switch block.Kind {
		case "interface":
			score["interface"]++
		case "vlan":
			score["switch"] += 2
			signals = appendSignal(signals, "vlan blocks")
		case "route", "routing":
			score["router"] += 2
			signals = appendSignal(signals, "routing statements")
		case "acl", "firewall", "nat", "vpn":
			score["firewall"]++
		}
		for _, line := range block.Lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "switchport ") || strings.Contains(lower, "trunk allowed vlan") {
				score["switch"] += 2
				signals = appendSignal(signals, "switchport statements")
			}
			if strings.Contains(lower, "access-list ") || strings.Contains(lower, "ip access-list ") {
				signals = appendSignal(signals, "access-list syntax")
			}
			if strings.HasPrefix(lower, "set ") {
				signals = appendSignal(signals, "set-style syntax")
			}
		}
	}

	deviceType := "unknown"
	switch {
	case score["firewall"] >= score["router"] && score["firewall"] >= score["switch"] && score["firewall"] > 0:
		deviceType = "firewall"
	case score["router"] >= score["switch"] && score["router"] > 0:
		deviceType = "router"
	case score["switch"] > 0:
		deviceType = "switch"
	case score["interface"] > 0:
		deviceType = "network-device"
	}

	confidence := 0.35
	if len(signals) >= 2 {
		confidence = 0.55
	}
	if requestedVendor == "generic" {
		confidence = 0.65
	}

	return DetectedPlatform{
		RequestedVendor: requestedVendor,
		Parser:          "generic",
		DetectedVendor:  "generic",
		DeviceType:      deviceType,
		Confidence:      confidence,
		Signals:         signals,
	}
}

func blockFingerprint(block configBlock) string {
	lines := append([]string(nil), block.Lines...)
	if block.Kind != "acl" && block.Kind != "firewall" {
		sort.Strings(lines)
	}
	return strings.Join(lines, "\n")
}

func stableID(value string) string {
	value = strings.ToLower(value)
	value = strings.NewReplacer("/", "_", " ", "-", ".", "_", ":", "_").Replace(value)
	value = regexp.MustCompile(`[^a-z0-9_-]+`).ReplaceAllString(value, "")
	if len(value) > 80 {
		value = value[:80]
	}
	if value == "" {
		return "unknown"
	}
	return value
}

func uniquePreserve(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func appendSignal(values []string, signal string) []string {
	for _, value := range values {
		if value == signal {
			return values
		}
	}
	return append(values, signal)
}

func isRouteLine(lower string) bool {
	return strings.HasPrefix(lower, "ip route ") ||
		strings.HasPrefix(lower, "ipv6 route ") ||
		strings.HasPrefix(lower, "route ") ||
		strings.Contains(lower, " static route ")
}

func routePrefix(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 4 && strings.EqualFold(fields[0], "ip") && strings.EqualFold(fields[1], "route") {
		return fields[2] + "/" + fields[3]
	}
	if len(fields) >= 3 && strings.EqualFold(fields[0], "ipv6") && strings.EqualFold(fields[1], "route") {
		return fields[2]
	}
	for i := 0; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], "route") {
			return fields[i+1]
		}
	}
	for i, field := range fields {
		if strings.EqualFold(field, "route") && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	if len(fields) > 1 {
		return fields[1]
	}
	return line
}

func accessListName(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "access-list") {
		return fields[1]
	}
	return ""
}

func aaaID(line string) string {
	fields := strings.Fields(line)
	lowerFields := make([]string, len(fields))
	for i, field := range fields {
		lowerFields[i] = strings.ToLower(field)
	}
	if len(lowerFields) >= 4 && lowerFields[0] == "aaa" {
		return strings.Join(lowerFields[:4], "-")
	}
	if len(lowerFields) >= 3 && (lowerFields[0] == "radius" || lowerFields[0] == "tacacs") {
		return strings.Join(lowerFields[:3], "-")
	}
	if len(lowerFields) >= 2 && lowerFields[0] == "username" {
		return "username-" + lowerFields[1]
	}
	return stableID(line)
}

func isNATLine(lower string) bool {
	return strings.Contains(lower, " nat ") ||
		strings.HasPrefix(lower, "nat ") ||
		strings.Contains(lower, " source-nat ") ||
		strings.Contains(lower, " destination-nat ") ||
		strings.Contains(lower, "masquerade")
}

func isVPNLine(lower string) bool {
	return strings.Contains(lower, " vpn") ||
		strings.Contains(lower, "ipsec") ||
		strings.Contains(lower, " ike") ||
		strings.Contains(lower, "isakmp") ||
		strings.Contains(lower, "tunnel ")
}

func isAAAAuthLine(lower string) bool {
	return strings.HasPrefix(lower, "aaa ") ||
		strings.Contains(lower, " radius") ||
		strings.Contains(lower, " tacacs") ||
		strings.HasPrefix(lower, "username ") ||
		strings.Contains(lower, "authentication")
}

func isManagementLine(lower string) bool {
	return strings.Contains(lower, "ssh") ||
		strings.Contains(lower, "telnet") ||
		strings.Contains(lower, "http server") ||
		strings.Contains(lower, "https server") ||
		strings.Contains(lower, "management access") ||
		strings.Contains(lower, "snmp-server community") ||
		strings.HasPrefix(lower, "line vty")
}

func isObservabilityLine(lower string) bool {
	return strings.HasPrefix(lower, "logging ") ||
		strings.HasPrefix(lower, "no logging ") ||
		strings.HasPrefix(lower, "snmp-server ") ||
		strings.HasPrefix(lower, "ntp ") ||
		strings.Contains(lower, "name-server") ||
		strings.HasPrefix(lower, "ip name-server") ||
		strings.HasPrefix(lower, "dns ")
}

func routeNextHop(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 5 && strings.EqualFold(fields[0], "ip") && strings.EqualFold(fields[1], "route") {
		return fields[4]
	}
	for i := 0; i+1 < len(fields); i++ {
		if strings.EqualFold(fields[i], "next-hop") || strings.EqualFold(fields[i], "next-table") {
			return fields[i+1]
		}
	}
	return ""
}

func parseACLRule(line string) TouchedRule {
	fields := strings.Fields(line)
	lowerFields := make([]string, len(fields))
	for i, field := range fields {
		lowerFields[i] = strings.ToLower(field)
	}
	rule := TouchedRule{}
	idx := -1
	for i, field := range lowerFields {
		if field == "permit" || field == "deny" || field == "allow" || field == "drop" {
			idx = i
			rule.Action = field
			break
		}
	}
	if idx == -1 {
		return rule
	}
	if idx+1 < len(fields) {
		rule.Protocol = lowerFields[idx+1]
	}
	sourceIndex := idx + 2
	if sourceIndex < len(fields) {
		rule.Source = fields[sourceIndex]
	} else {
		return rule
	}
	destinationIndex := sourceIndex + aclAddressTokenWidth(fields[sourceIndex:])
	if destinationIndex < len(fields) {
		rule.Destination = fields[destinationIndex]
	}
	serviceStart := destinationIndex
	if destinationIndex < len(fields) {
		serviceStart = destinationIndex + aclAddressTokenWidth(fields[destinationIndex:])
	}
	for i := serviceStart; i < len(fields); i++ {
		if strings.EqualFold(fields[i], "eq") && i+1 < len(fields) {
			rule.Service = fields[i+1]
			break
		}
	}
	return rule
}

func betterRuleParse(candidate, current TouchedRule) bool {
	if candidate.Action == "" {
		return false
	}
	if current.Action == "" {
		return true
	}
	return ruleParseScore(candidate) > ruleParseScore(current)
}

func ruleParseScore(rule TouchedRule) int {
	score := 0
	if rule.Action != "" {
		score++
	}
	if rule.Protocol != "" {
		score++
	}
	if rule.Source != "" {
		score++
	}
	if rule.Destination != "" {
		score++
	}
	if rule.Service != "" {
		score += 2
	}
	if rule.Action == "permit" || rule.Action == "allow" {
		score++
	}
	return score
}

func aclAddressTokenWidth(fields []string) int {
	if len(fields) == 0 {
		return 0
	}
	switch strings.ToLower(fields[0]) {
	case "any":
		return 1
	case "host":
		if len(fields) >= 2 {
			return 2
		}
		return 1
	default:
		if len(fields) >= 2 && looksIPv4(fields[0]) && looksWildcardOrMask(fields[1]) {
			return 2
		}
		return 1
	}
}

func looksIPv4(value string) bool {
	return regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`).MatchString(value)
}

func looksWildcardOrMask(value string) bool {
	return looksIPv4(value)
}

func isJunosManagementLine(fields []string) bool {
	joined := strings.ToLower(strings.Join(fields, " "))
	return strings.Contains(joined, " services ssh") ||
		strings.Contains(joined, " services netconf") ||
		strings.Contains(joined, " services web-management") ||
		strings.Contains(joined, " snmp ")
}

func isJunosAAALine(fields []string) bool {
	joined := strings.ToLower(strings.Join(fields, " "))
	return strings.Contains(joined, " authentication-order") ||
		strings.Contains(joined, " radius-server") ||
		strings.Contains(joined, " tacplus-server") ||
		strings.Contains(joined, " login user")
}

func isJunosObservabilityLine(fields []string) bool {
	joined := strings.ToLower(strings.Join(fields, " "))
	return strings.Contains(joined, " syslog ") ||
		strings.Contains(joined, " ntp ") ||
		strings.Contains(joined, " name-server")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func debugBlockIDs(blocks []configBlock) []string {
	out := make([]string, 0, len(blocks))
	for _, block := range blocks {
		out = append(out, fmt.Sprintf("%s:%s", block.Kind, block.ID))
	}
	return out
}
