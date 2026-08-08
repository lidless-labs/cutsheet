package configdiff

import (
	"sort"
	"strings"
)

// objectRefKind identifies a named config object that can be referenced from an interface.
type objectRefKind string

const (
	refKindACL        objectRefKind = "acl"
	refKindRouteMap   objectRefKind = "route-map"
	refKindPrefixList objectRefKind = "prefix-list"
)

// interfaceObjectRef is a named object applied to an interface (directly or via an applied route-map).
type interfaceObjectRef struct {
	Kind      objectRefKind
	Name      string // lower-cased for matching
	Display   string // original token for evidence/details
	Interface string
	Direction string // in|out|local, or empty for route-map/prefix-list
	Via       string // route-map name when prefix-list is reached through PBR
	Evidence  string
}

func appendUndefinedReferenceFindings(
	add func(severity, category, title, recommendation string, evidence, details []string),
	beforeBlocks, afterBlocks []configBlock,
) {
	beforeDefs := collectDefinedNamedObjects(beforeBlocks)
	afterDefs := collectDefinedNamedObjects(afterBlocks)
	beforeRefs := collectInterfaceObjectRefs(beforeBlocks)
	afterRefs := collectInterfaceObjectRefs(afterBlocks)

	beforeDangling := danglingRefKeys(beforeRefs, beforeDefs)
	afterDangling := filterDanglingRefs(afterRefs, afterDefs)

	byKind := map[objectRefKind][]interfaceObjectRef{}
	for _, ref := range afterDangling {
		key := refKey(ref)
		if beforeDangling[key] {
			continue // unchanged dangling state: no noise
		}
		byKind[ref.Kind] = append(byKind[ref.Kind], ref)
	}

	emit := func(kind objectRefKind, title, noun, recommendation string) {
		refs := byKind[kind]
		if len(refs) == 0 {
			return
		}
		sortInterfaceObjectRefs(refs)
		details := make([]string, 0, len(refs))
		evidence := make([]string, 0, len(refs))
		for _, ref := range refs {
			details = append(details, formatRefDetail(ref, noun))
			evidence = append(evidence, ref.Evidence)
		}
		add("high", "undefined_reference", title, recommendation, evidence, details)
	}

	emit(refKindACL,
		"Undefined ACL referenced on interface",
		"ACL",
		"Define the ACL/firewall policy or remove the interface filter application before relying on the intended policy.")
	emit(refKindRouteMap,
		"Undefined route-map referenced on interface",
		"route-map",
		"Define the route-map or remove the interface policy application before relying on policy-based routing.")
	emit(refKindPrefixList,
		"Undefined prefix-list referenced on interface",
		"prefix-list",
		"Define the prefix-list or remove the match from the interface-applied route-map before relying on the match criteria.")
}

func collectDefinedNamedObjects(blocks []configBlock) map[objectRefKind]map[string]bool {
	out := map[objectRefKind]map[string]bool{
		refKindACL:        {},
		refKindRouteMap:   {},
		refKindPrefixList: {},
	}
	for _, block := range blocks {
		switch block.Kind {
		case "acl", "firewall":
			name := strings.TrimPrefix(strings.TrimPrefix(block.ID, "acl:"), "firewall:")
			if name != "" && !strings.HasPrefix(name, "group-") && !strings.HasPrefix(name, "global-") {
				out[refKindACL][strings.ToLower(name)] = true
			}
		case "route-map":
			name := strings.TrimPrefix(block.ID, "route-map:")
			if name != "" {
				out[refKindRouteMap][strings.ToLower(name)] = true
			}
		case "prefix-list":
			name := strings.TrimPrefix(block.ID, "prefix-list:")
			if name != "" {
				out[refKindPrefixList][strings.ToLower(name)] = true
			}
		}
		// Numbered/named ACLs and set-style definitions may also appear as lines
		// inside merged blocks; scan lines for Cisco/EdgeOS definition forms.
		for _, line := range block.Lines {
			if name, ok := definedACLName(line); ok {
				out[refKindACL][name] = true
			}
			if name, ok := definedRouteMapName(line); ok {
				out[refKindRouteMap][name] = true
			}
			if name, ok := definedPrefixListName(line); ok {
				out[refKindPrefixList][name] = true
			}
		}
	}
	return out
}

func collectInterfaceObjectRefs(blocks []configBlock) []interfaceObjectRef {
	refs := []interfaceObjectRef{}
	routeMapBodies := map[string][]string{} // lower name -> lines
	appliedRouteMaps := []interfaceObjectRef{}

	for _, block := range blocks {
		if block.Kind == "route-map" {
			name := strings.TrimPrefix(block.ID, "route-map:")
			routeMapBodies[strings.ToLower(name)] = append(routeMapBodies[strings.ToLower(name)], block.Lines...)
		}
		for _, line := range block.Lines {
			if name, ok := definedRouteMapName(line); ok {
				routeMapBodies[name] = append(routeMapBodies[name], line)
			}
		}
	}

	for _, block := range blocks {
		_, ifaceDisplay := interfaceNamesFromBlock(block)
		if ifaceDisplay == "" {
			continue
		}
		for _, line := range block.Lines {
			if ref, ok := parseInterfaceACLRef(line, ifaceDisplay); ok {
				refs = append(refs, ref)
			}
			if ref, ok := parseInterfaceRouteMapRef(line, ifaceDisplay); ok {
				refs = append(refs, ref)
				appliedRouteMaps = append(appliedRouteMaps, ref)
			}
		}
	}

	for _, rmRef := range appliedRouteMaps {
		body := routeMapBodies[strings.ToLower(rmRef.Name)]
		for _, line := range body {
			if pref, ok := parseRouteMapPrefixListRef(line); ok {
				refs = append(refs, interfaceObjectRef{
					Kind:      refKindPrefixList,
					Name:      pref.Name,
					Display:   pref.Display,
					Interface: rmRef.Interface,
					Via:       rmRef.Display,
					Evidence:  line,
				})
			}
		}
	}
	return refs
}

func interfaceNamesFromBlock(block configBlock) (idName, displayName string) {
	if block.Kind != "interface" || !strings.HasPrefix(block.ID, "interface:") {
		return "", ""
	}
	idName = strings.TrimPrefix(block.ID, "interface:")
	fields := strings.Fields(block.Header)
	switch {
	case len(fields) >= 2 && strings.EqualFold(fields[0], "interface"):
		displayName = strings.Join(fields[1:], " ")
	case len(fields) >= 4 && strings.EqualFold(fields[1], "interfaces"):
		// EdgeOS/VyOS: set interfaces ethernet eth0
		displayName = fields[3]
	default:
		displayName = idName
	}
	return idName, displayName
}

func parseInterfaceACLRef(line, iface string) (interfaceObjectRef, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return interfaceObjectRef{}, false
	}
	lower := make([]string, len(fields))
	for i, f := range fields {
		lower[i] = strings.ToLower(f)
	}
	if lower[0] == "no" {
		return interfaceObjectRef{}, false
	}

	// Cisco: ip access-group NAME|NUM in|out
	if len(fields) >= 4 && lower[0] == "ip" && lower[1] == "access-group" {
		dir := lower[len(fields)-1]
		if dir != "in" && dir != "out" {
			return interfaceObjectRef{}, false
		}
		name := fields[2]
		if name == "" || strings.EqualFold(name, "in") || strings.EqualFold(name, "out") {
			return interfaceObjectRef{}, false
		}
		return interfaceObjectRef{
			Kind:      refKindACL,
			Name:      strings.ToLower(name),
			Display:   name,
			Interface: iface,
			Direction: dir,
			Evidence:  line,
		}, true
	}

	// EdgeOS/VyOS: set interfaces ... firewall in|out|local name NAME
	if len(fields) >= 2 && (lower[0] == "set" || lower[0] == "delete") {
		if lower[0] == "delete" {
			return interfaceObjectRef{}, false
		}
		fwIdx := indexOfToken(lower, "firewall")
		if fwIdx < 0 || fwIdx+3 >= len(fields) {
			return interfaceObjectRef{}, false
		}
		dir := lower[fwIdx+1]
		if dir != "in" && dir != "out" && dir != "local" {
			return interfaceObjectRef{}, false
		}
		if lower[fwIdx+2] != "name" && lower[fwIdx+2] != "ipv6-name" {
			return interfaceObjectRef{}, false
		}
		name := fields[fwIdx+3]
		if name == "" {
			return interfaceObjectRef{}, false
		}
		return interfaceObjectRef{
			Kind:      refKindACL,
			Name:      strings.ToLower(name),
			Display:   name,
			Interface: iface,
			Direction: dir,
			Evidence:  line,
		}, true
	}
	return interfaceObjectRef{}, false
}

func parseInterfaceRouteMapRef(line, iface string) (interfaceObjectRef, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return interfaceObjectRef{}, false
	}
	lower := make([]string, len(fields))
	for i, f := range fields {
		lower[i] = strings.ToLower(f)
	}
	if lower[0] == "no" {
		return interfaceObjectRef{}, false
	}
	// Cisco: ip policy route-map NAME
	if lower[0] == "ip" && lower[1] == "policy" && lower[2] == "route-map" {
		name := fields[3]
		if name == "" {
			return interfaceObjectRef{}, false
		}
		return interfaceObjectRef{
			Kind:      refKindRouteMap,
			Name:      strings.ToLower(name),
			Display:   name,
			Interface: iface,
			Evidence:  line,
		}, true
	}
	return interfaceObjectRef{}, false
}

func parseRouteMapPrefixListRef(line string) (interfaceObjectRef, bool) {
	fields := strings.Fields(line)
	lower := make([]string, len(fields))
	for i, f := range fields {
		lower[i] = strings.ToLower(f)
	}
	// match ip address prefix-list NAME
	// match ipv6 address prefix-list NAME
	for i := 0; i+4 < len(lower); i++ {
		if lower[i] == "match" && (lower[i+1] == "ip" || lower[i+1] == "ipv6") &&
			lower[i+2] == "address" && lower[i+3] == "prefix-list" {
			name := fields[i+4]
			if name == "" {
				return interfaceObjectRef{}, false
			}
			return interfaceObjectRef{
				Kind:    refKindPrefixList,
				Name:    strings.ToLower(name),
				Display: name,
			}, true
		}
	}
	return interfaceObjectRef{}, false
}

func definedACLName(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	lower := make([]string, len(fields))
	for i, f := range fields {
		lower[i] = strings.ToLower(f)
	}
	if lower[0] == "no" {
		return "", false
	}
	if len(fields) >= 4 && lower[0] == "ip" && lower[1] == "access-list" {
		return strings.ToLower(fields[3]), true
	}
	if name := accessListName(line); name != "" {
		return strings.ToLower(name), true
	}
	// EdgeOS: set firewall name NAME ...
	if len(fields) >= 4 && (lower[0] == "set" || lower[0] == "delete") &&
		lower[1] == "firewall" && (lower[2] == "name" || lower[2] == "ipv6-name") {
		return strings.ToLower(fields[3]), true
	}
	return "", false
}

func definedRouteMapName(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", false
	}
	if strings.EqualFold(fields[0], "no") {
		return "", false
	}
	if strings.EqualFold(fields[0], "route-map") {
		return strings.ToLower(fields[1]), true
	}
	return "", false
}

func definedPrefixListName(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", false
	}
	lower0 := strings.ToLower(fields[0])
	if lower0 == "no" {
		return "", false
	}
	if lower0 == "ip" && strings.EqualFold(fields[1], "prefix-list") {
		return strings.ToLower(fields[2]), true
	}
	if lower0 == "ipv6" && strings.EqualFold(fields[1], "prefix-list") {
		return strings.ToLower(fields[2]), true
	}
	return "", false
}

func danglingRefKeys(refs []interfaceObjectRef, defs map[objectRefKind]map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, ref := range filterDanglingRefs(refs, defs) {
		out[refKey(ref)] = true
	}
	return out
}

func filterDanglingRefs(refs []interfaceObjectRef, defs map[objectRefKind]map[string]bool) []interfaceObjectRef {
	out := []interfaceObjectRef{}
	seen := map[string]bool{}
	for _, ref := range refs {
		if defs[ref.Kind][ref.Name] {
			continue
		}
		key := refKey(ref)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	return out
}

func refKey(ref interfaceObjectRef) string {
	return string(ref.Kind) + "|" + ref.Name + "|" + strings.ToLower(ref.Interface) + "|" + ref.Direction + "|" + strings.ToLower(ref.Via)
}

func formatRefDetail(ref interfaceObjectRef, noun string) string {
	switch ref.Kind {
	case refKindACL:
		return noun + " " + ref.Display + " on " + ref.Interface + " " + ref.Direction
	case refKindRouteMap:
		return noun + " " + ref.Display + " on " + ref.Interface
	case refKindPrefixList:
		return noun + " " + ref.Display + " via route-map " + ref.Via + " on " + ref.Interface
	default:
		return noun + " " + ref.Display + " on " + ref.Interface
	}
}

func sortInterfaceObjectRefs(refs []interfaceObjectRef) {
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if !strings.EqualFold(a.Interface, b.Interface) {
			return strings.ToLower(a.Interface) < strings.ToLower(b.Interface)
		}
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		return strings.ToLower(a.Via) < strings.ToLower(b.Via)
	})
}

func indexOfToken(fields []string, want string) int {
	for i, f := range fields {
		if f == want {
			return i
		}
	}
	return -1
}
