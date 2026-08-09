package configdiff

import (
	"net/netip"
	"sort"
	"strings"
)

type routingPeerFact struct {
	Protocol string
	Peer     string
	LocalAS  string
	RemoteAS string
	Area     string
	Summary  string
	Evidence []string
}

// routingPeerChanges extracts BGP/OSPF neighbor facts from routing block diffs.
// Neighbor identity and core parameters are parsed from before/after line sets so
// existing routing:* block IDs stay unchanged.
func routingPeerChanges(changes []BlockChange) []TouchedRoutingPeer {
	beforePeers := map[string]routingPeerFact{}
	afterPeers := map[string]routingPeerFact{}

	for _, change := range changes {
		if !isRoutingPeerSource(change) {
			continue
		}
		header := change.Header
		for key, peer := range parseRoutingPeersFromLines(change.BeforeLines, header) {
			mergePeerFact(beforePeers, key, peer)
		}
		for key, peer := range parseRoutingPeersFromLines(change.AfterLines, header) {
			mergePeerFact(afterPeers, key, peer)
		}
	}

	keys := map[string]bool{}
	for key := range beforePeers {
		keys[key] = true
	}
	for key := range afterPeers {
		keys[key] = true
	}
	sorted := make([]string, 0, len(keys))
	for key := range keys {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)

	out := []TouchedRoutingPeer{}
	for _, key := range sorted {
		before, hadBefore := beforePeers[key]
		after, hasAfter := afterPeers[key]
		switch {
		case !hadBefore && hasAfter:
			out = append(out, touchedFromPeerFact(after, "added", "", after.Summary))
		case hadBefore && !hasAfter:
			out = append(out, touchedFromPeerFact(before, "removed", before.Summary, ""))
		case peerCoreChanged(before, after):
			fact := after
			if fact.LocalAS == "" {
				fact.LocalAS = before.LocalAS
			}
			if fact.Area == "" {
				fact.Area = before.Area
			}
			out = append(out, touchedFromPeerFact(fact, "changed", before.Summary, after.Summary))
		}
	}
	return out
}

func isRoutingPeerSource(change BlockChange) bool {
	if change.Kind == "routing" {
		return true
	}
	lower := strings.ToLower(change.Header + " " + change.ID)
	if strings.Contains(lower, "bgp") || strings.Contains(lower, "ospf") {
		return true
	}
	for _, line := range append(change.BeforeLines, change.AfterLines...) {
		if routingPeerLine(line) {
			return true
		}
	}
	return false
}

func routingPeerLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	fields := strings.Fields(lower)
	if len(fields) >= 4 && fields[0] == "neighbor" && looksPeerAddress(fields[1]) && fields[2] == "remote-as" {
		return true
	}
	if len(fields) >= 2 && fields[0] == "neighbor" && looksPeerAddress(fields[1]) {
		return true
	}
	if strings.Contains(lower, "protocols bgp") && strings.Contains(lower, " neighbor ") {
		return true
	}
	if strings.Contains(lower, "protocols ospf") && strings.Contains(lower, " neighbor ") {
		return true
	}
	return false
}

func parseRoutingPeersFromLines(lines []string, header string) map[string]routingPeerFact {
	out := map[string]routingPeerFact{}
	protoHint := routingProtocolHint(header, lines)
	localAS := localASFromHeaderOrLines(header, lines)
	ospfArea := ospfAreaFromLines(lines)

	for _, line := range lines {
		switch protoHint {
		case "bgp":
			if peer, ok := parseBGPNeighborLine(line, localAS); ok {
				mergePeerFact(out, peerKey(peer), peer)
			}
		case "ospf":
			if peer, ok := parseOSPFNeighborLine(line, ospfArea); ok {
				mergePeerFact(out, peerKey(peer), peer)
			}
		default:
			if peer, ok := parseBGPNeighborLine(line, localAS); ok {
				mergePeerFact(out, peerKey(peer), peer)
				continue
			}
			if peer, ok := parseOSPFNeighborLine(line, ospfArea); ok {
				mergePeerFact(out, peerKey(peer), peer)
			}
		}
	}
	return out
}

func routingProtocolHint(header string, lines []string) string {
	blob := strings.ToLower(header)
	for _, line := range lines {
		blob += " " + strings.ToLower(line)
	}
	hasBGP := strings.Contains(blob, "bgp") || strings.Contains(blob, "remote-as")
	hasOSPF := strings.Contains(blob, "ospf")
	switch {
	case hasBGP && !hasOSPF:
		return "bgp"
	case hasOSPF && !hasBGP:
		return "ospf"
	default:
		return ""
	}
}

func localASFromHeaderOrLines(header string, lines []string) string {
	if as := localASFromText(header); as != "" {
		return as
	}
	for _, line := range lines {
		if as := localASFromText(line); as != "" {
			return as
		}
	}
	return ""
}

func localASFromText(text string) string {
	fields := strings.Fields(strings.ToLower(text))
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "bgp" && isASNToken(fields[i+1]) {
			return fields[i+1]
		}
	}
	return ""
}

func ospfAreaFromLines(lines []string) string {
	for _, line := range lines {
		fields := strings.Fields(strings.ToLower(line))
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "area" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func parseBGPNeighborLine(line, localAS string) (routingPeerFact, bool) {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	fields := strings.Fields(trimmed)
	lowerFields := strings.Fields(lower)
	if len(fields) == 0 {
		return routingPeerFact{}, false
	}

	// Cisco/FRR: neighbor <addr> remote-as <asn>
	if len(lowerFields) >= 4 && lowerFields[0] == "neighbor" && lowerFields[2] == "remote-as" && looksPeerAddress(lowerFields[1]) {
		peer := routingPeerFact{
			Protocol: "bgp",
			Peer:     fields[1],
			LocalAS:  localAS,
			RemoteAS: fields[3],
			Summary:  "remote-as " + fields[3],
			Evidence: []string{trimmed},
		}
		if localAS != "" {
			peer.Summary = "local-as " + localAS + " " + peer.Summary
		}
		return peer, true
	}

	// EdgeOS/VyOS: set protocols bgp <asn> neighbor <addr> remote-as <asn>
	if idx := indexOfFold(lowerFields, "bgp"); idx >= 0 && idx+1 < len(lowerFields) {
		as := ""
		if isASNToken(lowerFields[idx+1]) {
			as = fields[idx+1]
		}
		nIdx := indexOfFold(lowerFields, "neighbor")
		if nIdx >= 0 && nIdx+1 < len(lowerFields) && looksPeerAddress(lowerFields[nIdx+1]) {
			remoteAS := ""
			if rIdx := indexOfFold(lowerFields, "remote-as"); rIdx >= 0 && rIdx+1 < len(fields) {
				remoteAS = fields[rIdx+1]
			}
			if remoteAS == "" && !strings.Contains(lower, "remote-as") {
				// Neighbor stanza without remote-as (description/update-source) is not a core peer fact alone.
				return routingPeerFact{}, false
			}
			if remoteAS == "" {
				return routingPeerFact{}, false
			}
			if as == "" {
				as = localAS
			}
			peer := routingPeerFact{
				Protocol: "bgp",
				Peer:     fields[nIdx+1],
				LocalAS:  as,
				RemoteAS: remoteAS,
				Summary:  "remote-as " + remoteAS,
				Evidence: []string{trimmed},
			}
			if as != "" {
				peer.Summary = "local-as " + as + " " + peer.Summary
			}
			return peer, true
		}
	}
	return routingPeerFact{}, false
}

func parseOSPFNeighborLine(line, defaultArea string) (routingPeerFact, bool) {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	fields := strings.Fields(trimmed)
	lowerFields := strings.Fields(lower)
	if len(fields) == 0 {
		return routingPeerFact{}, false
	}

	// Cisco/FRR: neighbor <addr> [priority|cost|poll-interval ...]
	if len(lowerFields) >= 2 && lowerFields[0] == "neighbor" && looksPeerAddress(lowerFields[1]) {
		// Avoid classifying BGP neighbor attribute lines as OSPF.
		if containsFold(lowerFields, "remote-as") || isBGPNeighborAttribute(lowerFields) {
			return routingPeerFact{}, false
		}
		peer := routingPeerFact{
			Protocol: "ospf",
			Peer:     fields[1],
			Area:     defaultArea,
			Summary:  "neighbor " + fields[1],
			Evidence: []string{trimmed},
		}
		if defaultArea != "" {
			peer.Summary += " area " + defaultArea
		}
		return peer, true
	}

	// EdgeOS/VyOS: set protocols ospf neighbor <addr>
	if indexOfFold(lowerFields, "ospf") >= 0 {
		nIdx := indexOfFold(lowerFields, "neighbor")
		if nIdx >= 0 && nIdx+1 < len(fields) && looksPeerAddress(lowerFields[nIdx+1]) {
			area := defaultArea
			if aIdx := indexOfFold(lowerFields, "area"); aIdx >= 0 && aIdx+1 < len(fields) {
				area = fields[aIdx+1]
			}
			peer := routingPeerFact{
				Protocol: "ospf",
				Peer:     fields[nIdx+1],
				Area:     area,
				Summary:  "neighbor " + fields[nIdx+1],
				Evidence: []string{trimmed},
			}
			if area != "" {
				peer.Summary += " area " + area
			}
			return peer, true
		}
	}
	return routingPeerFact{}, false
}

func mergePeerFact(dst map[string]routingPeerFact, key string, peer routingPeerFact) {
	existing, ok := dst[key]
	if !ok {
		dst[key] = peer
		return
	}
	if existing.LocalAS == "" {
		existing.LocalAS = peer.LocalAS
	}
	if existing.RemoteAS == "" {
		existing.RemoteAS = peer.RemoteAS
	}
	if existing.Area == "" {
		existing.Area = peer.Area
	}
	if peer.Summary != "" {
		existing.Summary = peer.Summary
	}
	existing.Evidence = uniquePreserve(append(existing.Evidence, peer.Evidence...))
	dst[key] = existing
}

func peerKey(peer routingPeerFact) string {
	return peer.Protocol + "|" + strings.ToLower(peer.Peer)
}

func peerCoreChanged(before, after routingPeerFact) bool {
	if before.Protocol == "bgp" {
		return before.RemoteAS != after.RemoteAS || (before.LocalAS != "" && after.LocalAS != "" && before.LocalAS != after.LocalAS)
	}
	if before.Protocol == "ospf" {
		return before.Area != after.Area && (before.Area != "" || after.Area != "")
	}
	return before.Summary != after.Summary
}

func touchedFromPeerFact(peer routingPeerFact, changeType, before, after string) TouchedRoutingPeer {
	evidence := append([]string{}, peer.Evidence...)
	if before != "" && after != "" && before != after {
		// Keep evidence focused on peer lines already collected.
	}
	return TouchedRoutingPeer{
		Protocol:   peer.Protocol,
		Peer:       peer.Peer,
		LocalAS:    peer.LocalAS,
		RemoteAS:   peer.RemoteAS,
		Area:       peer.Area,
		ChangeType: changeType,
		Before:     before,
		After:      after,
		Evidence:   evidence,
	}
}

// appendRoutingPeerFindings emits adjacency risk findings from touched peer facts.
func appendRoutingPeerFindings(add func(severity, category, title, recommendation string, evidence, details []string), peers []TouchedRoutingPeer) {
	for _, peer := range peers {
		switch peer.Protocol {
		case "bgp":
			switch peer.ChangeType {
			case "added":
				add("high", "routing", "BGP neighbor added", "Validate the new BGP session, prefix exchange, and routing policy before relying on the adjacency.", peer.Evidence, []string{"Added BGP neighbor " + peer.Peer + peerASDetail(peer) + "."})
			case "removed":
				add("high", "routing", "BGP neighbor removed", "Confirm dependent prefixes and failover paths before accepting loss of this BGP adjacency.", peer.Evidence, []string{"Removed BGP neighbor " + peer.Peer + peerASDetail(peer) + "."})
			case "changed":
				if peer.Before != "" && peer.After != "" && strings.Contains(peer.Before, "remote-as") && strings.Contains(peer.After, "remote-as") && peer.Before != peer.After {
					add("high", "routing", "BGP remote-AS changed", "A remote-AS change rewrites BGP session identity; confirm the peer ASN and inbound/outbound policy.", peer.Evidence, []string{"BGP neighbor " + peer.Peer + " changed from " + peer.Before + " to " + peer.After + "."})
				} else {
					add("medium", "routing", "BGP peer parameters changed", "Review BGP neighbor timers, source, and policy after the parameter change.", peer.Evidence, []string{"BGP neighbor " + peer.Peer + " parameters changed."})
				}
			}
		case "ospf":
			switch peer.ChangeType {
			case "added":
				add("high", "routing", "OSPF neighbor added", "Validate the new OSPF adjacency, area membership, and LSA exchange before relying on the neighbor.", peer.Evidence, []string{"Added OSPF neighbor " + peer.Peer + peerAreaDetail(peer) + "."})
			case "removed":
				add("high", "routing", "OSPF neighbor removed", "Confirm area connectivity and backup paths before accepting loss of this OSPF adjacency.", peer.Evidence, []string{"Removed OSPF neighbor " + peer.Peer + peerAreaDetail(peer) + "."})
			case "changed":
				add("medium", "routing", "OSPF peer parameters changed", "Review OSPF neighbor area and adjacency parameters after the change.", peer.Evidence, []string{"OSPF neighbor " + peer.Peer + " parameters changed."})
			}
		}
	}
}

func peerASDetail(peer TouchedRoutingPeer) string {
	parts := []string{}
	if peer.LocalAS != "" {
		parts = append(parts, "local-as "+peer.LocalAS)
	}
	if peer.RemoteAS != "" {
		parts = append(parts, "remote-as "+peer.RemoteAS)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func peerAreaDetail(peer TouchedRoutingPeer) string {
	if peer.Area == "" {
		return ""
	}
	return " (area " + peer.Area + ")"
}

func looksPeerAddress(token string) bool {
	if _, err := netip.ParseAddr(token); err == nil {
		return true
	}
	// Allow hostnames / interface names used as BGP neighbors in some dialects.
	if strings.Contains(token, "/") || strings.Contains(token, ":") {
		return false
	}
	return strings.ContainsAny(token, ".") || (len(token) > 0 && !isASNToken(token) && !isKeywordToken(token))
}

func isASNToken(token string) bool {
	if token == "" {
		return false
	}
	for _, r := range token {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isKeywordToken(token string) bool {
	switch strings.ToLower(token) {
	case "remote-as", "description", "update-source", "route-map", "prefix-list", "next-hop-self", "activate", "soft-reconfiguration", "priority", "poll-interval":
		return true
	default:
		return false
	}
}

func isBGPNeighborAttribute(fields []string) bool {
	if len(fields) < 3 {
		return false
	}
	switch strings.ToLower(fields[2]) {
	case "description", "update-source", "remote-as", "route-map", "password", "timers", "ebgp-multihop", "next-hop-self", "send-community", "soft-reconfiguration", "activate", "peer-group", "local-as", "shutdown":
		return true
	default:
		return false
	}
}

func indexOfFold(fields []string, want string) int {
	for i, field := range fields {
		if strings.EqualFold(field, want) {
			return i
		}
	}
	return -1
}

func containsFold(fields []string, want string) bool {
	return indexOfFold(fields, want) >= 0
}
