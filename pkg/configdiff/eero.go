package configdiff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
)

var knownEeroCollections = map[string]bool{
	"eeros":        true,
	"forwards":     true,
	"network":      true,
	"profiles":     true,
	"reservations": true,
}

// Parse reads the deterministic JSON snapshot emitted by the eero collector and
// maps only fields with an existing Analysis home onto typed block kinds. Port
// forwards are NAT objects, DNS is observability, WiFi/security settings are
// management-plane changes, and eero nodes are interface-like inventory blocks.
func (eeroJSONParser) Parse(text string, requestedVendor string) parsedConfig {
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &root); err != nil {
		parsed := parseGeneric(text, requestedVendor)
		parsed.Detection.Parser = "eero-json"
		parsed.Detection.DetectedVendor = "eero"
		parsed.Detection.Confidence = 0.30
		parsed.Detection.Signals = appendSignal(parsed.Detection.Signals, "requested eero-json but input was not valid JSON; treated generically")
		return parsed
	}

	blocks := []configBlock{}
	if network := eeroObject(root, "network"); len(network) > 0 {
		blocks = append(blocks, eeroNetworkBlocks(network)...)
	}
	for _, e := range eeroArray(root, "eeros") {
		key := eeroResourceKey(e, "eero")
		lines := eeroLeafLines("eero["+key+"]", e)
		lines = append(lines, "interface eero-"+key)
		sort.Strings(lines)
		blocks = append(blocks, configBlock{ID: "interface:eero-" + key, Kind: "interface", Header: "eero node " + eeroNodeName(e), Lines: uniquePreserve(lines)})
	}
	for _, e := range eeroArray(root, "forwards") {
		key := eeroResourceKey(e, "forward")
		lines := eeroLeafLines("forward["+key+"]", e)
		if line := eeroNATLine(e); line != "" {
			lines = append(lines, line)
		}
		sort.Strings(lines)
		blocks = append(blocks, configBlock{ID: "nat:" + key, Kind: "nat", Header: "eero forward " + eeroForwardName(e), Lines: uniquePreserve(lines)})
	}
	for _, e := range eeroArray(root, "profiles") {
		key := eeroResourceKey(e, "profile")
		blocks = append(blocks, configBlock{ID: "profile:" + key, Kind: "profile", Header: "eero profile " + eeroProfileName(e), Lines: eeroLeafLines("profile["+key+"]", e)})
	}
	for _, e := range eeroArray(root, "reservations") {
		key := eeroResourceKey(e, "reservation")
		blocks = append(blocks, configBlock{ID: "reservation:" + key, Kind: "reservation", Header: "eero reservation " + eeroReservationName(e), Lines: eeroLeafLines("reservation["+key+"]", e)})
	}

	keys := make([]string, 0, len(root))
	for k := range root {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if knownEeroCollections[k] {
			continue
		}
		var value any
		if err := json.Unmarshal(root[k], &value); err != nil {
			continue
		}
		lines := []string{}
		eeroFlatten(strings.ToLower(k), value, &lines)
		sort.Strings(lines)
		if len(lines) == 0 {
			continue
		}
		blocks = append(blocks, configBlock{ID: "line:" + stableID(strings.ToLower(k)), Kind: "generic", Header: k, Lines: uniquePreserve(lines)})
	}

	blocks = mergeRelatedBlocks(blocks)
	detection := detectPlatform(blocks, requestedVendor)
	detection.Parser = "eero-json"
	detection.DetectedVendor = "eero"
	detection.DeviceType = "mesh"
	detection.Confidence = 0.82
	if !strings.EqualFold(requestedVendor, "auto") {
		detection.Confidence = 0.92
	}
	detection.Signals = appendSignal(detection.Signals, "eero collector json snapshot")
	return parsedConfig{Detection: detection, Blocks: blocks}
}

func looksEeroJSON(text string) bool {
	trimmed := strings.TrimSpace(text)
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	lower := strings.ToLower(trimmed)
	required := []string{"eeros", "forwards", "network", "profiles", "reservations"}
	for _, key := range required {
		if !strings.Contains(lower, `"`+key+`"`) {
			return false
		}
	}
	return strings.Contains(lower, `"/2.2/networks/`) || strings.Contains(lower, `"/2.2/eeros/`)
}

func eeroNetworkBlocks(network map[string]any) []configBlock {
	url := firstNonEmpty(eeroScalar(network["url"]), "network")
	groups := []struct {
		name   string
		kind   string
		fields []string
	}{
		{"wifi", "management", []string{"name", "password", "wpa3", "guest_network"}},
		{"dns", "observability", []string{"dns"}},
		{"dhcp", "network", []string{"dhcp", "ip_settings"}},
		{"features", "network", []string{"upnp", "band_steering", "ipv6_upstream", "thread", "sqm"}},
	}

	blocks := []configBlock{}
	for _, group := range groups {
		lines := []string{}
		for _, field := range group.fields {
			value, ok := network[field]
			if !ok {
				continue
			}
			eeroFlatten("network."+field, value, &lines)
		}
		sort.Strings(lines)
		if len(lines) == 0 {
			continue
		}
		blocks = append(blocks, configBlock{
			ID:     group.kind + ":" + url + "/" + group.name,
			Kind:   group.kind,
			Header: "eero network " + group.name + " " + url,
			Lines:  uniquePreserve(lines),
		})
	}
	return blocks
}

func eeroObject(root map[string]json.RawMessage, key string) map[string]any {
	raw, ok := root[key]
	if !ok {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	return obj
}

func eeroArray(root map[string]json.RawMessage, key string) []map[string]any {
	raw, ok := root[key]
	if !ok {
		return nil
	}
	var arr []map[string]any
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	return arr
}

func eeroLeafLines(prefix string, e map[string]any) []string {
	lines := []string{}
	eeroFlatten(prefix, e, &lines)
	sort.Strings(lines)
	return uniquePreserve(lines)
}

func eeroFlatten(prefix string, v any, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			eeroFlatten(prefix+"."+strings.ToLower(k), t[k], out)
		}
	case []any:
		allScalar := true
		scalars := []string{}
		for _, item := range t {
			switch item.(type) {
			case map[string]any, []any:
				allScalar = false
			default:
				scalars = append(scalars, eeroScalarForPath(prefix, item))
			}
		}
		if allScalar {
			*out = append(*out, prefix+" = ["+strings.Join(scalars, ",")+"]")
			return
		}
		for i, item := range t {
			eeroFlatten(prefix+"."+strconv.Itoa(i), item, out)
		}
	default:
		*out = append(*out, prefix+" = "+eeroScalarForPath(prefix, v))
	}
}

func eeroScalarForPath(path string, v any) string {
	if eeroSensitivePath(path) {
		value := eeroScalar(v)
		if value == "" {
			return "<redacted>"
		}
		sum := sha256.Sum256([]byte(value))
		return "<redacted:" + hex.EncodeToString(sum[:])[:12] + ">"
	}
	return eeroScalar(v)
}

func eeroSensitivePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".password") || strings.Contains(lower, ".password.")
}

func eeroScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == math.Trunc(t) && !math.IsInf(t, 0) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

func eeroResourceKey(e map[string]any, fallback string) string {
	if url := eeroScalar(e["url"]); url != "" {
		return strings.ToLower(url)
	}
	for _, field := range []string{"serial", "mac_address", "mac", "description", "name"} {
		if value := eeroScalar(e[field]); value != "" {
			return strings.ToLower(value)
		}
	}
	return fallback + "-" + stableID(eeroObjectFingerprint(e))
}

func eeroObjectFingerprint(e map[string]any) string {
	b, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return string(b)
}

func eeroNodeName(e map[string]any) string {
	return firstNonEmpty(eeroScalar(e["location"]), eeroScalar(e["serial"]), eeroScalar(e["url"]))
}

func eeroForwardName(e map[string]any) string {
	return firstNonEmpty(eeroScalar(e["description"]), eeroScalar(e["url"]))
}

func eeroProfileName(e map[string]any) string {
	return firstNonEmpty(eeroScalar(e["name"]), eeroScalar(e["url"]))
}

func eeroReservationName(e map[string]any) string {
	return firstNonEmpty(eeroScalar(e["description"]), eeroScalar(e["ip"]), eeroScalar(e["url"]))
}

func eeroNATLine(e map[string]any) string {
	protocol := strings.ToLower(firstNonEmpty(eeroScalar(e["protocol"]), "tcp"))
	gatewayPort := eeroScalar(e["gateway_port"])
	clientIP := eeroScalar(e["ip"])
	clientPort := eeroScalar(e["client_port"])
	enabled := eeroScalar(e["enabled"])
	if gatewayPort == "" && clientIP == "" && clientPort == "" {
		return ""
	}
	parts := []string{"nat port-forward", protocol}
	if gatewayPort != "" {
		parts = append(parts, "gateway_port", gatewayPort)
	}
	if clientIP != "" {
		parts = append(parts, "client", clientIP)
	}
	if clientPort != "" {
		parts = append(parts, "client_port", clientPort)
	}
	if enabled != "" {
		parts = append(parts, "enabled", enabled)
	}
	return strings.Join(parts, " ")
}
