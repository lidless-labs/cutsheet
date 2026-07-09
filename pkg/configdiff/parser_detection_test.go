package configdiff

import "testing"

func TestSelectParserVendorAliases(t *testing.T) {
	cases := map[string]string{
		"ubiquiti":            "*configdiff.edgeSwitchParser",
		"edgeswitch":          "*configdiff.edgeSwitchParser",
		"ubiquiti-edgeswitch": "*configdiff.edgeSwitchParser",
		"edgeos":              "*configdiff.edgeOSParser",
		"vyos":                "*configdiff.edgeOSParser",
		"usg":                 "*configdiff.edgeOSParser",
		"panos":               "*configdiff.panosParser",
		"palo-alto":           "*configdiff.panosParser",
		"pan-os":              "*configdiff.panosParser",
		"unifi":               "*configdiff.unifiJSONParser",
		"unifi-json":          "*configdiff.unifiJSONParser",
		"unifi-controller":    "*configdiff.unifiJSONParser",
		"eero":                "*configdiff.eeroJSONParser",
		"eero-json":           "*configdiff.eeroJSONParser",
		"cisco-ios":           "*configdiff.ciscoIOSParser",
		"junos":               "*configdiff.junosParser",
		"fortinet":            "*configdiff.fortinetParser",
		"generic":             "*configdiff.genericParser",
	}
	for vendor, want := range cases {
		p, err := selectParser(vendor, "")
		if err != nil {
			t.Fatalf("selectParser(%q) error: %v", vendor, err)
		}
		if got := typeName(p); got != want {
			t.Errorf("selectParser(%q) = %s, want %s", vendor, got, want)
		}
	}
}

func TestAutoDetectEdgeSwitchBeforeCisco(t *testing.T) {
	// An EdgeSwitch config also contains IOS-like tokens, so detection must prefer
	// the EdgeSwitch labeling over cisco-ios in the auto chain.
	text := "interface 0/1\n switchport access vlan 10\nvlan database\nvlan 10\nserviceport protocol none\nip route 0.0.0.0 0.0.0.0 198.18.0.1\n"
	p, err := selectParser("auto", text)
	if err != nil {
		t.Fatalf("selectParser auto error: %v", err)
	}
	parsed := p.Parse(text, "auto")
	if parsed.Detection.DetectedVendor != "ubiquiti" {
		t.Errorf("detected vendor = %q, want ubiquiti", parsed.Detection.DetectedVendor)
	}
	if parsed.Detection.Parser != "cisco-ios" {
		t.Errorf("parser = %q, want cisco-ios (EdgeSwitch rides the IOS parse path)", parsed.Detection.Parser)
	}
}

func TestAutoDetectEdgeOSNotJunosOrFortinet(t *testing.T) {
	// EdgeOS is set-style (could collide with Junos) and uses `set service ...` lines
	// (could collide with Fortinet). It must win over both in the auto chain.
	text := "set interfaces ethernet eth0 address 198.18.0.1/24\nset service gui http-port 80\nset service ssh port 22\nset service nat rule 5000 type masquerade\nset protocols static route 0.0.0.0/0 next-hop 198.18.0.254\nset firewall name WAN_IN default-action drop\n"
	p, err := selectParser("auto", text)
	if err != nil {
		t.Fatalf("selectParser auto error: %v", err)
	}
	if got := typeName(p); got != "*configdiff.edgeOSParser" {
		t.Fatalf("auto-detected %s, want edgeOSParser", got)
	}
	parsed := p.Parse(text, "auto")
	if parsed.Detection.Parser != "edgeos" || parsed.Detection.DetectedVendor != "ubiquiti" {
		t.Errorf("detection = %s/%s, want edgeos/ubiquiti", parsed.Detection.Parser, parsed.Detection.DetectedVendor)
	}
}

func TestClassifyEdgeOSSetLine(t *testing.T) {
	cases := []struct {
		line     string
		wantKind string
		wantID   string
	}{
		{"set interfaces ethernet eth0 address 198.18.0.1/24", "interface", "interface:eth0"},
		{"set interfaces ethernet eth1 vif 20 address 198.18.20.1/24", "vlan", "vlan:20"},
		{"set protocols static route 0.0.0.0/0 next-hop 198.18.0.254", "route", "route:0.0.0.0/0"},
		{"delete protocols static route 0.0.0.0/0 next-hop 198.18.0.254", "route", "route:0.0.0.0/0"},
		{"set firewall name WAN_IN rule 10 action accept", "acl", "acl:wan_in"},
		{"set service nat rule 5000 type masquerade", "nat", "nat:rule-5000"},
		{"set service ssh port 22", "management", "management:ssh"},
		{"set system login user admin authentication plaintext-password x", "aaa", "aaa:user-admin"},
		{"set service snmp community public", "observability", "observability:snmp"},
	}
	for _, tc := range cases {
		kind, id, _ := classifyEdgeOSSetLine(tc.line)
		if kind != tc.wantKind || id != tc.wantID {
			t.Errorf("classifyEdgeOSSetLine(%q) = (%q, %q), want (%q, %q)", tc.line, kind, id, tc.wantKind, tc.wantID)
		}
	}
}

func TestAutoDetectPANOSBeforeJunos(t *testing.T) {
	// PAN-OS is set-style and shares `set service`/`set address` with EdgeOS/Junos. Its
	// exclusive heads (rulebase, deviceconfig, zone, virtual-router) must win the auto chain.
	text := "set deviceconfig system hostname PA-1\nset zone trust network layer3 ethernet1/1\nset rulebase security rules R1 source any\nset rulebase security rules R1 action allow\nset network virtual-router default routing-table ip static-route D destination 0.0.0.0/0\n"
	p, err := selectParser("auto", text)
	if err != nil {
		t.Fatalf("selectParser auto error: %v", err)
	}
	if got := typeName(p); got != "*configdiff.panosParser" {
		t.Fatalf("auto-detected %s, want panosParser", got)
	}
	parsed := p.Parse(text, "auto")
	if parsed.Detection.Parser != "panos" || parsed.Detection.DetectedVendor != "paloalto" {
		t.Errorf("detection = %s/%s, want panos/paloalto", parsed.Detection.Parser, parsed.Detection.DetectedVendor)
	}
}

func TestClassifyPANOSSetLine(t *testing.T) {
	cases := []struct {
		line     string
		wantKind string
		wantID   string
	}{
		{"set rulebase security rules ALLOW-WEB action allow", "firewall", "firewall:allow-web"},
		{"set rulebase nat rules SNAT-OUT source-translation x", "nat", "nat:snat-out"},
		{"set address NET-INTERNAL ip-netmask 198.18.0.0/8", "firewall", "firewall:addr-net-internal"},
		{"set zone trust network layer3 ethernet1/2", "interface", "interface:zone-trust"},
		{"set network virtual-router default routing-table ip static-route DEFAULT destination 0.0.0.0/0", "route", "route:default"},
		{"set mgt-config users admin permissions role-based superuser yes", "aaa", "aaa:user-admin"},
		{"set deviceconfig system snmp-setting access-setting version v2c", "observability", ""},
	}
	for _, tc := range cases {
		kind, id, _ := classifyPANOSSetLine(tc.line)
		if kind != tc.wantKind {
			t.Errorf("classifyPANOSSetLine(%q) kind = %q, want %q", tc.line, kind, tc.wantKind)
		}
		if tc.wantID != "" && id != tc.wantID {
			t.Errorf("classifyPANOSSetLine(%q) id = %q, want %q", tc.line, id, tc.wantID)
		}
	}
}

func TestAutoDetectUnifiJSONFirst(t *testing.T) {
	text := "{\"networkconf\":[{\"_id\":\"n1\",\"name\":\"Corp\",\"vlan\":10}],\"port_overrides\":[{\"port_idx\":1,\"native_networkconf_id\":\"n1\"}]}"
	p, err := selectParser("auto", text)
	if err != nil {
		t.Fatalf("selectParser auto error: %v", err)
	}
	if got := typeName(p); got != "*configdiff.unifiJSONParser" {
		t.Fatalf("auto-detected %s, want unifiJSONParser", got)
	}
	parsed := p.Parse(text, "auto")
	if parsed.Detection.Parser != "unifi-json" || parsed.Detection.DetectedVendor != "ubiquiti" {
		t.Errorf("detection = %s/%s, want unifi-json/ubiquiti", parsed.Detection.Parser, parsed.Detection.DetectedVendor)
	}
}

func TestAutoDetectEeroJSON(t *testing.T) {
	text := `{"eeros":[{"url":"/2.2/eeros/11","serial":"S1111111111111","mac_address":"00:00:5E:00:53:01","gateway":true}],"forwards":[],"network":{"url":"/2.2/networks/1","name":"Lab Mesh","upnp":false},"profiles":[],"reservations":[]}`
	p, err := selectParser("auto", text)
	if err != nil {
		t.Fatalf("selectParser auto error: %v", err)
	}
	parsed := p.Parse(text, "auto")
	if parsed.Detection.Parser != "eero-json" || parsed.Detection.DetectedVendor != "eero" {
		t.Errorf("detection = %s/%s, want eero-json/eero", parsed.Detection.Parser, parsed.Detection.DetectedVendor)
	}
	if parsed.Detection.DeviceType != "mesh" {
		t.Errorf("device type = %q, want mesh", parsed.Detection.DeviceType)
	}
}

func TestUnifiJSONStillDetectsAsUnifi(t *testing.T) {
	text := `{"networkconf":[{"_id":"n1","name":"Corp","vlan":10}],"port_overrides":[{"port_idx":1,"native_networkconf_id":"n1"}],"forwards":[{"description":"not an eero export"}]}`
	p, err := selectParser("auto", text)
	if err != nil {
		t.Fatalf("selectParser auto error: %v", err)
	}
	parsed := p.Parse(text, "auto")
	if parsed.Detection.Parser != "unifi-json" || parsed.Detection.DetectedVendor != "ubiquiti" {
		t.Errorf("detection = %s/%s, want unifi-json/ubiquiti", parsed.Detection.Parser, parsed.Detection.DetectedVendor)
	}
}

func TestEeroDetectorLeavesGenericTextAlone(t *testing.T) {
	text := "operator note: add a forward, remove a reservation, and check the eero node inventory\n"
	p, err := selectParser("auto", text)
	if err != nil {
		t.Fatalf("selectParser auto error: %v", err)
	}
	parsed := p.Parse(text, "auto")
	if parsed.Detection.Parser != "generic" || parsed.Detection.DetectedVendor != "generic" {
		t.Errorf("detection = %s/%s, want generic/generic", parsed.Detection.Parser, parsed.Detection.DetectedVendor)
	}
}

func TestUnifiJSONStableAcrossArrayOrder(t *testing.T) {
	// Reordering array entries must not change the analysis: block IDs key on stable
	// content (name/_id/port_idx), not array index.
	a := "{\"networkconf\":[{\"_id\":\"n1\",\"name\":\"Corp\",\"vlan\":10},{\"_id\":\"n2\",\"name\":\"IoT\",\"vlan\":30}]}"
	b := "{\"networkconf\":[{\"_id\":\"n2\",\"name\":\"IoT\",\"vlan\":30},{\"_id\":\"n1\",\"name\":\"Corp\",\"vlan\":10}]}"
	pa := unifiJSONParser{}.Parse(a, "unifi")
	pb := unifiJSONParser{}.Parse(b, "unifi")
	changes := diffBlocks(pa.Blocks, pb.Blocks)
	if len(changes) != 0 {
		t.Fatalf("reordering array entries produced %d changes, want 0", len(changes))
	}
}

func TestUnifiNonJSONFallback(t *testing.T) {
	// An explicit --vendor unifi against non-JSON text must not panic; it degrades to a
	// low-confidence generic parse rather than claiming a UniFi parse.
	parsed := unifiJSONParser{}.Parse("interface GigabitEthernet0/1\n switchport mode access\n", "unifi")
	if parsed.Detection.Parser != "unifi-json" {
		t.Errorf("parser = %q, want unifi-json", parsed.Detection.Parser)
	}
	if parsed.Detection.Confidence != 0.30 {
		t.Errorf("confidence = %v, want 0.30 for non-JSON fallback", parsed.Detection.Confidence)
	}
}

func typeName(v any) string {
	switch v.(type) {
	case edgeSwitchParser:
		return "*configdiff.edgeSwitchParser"
	case edgeOSParser:
		return "*configdiff.edgeOSParser"
	case panosParser:
		return "*configdiff.panosParser"
	case unifiJSONParser:
		return "*configdiff.unifiJSONParser"
	case eeroJSONParser:
		return "*configdiff.eeroJSONParser"
	case ciscoIOSParser:
		return "*configdiff.ciscoIOSParser"
	case junosParser:
		return "*configdiff.junosParser"
	case fortinetParser:
		return "*configdiff.fortinetParser"
	case genericParser:
		return "*configdiff.genericParser"
	default:
		return "unknown"
	}
}
