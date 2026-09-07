package configdiff

import (
	"path/filepath"
	"testing"
)

func TestCatalystSwitchingSemantics(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "catalyst-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "catalyst-after.cfg"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}

	wantCategories := map[string]bool{
		"switchport_mode": false,
		"trunk":           false,
		"native_vlan":     false,
		"spanning_tree":   false,
		"etherchannel":    false,
		"vtp":             false,
		"storm_control":   false,
	}
	for _, sc := range result.Analysis.SwitchingChanges {
		if _, ok := wantCategories[sc.Category]; ok {
			wantCategories[sc.Category] = true
		}
	}
	for category, found := range wantCategories {
		if !found {
			t.Errorf("expected a switching change of category %q, found none", category)
		}
	}

	wantRisks := []string{
		"Switchport mode changed",
		"Trunk carries all VLANs",
		"Trunk native VLAN changed",
		"BPDU protection reduced or PortFast on trunk",
		"EtherChannel membership or mode changed",
		"Spanning-tree mode changed",
		"Spanning-tree root or priority changed",
		"VTP mode or domain changed",
		"Storm-control reduced or removed",
	}
	got := map[string]bool{}
	for _, r := range result.Analysis.RiskFindings {
		got[r.Title] = true
	}
	for _, want := range wantRisks {
		if !got[want] {
			t.Errorf("expected risk finding %q, not found", want)
		}
	}
}

func TestSwitchingDetectorsAreSpecific(t *testing.T) {
	// A trunk that only narrows its allowed VLAN list must not trigger the
	// "carries all VLANs" risk, and an unchanged mode must not flag a mode change.
	before := []string{"switchport mode trunk", "switchport trunk allowed vlan 10,20,30"}
	after := []string{"switchport mode trunk", "switchport trunk allowed vlan 10,30"}
	if trunkCarriesAllVLANs(before, after) {
		t.Error("narrowing a trunk should not be flagged as carrying all VLANs")
	}
	if switchportMode(firstMatch(before, isSwitchportModeLine)) != switchportMode(firstMatch(after, isSwitchportModeLine)) {
		t.Error("unchanged switchport mode should compare equal")
	}

	// Removing BPDU guard is a reduction in protection.
	if !bpduProtectionReducedOrPortfastTrunk([]string{"spanning-tree bpduguard enable"}, []string{}) {
		t.Error("removing bpduguard should be flagged")
	}
	// PortFast on an access port is normal and must not be flagged as portfast-on-trunk.
	if bpduProtectionReducedOrPortfastTrunk([]string{}, []string{"switchport mode access", "spanning-tree portfast"}) {
		t.Error("portfast on an access port should not be flagged")
	}
}

func TestSpanningTreeEnabledDetectorsRejectNegatedCommands(t *testing.T) {
	if bpduProtectionReducedOrPortfastTrunk(nil, []string{"switchport mode trunk", "no spanning-tree portfast"}) {
		t.Fatal("negated PortFast on a trunk must not be treated as PortFast enabled")
	}
	if anyLine([]string{"no spanning-tree bpduguard enable"}, isBpduGuardEnableLine) {
		t.Fatal("negated BPDU guard must not be treated as BPDU guard enabled")
	}
	if isPortfastLine("no spanning-tree portfast") || isBpduGuardLine("no spanning-tree bpduguard enable") || isStpGuardLine("no spanning-tree guard root") {
		t.Fatal("negated spanning-tree commands must not be enabled-state facts")
	}
	changes := switchingChanges([]BlockChange{{
		ID:          "interface:GigabitEthernet1/0/1",
		ChangeType:  "changed",
		BeforeLines: []string{"spanning-tree portfast"},
		AfterLines:  []string{"no spanning-tree portfast"},
	}})
	if len(changes) != 1 || changes[0].After != "no spanning-tree portfast" {
		t.Fatalf("negated PortFast removal must remain tracked: %#v", changes)
	}
}
