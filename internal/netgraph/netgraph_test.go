package netgraph

import (
	"testing"

	"github.com/solomonneas/cutsheet/pkg/configdiff"
)

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// TestCrossDeviceBlastRadius is the whole point: two devices that touch the same
// VLAN id become connected through the global VLAN node, so a change to that
// VLAN has a blast radius that spans both devices.
func TestCrossDeviceBlastRadius(t *testing.T) {
	edgeA := configdiff.Analysis{
		TouchedInterfaces: []configdiff.TouchedInterface{{Name: "gi0/1"}},
		TouchedVLANs:      []configdiff.TouchedVLAN{{ID: "10"}},
		TouchedRoutes:     []configdiff.TouchedRoute{{Prefix: "198.51.100.0/24", AfterNextHop: "192.0.2.1"}},
	}
	edgeB := configdiff.Analysis{
		TouchedInterfaces: []configdiff.TouchedInterface{{Name: "gi0/2"}},
		TouchedVLANs:      []configdiff.TouchedVLAN{{ID: "10"}},
	}

	g := Merge(Derive("edge-a", edgeA), Derive("edge-b", edgeB))

	// The shared VLAN node exists once and both devices link to it.
	vlanNodes := 0
	for _, n := range g.Nodes {
		if n.ID == "vlan:10" {
			vlanNodes++
		}
	}
	if vlanNodes != 1 {
		t.Fatalf("expected exactly one global vlan:10 node, got %d", vlanNodes)
	}

	// One hop from the VLAN reaches exactly the two devices.
	oneHop := BlastRadius(g, "vlan:10", 1)
	if len(oneHop) != 2 || !contains(oneHop, "device:edge-a") || !contains(oneHop, "device:edge-b") {
		t.Fatalf("one-hop blast radius of vlan:10 = %v, want the two devices", oneHop)
	}

	// Unbounded, the blast radius crosses into edge-b's own interface.
	full := BlastRadius(g, "vlan:10", 0)
	if !contains(full, "device:edge-b/interface:gi0/2") {
		t.Fatalf("cross-device blast radius missing edge-b's interface: %v", full)
	}

	// The route -> next-hop edge is present and reachable.
	fromNextHop := BlastRadius(g, "nexthop:192.0.2.1", 0)
	if !contains(fromNextHop, "device:edge-a/route:198.51.100.0/24") {
		t.Fatalf("next-hop node not linked to its route: %v", fromNextHop)
	}
}

// TestDeriveIsDeterministic guards the projection: same analysis in, same graph
// out (nodes and edges sorted, deduped).
func TestDeriveIsDeterministic(t *testing.T) {
	a := configdiff.Analysis{
		TouchedVLANs: []configdiff.TouchedVLAN{{ID: "10"}, {ID: "10"}},
	}
	g1 := Derive("d1", a)
	g2 := Derive("d1", a)
	if len(g1.Nodes) != len(g2.Nodes) || len(g1.Edges) != len(g2.Edges) {
		t.Fatalf("derive not deterministic")
	}
	// Duplicate VLAN id collapses to one global node (plus the device node).
	if len(g1.Nodes) != 2 {
		t.Fatalf("expected device + one vlan node, got %d", len(g1.Nodes))
	}
}
