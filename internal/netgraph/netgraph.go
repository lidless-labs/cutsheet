// Package netgraph derives a network-state graph from configdiff analyses so a
// change's blast radius can be traced across devices, not just within one.
//
// ActiveGraph-inspired (see docs/design/activegraph-inspiration.md): cutsheet
// already extracts typed facts (interfaces, VLANs, routes, rules) per change but
// keeps them as flat lists with no edges. This package turns those facts into
// nodes and edges. It is a pure, rebuildable projection of the analysis, never a
// hand-authored source of truth.
//
// Cross-device links are INFERRED from shared keys (a VLAN id used on two
// devices, a route next-hop that is another device's address). cutsheet has no
// neighbor/topology ingestion (LLDP/CDP), so these bridges are heuristic; true
// topology-grade blast radius is a separate, larger workstream.
package netgraph

import (
	"sort"

	"github.com/solomonneas/cutsheet/pkg/configdiff"
)

// Node kinds.
const (
	KindDevice    = "device"
	KindInterface = "interface"
	KindVLAN      = "vlan"
	KindRoute     = "route"
	KindNextHop   = "nexthop"
	KindRule      = "rule"
)

// Edge types.
const (
	EdgeHasInterface = "has_interface"
	EdgeHasVLAN      = "has_vlan"
	EdgeHasRoute     = "has_route"
	EdgeHasRule      = "has_rule"
	EdgeNextHop      = "next_hop"
)

// Node is a vertex in the network-state graph. Device-scoped nodes are
// namespaced by device; VLAN and next-hop nodes are GLOBAL (id not namespaced)
// so the same VLAN id or next-hop IP on two devices resolves to one node, which
// is exactly what links devices for cross-device blast radius.
type Node struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Device string `json:"device,omitempty"`
	Label  string `json:"label"`
}

// Edge is an undirected-in-effect relationship; BlastRadius walks it both ways.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// Graph is a set of nodes and edges, deduplicated by id / (from,to,type).
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

func deviceScoped(device, kind, name string) string {
	return "device:" + device + "/" + kind + ":" + name
}

// Derive builds the graph fragment for a single device from its analysis.
func Derive(device string, analysis configdiff.Analysis) Graph {
	b := &builder{nodes: map[string]Node{}, edges: map[string]Edge{}}
	deviceID := KindDevice + ":" + device
	b.addNode(Node{ID: deviceID, Kind: KindDevice, Device: device, Label: device})

	for _, iface := range analysis.TouchedInterfaces {
		id := deviceScoped(device, KindInterface, iface.Name)
		b.addNode(Node{ID: id, Kind: KindInterface, Device: device, Label: iface.Name})
		b.addEdge(deviceID, id, EdgeHasInterface)
	}
	for _, vlan := range analysis.TouchedVLANs {
		// Global VLAN node: shared across devices that touch the same VLAN id.
		id := KindVLAN + ":" + vlan.ID
		b.addNode(Node{ID: id, Kind: KindVLAN, Label: "VLAN " + vlan.ID})
		b.addEdge(deviceID, id, EdgeHasVLAN)
	}
	for _, route := range analysis.TouchedRoutes {
		id := deviceScoped(device, KindRoute, route.Prefix)
		b.addNode(Node{ID: id, Kind: KindRoute, Device: device, Label: route.Prefix})
		b.addEdge(deviceID, id, EdgeHasRoute)
		if nh := route.AfterNextHop; nh != "" {
			// Global next-hop node: a route pointing at another device's
			// address links the two devices.
			nhID := KindNextHop + ":" + nh
			b.addNode(Node{ID: nhID, Kind: KindNextHop, Label: nh})
			b.addEdge(id, nhID, EdgeNextHop)
		}
	}
	for _, rule := range analysis.TouchedACLFirewallRules {
		id := deviceScoped(device, KindRule, rule.Name)
		b.addNode(Node{ID: id, Kind: KindRule, Device: device, Label: rule.Name})
		b.addEdge(deviceID, id, EdgeHasRule)
	}
	return b.graph()
}

// Merge unions several device graphs into one, deduplicating shared global
// nodes (VLANs, next-hops) so devices become connected through them.
func Merge(graphs ...Graph) Graph {
	b := &builder{nodes: map[string]Node{}, edges: map[string]Edge{}}
	for _, g := range graphs {
		for _, n := range g.Nodes {
			b.addNode(n)
		}
		for _, e := range g.Edges {
			b.addEdge(e.From, e.To, e.Type)
		}
	}
	return b.graph()
}

// BlastRadius returns the ids reachable from startID within maxDepth hops,
// treating edges as bidirectional. The start node is excluded from the result.
// maxDepth <= 0 means unbounded.
func BlastRadius(g Graph, startID string, maxDepth int) []string {
	adj := map[string][]string{}
	for _, e := range g.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	visited := map[string]bool{startID: true}
	frontier := []string{startID}
	var reached []string
	for depth := 0; len(frontier) > 0 && (maxDepth <= 0 || depth < maxDepth); depth++ {
		var next []string
		for _, id := range frontier {
			for _, nb := range adj[id] {
				if visited[nb] {
					continue
				}
				visited[nb] = true
				reached = append(reached, nb)
				next = append(next, nb)
			}
		}
		frontier = next
	}
	sort.Strings(reached)
	return reached
}

type builder struct {
	nodes map[string]Node
	edges map[string]Edge
}

func (b *builder) addNode(n Node) {
	if _, ok := b.nodes[n.ID]; !ok {
		b.nodes[n.ID] = n
	}
}

func (b *builder) addEdge(from, to, typ string) {
	key := from + "\x1f" + to + "\x1f" + typ
	if _, ok := b.edges[key]; !ok {
		b.edges[key] = Edge{From: from, To: to, Type: typ}
	}
}

func (b *builder) graph() Graph {
	nodes := make([]Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	edges := make([]Edge, 0, len(b.edges))
	for _, e := range b.edges {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Type < edges[j].Type
	})
	return Graph{Nodes: nodes, Edges: edges}
}
