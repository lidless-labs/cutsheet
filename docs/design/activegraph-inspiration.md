# ActiveGraph inspiration: pre-flight fork + network-state graph

Part of a fleet-wide effort inspired by Yohei Nakajima's
[ActiveGraph](https://github.com/yoheinakajima/activegraph). Master notes:
`~/notes/activegraph-credits.md`. ActiveGraph is a reference architecture only;
no code from it is vendored or depended on here.

## What we borrowed

- **Fork a candidate before committing it.** ActiveGraph forks a run to explore a
  branch without disturbing the parent (`fork_run`, `store/sqlite.py`). The
  network analogue is: evaluate a candidate config against the running one and
  see the blast radius *before* you apply it.
- **Turn flat facts into a graph.** ActiveGraph's world is nodes and edges you
  can traverse. cutsheet already extracts typed facts (interfaces, VLANs, routes,
  rules) but kept them as flat lists with no edges, so "what else does this
  touch?" could not be answered across devices.

## What landed in cutsheet

- **`configdiff.AnalyzeContent(before, after, vendor)`** — a pure, in-memory
  analysis with no file or report I/O, extracted from `Explain` (which now calls
  it and then persists). This is the seam that makes a candidate config
  inspectable without side effects.
- **`cutsheet preflight --current <cfg> --candidate <cfg>`** — runs the analyzer
  on a candidate and prints the risk findings + rollback confidence, writing
  **nothing** (no report dir, no `changes` row, no git commit). The "cut sheet"
  made safe.
- **`internal/netgraph`** — derives a network-state graph from an analysis:
  device / interface / VLAN / route / next-hop / rule nodes with edges. VLAN and
  next-hop nodes are **global** (not device-namespaced), so two devices that
  touch the same VLAN id (or a route pointing at another device's address) become
  connected through a shared node. `BlastRadius(graph, nodeID, depth)` then walks
  that graph, giving **cross-device** blast radius, which the flat fact lists
  could never express.

The payoff for the flagship: the two things it most needed. You can pre-flight a
change safely, and you can ask "if I pull VLAN 10, what does it touch?" and get an
answer that crosses device boundaries.

## What we did differently, and why

- **Graph is a pure, rebuildable projection of the analysis, never stored truth.**
  It is derived from `Analysis` (itself already persisted as `analysis_json`), so
  it can always be rebuilt and can never disagree with the recorded findings.
- **Cross-device edges are inferred from shared keys, and we say so.** cutsheet has
  no neighbor/topology ingestion (LLDP/CDP/ARP), so devices are bridged only by
  shared VLAN ids and next-hop IPs. That is heuristic. True topology-grade blast
  radius needs a collector-side neighbor-discovery workstream and is explicitly
  out of scope here. The package documents this at the top so no one mistakes the
  inference for measured topology.
- **Pre-flight, not a persisted fork.** cutsheet's real fork is cheap because git
  + the pure `AnalyzeContent` already let you diff arbitrary content; a candidate
  never needs to be committed to be analyzed. So the "fork" is a read-only
  evaluation rather than a copied branch of stored state.

## Deferred (next cutsheet slice)

Two pieces from the original plan are intentionally left for a follow-up, to keep
this change tight and fully tested:

- **Persisting the graph** to new SQLite tables (`graph_nodes`/`graph_edges` via a
  `0003_netgraph.sql` migration + `ReplaceDeviceGraph`) and a `graph` query
  command. The derivation and traversal are done and tested; only persistence and
  a CLI surface remain.
- **Typed event stream + `replay`** (`ConfigSnapshotted`/`ChangeAnalyzed`/
  `FindingRaised` + re-run the analyzer over commit history on upgrade). cutsheet's
  git snapshots + insert-only `changes` are already an immutable log, so this is
  lower urgency than the graph and the pre-flight.

## Feedback worth sending Yohei

cutsheet shows the "fork" primitive is most valuable when the substrate is already
content-addressed (git snapshots) and the analysis is a pure function: you don't
need to copy state to fork it, you just analyze the candidate against HEAD. And
the graph layer is a reminder that turning flat domain facts into ActiveGraph-style
nodes/edges is where cross-entity questions (blast radius) become answerable, but
only as well as your edges are grounded, ours are inferred from shared keys, and
being explicit about that is important so a heuristic graph is not read as truth.
