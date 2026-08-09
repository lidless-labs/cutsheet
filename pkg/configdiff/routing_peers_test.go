package configdiff

import (
	"path/filepath"
	"testing"
)

func TestBGPPeerAddedRemovedAndRemoteASChanged(t *testing.T) {
	before := `
hostname lab-r1
router bgp 65001
 neighbor 198.18.1.2 remote-as 65002
 neighbor 198.18.1.3 remote-as 65003
 neighbor 198.18.1.4 remote-as 65004
`
	after := `
hostname lab-r1
router bgp 65001
 neighbor 198.18.1.2 remote-as 65099
 neighbor 198.18.1.3 remote-as 65003
 neighbor 198.18.1.5 remote-as 65005
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}

	peers := indexRoutingPeers(analysis.TouchedRoutingPeers)
	assertPeer(t, peers, "bgp", "198.18.1.5", "added", "65001", "65005", "")
	assertPeer(t, peers, "bgp", "198.18.1.4", "removed", "65001", "65004", "")
	assertPeer(t, peers, "bgp", "198.18.1.2", "changed", "65001", "65099", "")

	wantRisks := []string{
		"BGP neighbor added",
		"BGP neighbor removed",
		"BGP remote-AS changed",
	}
	for _, title := range wantRisks {
		finding := riskByTitle(analysis.RiskFindings, title)
		if finding == nil {
			t.Fatalf("missing risk %q in %#v", title, analysis.RiskFindings)
		}
		if finding.Severity != "high" {
			t.Fatalf("%s severity = %q, want high", title, finding.Severity)
		}
		if finding.Category != "routing" {
			t.Fatalf("%s category = %q, want routing", title, finding.Category)
		}
	}
	if hasRisk(analysis.RiskFindings, "BGP neighbor added") {
		added := riskByTitle(analysis.RiskFindings, "BGP neighbor added")
		if !containsString(added.Evidence, "neighbor 198.18.1.5 remote-as 65005") {
			t.Fatalf("added peer evidence missing: %#v", added.Evidence)
		}
	}
}

func TestOSPFPeerAddedAndRemoved(t *testing.T) {
	before := `
hostname lab-r1
router ospf 1
 neighbor 198.18.2.2
 neighbor 198.18.2.3
 network 198.18.0.0 0.0.255.255 area 0
`
	after := `
hostname lab-r1
router ospf 1
 neighbor 198.18.2.2
 neighbor 198.18.2.4
 network 198.18.0.0 0.0.255.255 area 0
`
	analysis, err := AnalyzeContent(before, after, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}

	peers := indexRoutingPeers(analysis.TouchedRoutingPeers)
	assertPeer(t, peers, "ospf", "198.18.2.4", "added", "", "", "0")
	assertPeer(t, peers, "ospf", "198.18.2.3", "removed", "", "", "0")

	for _, title := range []string{"OSPF neighbor added", "OSPF neighbor removed"} {
		finding := riskByTitle(analysis.RiskFindings, title)
		if finding == nil {
			t.Fatalf("missing risk %q in %#v", title, analysis.RiskFindings)
		}
		if finding.Severity != "high" || finding.Category != "routing" {
			t.Fatalf("%s: severity=%q category=%q", title, finding.Severity, finding.Category)
		}
	}
}

func TestEdgeOSBGPPeerChanges(t *testing.T) {
	before := `
set protocols bgp 65001 neighbor 198.18.10.2 remote-as 65002
set protocols bgp 65001 neighbor 198.18.10.3 remote-as 65003
`
	after := `
set protocols bgp 65001 neighbor 198.18.10.2 remote-as 65022
set protocols bgp 65001 neighbor 198.18.10.4 remote-as 65004
`
	analysis, err := AnalyzeContent(before, after, "edgeos")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}

	peers := indexRoutingPeers(analysis.TouchedRoutingPeers)
	assertPeer(t, peers, "bgp", "198.18.10.2", "changed", "65001", "65022", "")
	assertPeer(t, peers, "bgp", "198.18.10.3", "removed", "65001", "65003", "")
	assertPeer(t, peers, "bgp", "198.18.10.4", "added", "65001", "65004", "")

	if riskByTitle(analysis.RiskFindings, "BGP remote-AS changed") == nil {
		t.Fatalf("expected BGP remote-AS changed finding: %#v", analysis.RiskFindings)
	}
}

func TestRoutingPeersUnchangedAreSilent(t *testing.T) {
	cfg := `
hostname lab-r1
router bgp 65001
 neighbor 198.18.1.2 remote-as 65002
router ospf 1
 neighbor 198.18.2.2
`
	analysis, err := AnalyzeContent(cfg, cfg, "cisco-ios")
	if err != nil {
		t.Fatalf("AnalyzeContent: %v", err)
	}
	if len(analysis.TouchedRoutingPeers) != 0 {
		t.Fatalf("unchanged peers must not appear: %#v", analysis.TouchedRoutingPeers)
	}
	for _, title := range []string{
		"BGP neighbor added",
		"BGP neighbor removed",
		"BGP remote-AS changed",
		"OSPF neighbor added",
		"OSPF neighbor removed",
	} {
		if hasRisk(analysis.RiskFindings, title) {
			t.Fatalf("unchanged config must not emit %q", title)
		}
	}
}

func TestBGPPeerFixtureGolden(t *testing.T) {
	result, err := Explain(Options{
		BeforePath: filepath.Join("..", "..", "testdata", "bgp-peers-before.cfg"),
		AfterPath:  filepath.Join("..", "..", "testdata", "bgp-peers-after.cfg"),
		Vendor:     "auto",
		OutDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(result.Analysis.TouchedRoutingPeers) < 3 {
		t.Fatalf("expected at least 3 peer changes, got %#v", result.Analysis.TouchedRoutingPeers)
	}
	for _, title := range []string{"BGP neighbor added", "BGP neighbor removed", "BGP remote-AS changed"} {
		if !hasRisk(result.Analysis.RiskFindings, title) {
			t.Fatalf("missing risk %q", title)
		}
	}
}

func TestParseCiscoBGPNeighbors(t *testing.T) {
	lines := []string{
		"router bgp 65001",
		"neighbor 198.18.1.2 remote-as 65002",
		"neighbor 198.18.1.2 description uplink",
		"neighbor 198.18.1.3 remote-as 65003",
	}
	peers := parseRoutingPeersFromLines(lines, "router bgp 65001")
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want 2: %#v", len(peers), peers)
	}
	p := peers["bgp|198.18.1.2"]
	if p.LocalAS != "65001" || p.RemoteAS != "65002" {
		t.Fatalf("peer AS fields wrong: %#v", p)
	}
}

func indexRoutingPeers(peers []TouchedRoutingPeer) map[string]TouchedRoutingPeer {
	out := map[string]TouchedRoutingPeer{}
	for _, peer := range peers {
		out[peer.Protocol+"|"+peer.Peer] = peer
	}
	return out
}

func assertPeer(t *testing.T, peers map[string]TouchedRoutingPeer, protocol, addr, changeType, localAS, remoteAS, area string) {
	t.Helper()
	peer, ok := peers[protocol+"|"+addr]
	if !ok {
		t.Fatalf("missing peer %s %s in %#v", protocol, addr, peers)
	}
	if peer.ChangeType != changeType {
		t.Fatalf("%s %s change_type=%q want %q", protocol, addr, peer.ChangeType, changeType)
	}
	if localAS != "" && peer.LocalAS != localAS {
		t.Fatalf("%s %s local_as=%q want %q", protocol, addr, peer.LocalAS, localAS)
	}
	if remoteAS != "" && peer.RemoteAS != remoteAS {
		t.Fatalf("%s %s remote_as=%q want %q", protocol, addr, peer.RemoteAS, remoteAS)
	}
	if area != "" && peer.Area != area {
		t.Fatalf("%s %s area=%q want %q", protocol, addr, peer.Area, area)
	}
	if len(peer.Evidence) == 0 {
		t.Fatalf("%s %s missing evidence", protocol, addr)
	}
}
