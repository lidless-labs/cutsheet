package configdiff

type Options struct {
	BeforePath string
	AfterPath  string
	Vendor     string
	OutDir     string
}

type Result struct {
	OutDir   string
	Analysis Analysis
}

type Analysis struct {
	SchemaVersion            string             `json:"schema_version"`
	DetectedPlatform         DetectedPlatform   `json:"detected_platform"`
	BlockChanges             []BlockChange      `json:"block_changes"`
	TouchedInterfaces        []TouchedInterface `json:"touched_interfaces"`
	TouchedVLANs             []TouchedVLAN      `json:"touched_vlans"`
	TouchedRoutes            []TouchedRoute     `json:"touched_routes"`
	TouchedACLFirewallRules  []TouchedRule      `json:"touched_acl_firewall_rules"`
	TouchedNATObjects        []TouchedObject    `json:"touched_nat_objects"`
	TouchedVPNObjects        []TouchedObject    `json:"touched_vpn_objects"`
	ManagementPlaneChanges   []CategoryChange   `json:"management_plane_changes"`
	AAAChanges               []CategoryChange   `json:"aaa_changes"`
	LoggingSNMPNTPDNSChanges []CategoryChange   `json:"logging_snmp_ntp_dns_changes"`
	SwitchingChanges         []SwitchingChange    `json:"switching_changes"`
	TouchedRoutingPeers      []TouchedRoutingPeer `json:"touched_routing_peers"`
	RiskFindings             []RiskFinding        `json:"risk_findings"`
	Rollback                 RollbackAnalysis     `json:"rollback"`
}

// SwitchingChange captures a Layer 2 switching construct that changed between the
// before and after configs: switchport mode, trunk scope, native VLAN, spanning-tree,
// EtherChannel, VTP, or storm-control. It is additive to the typed VLAN/interface
// facts and models switching semantics those fields do not capture.
type SwitchingChange struct {
	Category   string   `json:"category"`
	Subject    string   `json:"subject"`
	ChangeType string   `json:"change_type"`
	Before     string   `json:"before,omitempty"`
	After      string   `json:"after,omitempty"`
	Evidence   []string `json:"evidence"`
}

// TouchedRoutingPeer captures a BGP or OSPF neighbor that was added, removed, or
// had a core parameter change (remote-AS for BGP, area for OSPF). Peers are extracted
// semantically from existing routing blocks rather than reshaping block IDs.
type TouchedRoutingPeer struct {
	Protocol   string   `json:"protocol"`
	Peer       string   `json:"peer"`
	LocalAS    string   `json:"local_as,omitempty"`
	RemoteAS   string   `json:"remote_as,omitempty"`
	Area       string   `json:"area,omitempty"`
	ChangeType string   `json:"change_type"`
	Before     string   `json:"before,omitempty"`
	After      string   `json:"after,omitempty"`
	Evidence   []string `json:"evidence"`
}

type DetectedPlatform struct {
	RequestedVendor string   `json:"requested_vendor"`
	Parser          string   `json:"parser"`
	DetectedVendor  string   `json:"detected_vendor"`
	DeviceType      string   `json:"device_type"`
	Confidence      float64  `json:"confidence"`
	Signals         []string `json:"signals"`
}

type BlockChange struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	ChangeType  string   `json:"change_type"`
	Header      string   `json:"header"`
	BeforeLines []string `json:"before_lines,omitempty"`
	AfterLines  []string `json:"after_lines,omitempty"`
}

type TouchedInterface struct {
	Name        string   `json:"name"`
	ChangeType  string   `json:"change_type"`
	BeforeLines []string `json:"before_lines,omitempty"`
	AfterLines  []string `json:"after_lines,omitempty"`
}

type TouchedVLAN struct {
	ID         string   `json:"id"`
	ChangeType string   `json:"change_type"`
	Evidence   []string `json:"evidence"`
}

type TouchedRoute struct {
	Prefix        string   `json:"prefix"`
	ChangeType    string   `json:"change_type"`
	BeforeNextHop string   `json:"before_next_hop,omitempty"`
	AfterNextHop  string   `json:"after_next_hop,omitempty"`
	Evidence      []string `json:"evidence"`
}

type TouchedRule struct {
	Name        string   `json:"name"`
	Action      string   `json:"action,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Source      string   `json:"source,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Service     string   `json:"service,omitempty"`
	ChangeType  string   `json:"change_type"`
	Evidence    []string `json:"evidence"`
}

type TouchedObject struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	ChangeType string   `json:"change_type"`
	Evidence   []string `json:"evidence"`
}

type CategoryChange struct {
	Category   string   `json:"category"`
	ChangeType string   `json:"change_type"`
	Evidence   []string `json:"evidence"`
}

type RiskFinding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Details        []string `json:"details"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
}

type RollbackAnalysis struct {
	Confidence string            `json:"confidence"`
	Summary    string            `json:"summary"`
	Snippets   []RollbackSnippet `json:"snippets"`
}

type RollbackSnippet struct {
	ChangeID             string   `json:"change_id"`
	Kind                 string   `json:"kind"`
	Header               string   `json:"header"`
	Lines                []string `json:"lines"`
	ExactReapply         []string `json:"exact_reapply,omitempty"`
	CandidateCommands    []string `json:"candidate_commands,omitempty"`
	ManualReviewRequired bool     `json:"manual_review_required"`
	Note                 string   `json:"note"`
}

type parsedConfig struct {
	Detection DetectedPlatform
	Blocks    []configBlock
}

type configBlock struct {
	ID     string
	Kind   string
	Header string
	Lines  []string
}
