package configdiff

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func writeHTMLReport(outDir string, analysis Analysis) error {
	if err := os.WriteFile(filepath.Join(outDir, "report.html"), []byte(renderHTMLReport(analysis)), 0o600); err != nil {
		return fmt.Errorf("write report.html: %w", err)
	}
	return nil
}

func renderHTMLReport(a Analysis) string {
	counts := severityCounts(a.RiskFindings)
	var b strings.Builder
	writeHTMLDocumentStart(&b)
	writeHTMLHeader(&b, a)
	writeHTMLMetrics(&b, a, counts)
	writeHTMLReportNav(&b)
	b.WriteString(`<section class="layout">`)
	writeHTMLRiskPanel(&b, a.RiskFindings)
	writeHTMLChangePanel(&b, a.BlockChanges)
	b.WriteString(`</section>`)
	writeHTMLTouchedObjects(&b, a)
	writeHTMLRollback(&b, a.Rollback)
	writeHTMLValidationAndChecklist(&b, a)
	writeHTMLScript(&b)
	writeHTMLDocumentEnd(&b)
	return b.String()
}

func writeHTMLDocumentStart(b *strings.Builder) {
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cutsheet Change Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8f5;
      --ink: #17211c;
      --muted: #5d6b62;
      --line: #d9dfd8;
      --panel: #ffffff;
      --panel-2: #eff4ee;
      --accent: #18745a;
      --accent-soft: #dcebe5;
      --danger: #b42318;
      --warn: #b7791f;
      --low: #23864d;
      --code: #16231e;
      --code-line: #22332c;
      --add: #dff4e8;
      --remove: #fae2df;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    main {
      width: min(1280px, calc(100vw - 48px));
      margin: 0 auto;
      padding: 32px 0 44px;
    }
    header {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 20px;
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: 34px; line-height: 1.08; font-weight: 760; }
    h2 { font-size: 20px; line-height: 1.2; }
    h3 { font-size: 15px; line-height: 1.3; }
    a { color: inherit; }
    .subtle { color: var(--muted); }
    .meta, .nav, .filter-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .meta { justify-content: flex-end; }
    .pill, .tag, .nav a, button {
      border: 1px solid var(--line);
      border-radius: 999px;
      background: var(--panel);
      color: var(--muted);
      font-size: 13px;
      white-space: nowrap;
    }
    .pill { display: inline-flex; align-items: center; padding: 7px 11px; }
    .tag { padding: 4px 8px; align-self: start; }
    .nav { margin: 0 0 18px; }
    .nav a {
      text-decoration: none;
      padding: 8px 12px;
    }
    .nav a:hover, button:hover { border-color: var(--accent); color: var(--accent); }
    button {
      cursor: pointer;
      padding: 8px 12px;
      font: inherit;
    }
    input, select {
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      color: var(--ink);
      font: inherit;
      font-size: 13px;
      padding: 7px 10px;
    }
    input { min-width: 220px; flex: 1; }
    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .metric, .panel, .risk, .change, .object-card, .snippet {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .metric { padding: 13px; min-height: 88px; }
    .metric .label {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }
    .metric .value {
      font-size: 30px;
      line-height: 1;
      font-weight: 760;
      overflow-wrap: anywhere;
    }
    .layout {
      display: grid;
      grid-template-columns: minmax(330px, 0.85fr) minmax(600px, 1.15fr);
      gap: 18px;
      align-items: start;
    }
    .panel { overflow: hidden; margin-bottom: 18px; }
    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 16px 18px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-2);
    }
    .panel-body { padding: 16px 18px 18px; }
    .risk-list, .change-list, .snippet-list { display: grid; gap: 12px; }
    .risk {
      display: grid;
      grid-template-columns: 76px minmax(0, 1fr);
      gap: 12px;
      padding: 13px;
    }
    .severity {
      align-self: start;
      width: 68px;
      border-radius: 999px;
      padding: 5px 8px;
      text-align: center;
      font-size: 12px;
      font-weight: 720;
      text-transform: uppercase;
    }
    .high { color: #fff; background: var(--danger); }
    .medium { color: #221100; background: #f5d28a; }
    .low { color: #fff; background: var(--low); }
    .risk-title { font-weight: 730; margin-bottom: 5px; }
    .risk-detail, .evidence, .details, .small-list {
      color: var(--muted);
      font-size: 13px;
      line-height: 1.4;
    }
    .details, .evidence { margin-top: 8px; }
    .details div, .evidence div { margin-top: 3px; }
    .change { overflow: hidden; }
    .change-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 13px 14px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-2);
    }
    .change-title { display: grid; gap: 3px; min-width: 0; }
    .change-title h3 { overflow-wrap: anywhere; }
    .diff {
      display: grid;
      grid-template-columns: 1fr 1fr;
    }
    .side + .side { border-left: 1px solid var(--line); }
    .side-label {
      padding: 8px 12px;
      color: var(--muted);
      border-bottom: 1px solid var(--line);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      background: #fbfcfa;
    }
    pre {
      margin: 0;
      min-height: 96px;
      overflow-x: auto;
      white-space: pre-wrap;
      font: 12.5px/1.5 "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      color: #e8f3ed;
      background: var(--code);
    }
    .line { display: block; padding: 0 12px; min-height: 18px; }
    .line:first-child { padding-top: 12px; }
    .line:last-child { padding-bottom: 12px; }
    .line.added { background: rgb(46 160 92 / 24%); }
    .line.removed { background: rgb(216 73 57 / 25%); }
    .empty { color: #8fa096; font-style: italic; padding: 12px; display: block; }
    .object-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }
    .object-card { padding: 13px; min-height: 112px; }
    .object-card h3 { margin-bottom: 8px; }
    .small-list { display: grid; gap: 5px; }
    .small-list div { overflow-wrap: anywhere; }
    .snippet { overflow: hidden; }
    .snippet summary {
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 13px 14px;
      background: var(--panel-2);
      border-bottom: 1px solid var(--line);
      font-weight: 700;
    }
    .snippet-body { padding: 13px 14px 14px; display: grid; gap: 12px; }
    .checklist {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    ul { margin: 0; padding-left: 18px; }
    li + li { margin-top: 7px; }
    .hidden { display: none; }
    .count-note { font-size: 13px; color: var(--muted); margin-left: auto; }
    @media (max-width: 980px) {
      main { width: min(100vw - 28px, 760px); padding-top: 20px; }
      header, .layout { display: grid; grid-template-columns: 1fr; }
      .meta { justify-content: flex-start; }
      .metrics, .object-grid, .checklist { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .diff { grid-template-columns: 1fr; }
      .side + .side { border-left: 0; border-top: 1px solid var(--line); }
    }
    @media (max-width: 640px) {
      .metrics, .object-grid, .checklist { grid-template-columns: 1fr; }
      .risk { grid-template-columns: 1fr; }
      .severity { width: max-content; }
      input, select, button { width: 100%; }
    }
  </style>
</head>
<body>
  <main>
`)
}

func writeHTMLHeader(b *strings.Builder, a Analysis) {
	b.WriteString(`    <header>
      <div>
        <h1>Cutsheet Change Report</h1>
        <div class="subtle">Offline deterministic review of before and after network configs.</div>
      </div>
      <div class="meta">`)
	fmt.Fprintf(b, `<span class="pill">Parser: %s</span>`, e(a.DetectedPlatform.Parser))
	fmt.Fprintf(b, `<span class="pill">Vendor: %s</span>`, e(a.DetectedPlatform.DetectedVendor))
	fmt.Fprintf(b, `<span class="pill">Device: %s</span>`, e(a.DetectedPlatform.DeviceType))
	fmt.Fprintf(b, `<span class="pill">Confidence: %.2f</span>`, a.DetectedPlatform.Confidence)
	b.WriteString(`</div>
    </header>
`)
}

func writeHTMLMetrics(b *strings.Builder, a Analysis, counts map[string]int) {
	b.WriteString(`    <section class="metrics" aria-label="Summary metrics">`)
	writeMetric(b, "Blocks", fmt.Sprint(len(a.BlockChanges)))
	writeMetric(b, "High", fmt.Sprint(counts["high"]))
	writeMetric(b, "Medium", fmt.Sprint(counts["medium"]))
	writeMetric(b, "Low", fmt.Sprint(counts["low"]))
	writeMetric(b, "Touched", fmt.Sprint(touchedObjectTotal(a)))
	writeMetric(b, "Rollback", a.Rollback.Confidence)
	b.WriteString(`</section>
`)
}

func writeHTMLReportNav(b *strings.Builder) {
	b.WriteString(`    <nav class="nav" aria-label="Report sections">
      <a href="#risks">Risks</a>
      <a href="#changes">Changed Blocks</a>
      <a href="#touched">Touched Objects</a>
      <a href="#rollback">Rollback</a>
      <a href="#validation">Validation</a>
    </nav>
`)
}

func writeHTMLRiskPanel(b *strings.Builder, risks []RiskFinding) {
	b.WriteString(`      <article class="panel" id="risks">
        <div class="panel-head">
          <h2>Risk Findings</h2>`)
	fmt.Fprintf(b, `<span class="tag" id="risk-count">%d total</span>`, len(risks))
	b.WriteString(`</div>
        <div class="panel-body">
          <div class="filter-row" aria-label="Risk filters">
            <input id="risk-search" type="search" placeholder="Search risks, evidence, recommendations">
            <select id="risk-severity">
              <option value="">All severities</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button type="button" id="risk-reset">Reset</button>
          </div>
          <div class="risk-list" style="margin-top:12px;">`)
	if len(risks) == 0 {
		b.WriteString(`<div class="subtle">No deterministic risk findings were detected.</div>`)
	}
	for _, risk := range risks {
		searchText := strings.Join(append(append([]string{risk.ID, risk.Severity, risk.Category, risk.Title, risk.Recommendation}, risk.Details...), risk.Evidence...), " ")
		fmt.Fprintf(b, `<section class="risk" data-risk data-severity="%s" data-search="%s">`, e(strings.ToLower(risk.Severity)), attr(searchText))
		fmt.Fprintf(b, `<div class="severity %s">%s</div><div>`, severityClass(risk.Severity), e(risk.Severity))
		fmt.Fprintf(b, `<div class="risk-title">%s - %s</div>`, e(risk.ID), e(risk.Title))
		fmt.Fprintf(b, `<div class="risk-detail">%s</div>`, e(risk.Recommendation))
		writeHTMLList(b, "details", risk.Details, 4)
		writeHTMLList(b, "evidence", risk.Evidence, 4)
		b.WriteString(`</div></section>`)
	}
	b.WriteString(`</div>
        </div>
      </article>
`)
}

func writeHTMLChangePanel(b *strings.Builder, changes []BlockChange) {
	kinds := changeKinds(changes)
	b.WriteString(`      <article class="panel" id="changes">
        <div class="panel-head">
          <h2>Changed Blocks</h2>`)
	fmt.Fprintf(b, `<span class="tag" id="change-count">%d total</span>`, len(changes))
	b.WriteString(`</div>
        <div class="panel-body">
          <div class="filter-row" aria-label="Changed block filters">
            <input id="change-search" type="search" placeholder="Search changed headers or config lines">
            <select id="change-kind">
              <option value="">All block kinds</option>`)
	for _, kind := range kinds {
		fmt.Fprintf(b, `<option value="%s">%s</option>`, e(kind), e(kind))
	}
	b.WriteString(`</select>
            <select id="change-type">
              <option value="">All change types</option>
              <option value="added">Added</option>
              <option value="changed">Changed</option>
              <option value="removed">Removed</option>
            </select>
            <button type="button" id="change-reset">Reset</button>
          </div>
          <div class="change-list" style="margin-top:12px;">`)
	if len(changes) == 0 {
		b.WriteString(`<div class="subtle">No effective configuration changes were detected after normalization.</div>`)
	}
	for _, change := range changes {
		searchText := strings.Join(append(append([]string{change.Header, change.Kind, change.ChangeType}, change.BeforeLines...), change.AfterLines...), " ")
		fmt.Fprintf(b, `<section class="change" data-change data-kind="%s" data-type="%s" data-search="%s">`, e(change.Kind), e(change.ChangeType), attr(searchText))
		fmt.Fprintf(b, `<div class="change-head"><div class="change-title"><h3>%s</h3>`, e(change.Header))
		fmt.Fprintf(b, `<div class="subtle">%s block</div></div>`, e(change.Kind))
		fmt.Fprintf(b, `<span class="tag">%s</span></div>`, e(change.ChangeType))
		b.WriteString(`<div class="diff"><div class="side"><div class="side-label">Before</div>`)
		writeDiffCodeLines(b, change.BeforeLines, lineStatusRemoved(change.BeforeLines, change.AfterLines))
		b.WriteString(`</div><div class="side"><div class="side-label">After</div>`)
		writeDiffCodeLines(b, change.AfterLines, lineStatusAdded(change.BeforeLines, change.AfterLines))
		b.WriteString(`</div></div></section>`)
	}
	b.WriteString(`</div>
        </div>
      </article>
`)
}

func writeHTMLTouchedObjects(b *strings.Builder, a Analysis) {
	b.WriteString(`    <section class="panel" id="touched">
      <div class="panel-head">
        <h2>Touched Objects</h2>`)
	fmt.Fprintf(b, `<span class="tag">%d total</span>`, touchedObjectTotal(a))
	b.WriteString(`</div>
      <div class="panel-body object-grid">`)
	writeObjectCard(b, "Interfaces", interfaceItems(a.TouchedInterfaces))
	writeObjectCard(b, "VLANs", vlanItems(a.TouchedVLANs))
	writeObjectCard(b, "Routes", routeItems(a.TouchedRoutes))
	writeObjectCard(b, "ACL / Firewall", ruleItems(a.TouchedACLFirewallRules))
	writeObjectCard(b, "NAT", objectItems(a.TouchedNATObjects))
	writeObjectCard(b, "VPN", objectItems(a.TouchedVPNObjects))
	writeObjectCard(b, "Switching / L2", switchingItems(a.SwitchingChanges))
	writeObjectCard(b, "Routing Peers", routingPeerItems(a.TouchedRoutingPeers))
	writeObjectCard(b, "Security Boundaries", securityBoundaryItems(a.TouchedSecurityBoundaries))
	writeObjectCard(b, "Management", categoryItems(a.ManagementPlaneChanges))
	writeObjectCard(b, "AAA / Auth", categoryItems(a.AAAChanges))
	writeObjectCard(b, "Monitoring", categoryItems(a.LoggingSNMPNTPDNSChanges))
	b.WriteString(`</div>
    </section>
`)
}

func writeHTMLRollback(b *strings.Builder, rollback RollbackAnalysis) {
	b.WriteString(`    <section class="panel" id="rollback">
      <div class="panel-head">
        <h2>Rollback</h2>`)
	fmt.Fprintf(b, `<span class="tag">%s</span>`, e(rollback.Confidence))
	b.WriteString(`</div>
      <div class="panel-body">
        <p class="subtle">`)
	b.WriteString(e(rollback.Summary))
	b.WriteString(`</p>
        <div class="snippet-list" style="margin-top:12px;">`)
	if len(rollback.Snippets) == 0 {
		b.WriteString(`<div class="subtle">No rollback snippets are required.</div>`)
	}
	for _, snippet := range rollback.Snippets {
		fmt.Fprintf(b, `<details class="snippet"><summary><span>%s</span><span class="tag">%s</span></summary><div class="snippet-body">`, e(snippet.ChangeID), e(snippet.Kind))
		fmt.Fprintf(b, `<div class="small-list"><div>%s</div><div>Manual review required: <strong>%t</strong></div></div>`, e(snippet.Note), snippet.ManualReviewRequired)
		if len(snippet.Lines) > 0 {
			b.WriteString(`<div><h3>Captured lines</h3>`)
			writePlainCodeLines(b, snippet.Lines)
			b.WriteString(`</div>`)
		}
		if len(snippet.CandidateCommands) > 0 {
			b.WriteString(`<div><h3>Candidate commands</h3>`)
			writePlainCodeLines(b, snippet.CandidateCommands)
			b.WriteString(`</div>`)
		}
		b.WriteString(`</div></details>`)
	}
	b.WriteString(`</div>
      </div>
    </section>
`)
}

func writeHTMLValidationAndChecklist(b *strings.Builder, a Analysis) {
	b.WriteString(`    <section class="panel" id="validation">
      <div class="panel-head">
        <h2>Validation</h2>
        <span class="tag">operator plan</span>
      </div>
      <div class="panel-body checklist">
        <div>
          <h3>Before and during change</h3>
          <ul class="small-list">
            <li>Confirm out-of-band or break-glass access is available.</li>
            <li>Save the current running configuration and relevant operational state.</li>
            <li>Capture route, interface, neighbor, session, VPN, NAT, ACL, logging, and authentication baselines as applicable.</li>
            <li>Watch for management session loss, route churn, interface state changes, and unexpected denies.</li>
          </ul>
        </div>
        <div>
          <h3>After change</h3>
          <ul class="small-list">`)
	writeValidationItem(b, "Confirm management access through approved paths before and after the change.")
	if len(a.TouchedRoutes) > 0 {
		writeValidationItem(b, "Validate reachability for touched route prefixes and default route behavior.")
	}
	if len(a.TouchedInterfaces) > 0 {
		writeValidationItem(b, "Check touched interfaces for link state, errors, VLAN membership, and expected neighbors.")
	}
	if len(a.TouchedACLFirewallRules) > 0 {
		writeValidationItem(b, "Test allowed and denied traffic paths for changed ACL or firewall rules.")
	}
	if len(a.SwitchingChanges) > 0 {
		writeValidationItem(b, "Verify spanning-tree topology, EtherChannel bundling, VTP mode, and trunk/native VLAN scope.")
	}
	if len(a.TouchedRoutingPeers) > 0 {
		writeValidationItem(b, "Verify BGP and OSPF neighbor state, AS/area membership, and prefix exchange for touched routing peers.")
	}
	if len(a.TouchedSecurityBoundaries) > 0 {
		writeValidationItem(b, "Validate security-zone boundaries for newly permitted cross-zone flows, collapsed trust boundaries, and management access across segments.")
	}
	if len(a.TouchedNATObjects) > 0 {
		writeValidationItem(b, "Validate NAT translations and session setup for affected flows.")
	}
	if len(a.TouchedVPNObjects) > 0 {
		writeValidationItem(b, "Validate tunnel establishment, selectors, and encrypted traffic counters.")
	}
	if len(a.AAAChanges) > 0 {
		writeValidationItem(b, "Test administrative login with primary and fallback authentication paths.")
	}
	if len(a.LoggingSNMPNTPDNSChanges) > 0 {
		writeValidationItem(b, "Confirm logs, SNMP polling/traps, NTP sync, and DNS resolution remain healthy.")
	}
	writeValidationItem(b, "Compare post-change facts against the pre-change baseline and rollback if critical checks fail.")
	b.WriteString(`</ul>
        </div>
      </div>
    </section>
`)
}

func writeHTMLScript(b *strings.Builder) {
	b.WriteString(`    <script>
      const text = (value) => (value || "").toLowerCase();
      function wireFilter(itemsSelector, searchId, selectIds, countId) {
        const search = document.getElementById(searchId);
        const selects = selectIds.map((id) => document.getElementById(id)).filter(Boolean);
        const count = document.getElementById(countId);
        const items = Array.from(document.querySelectorAll(itemsSelector));
        function apply() {
          const q = text(search && search.value);
          let visible = 0;
          for (const item of items) {
            let show = !q || text(item.dataset.search).includes(q);
            for (const select of selects) {
              if (select.value && item.dataset[select.dataset.key] !== select.value) show = false;
            }
            item.classList.toggle("hidden", !show);
            if (show) visible++;
          }
          if (count) count.textContent = visible + " of " + items.length;
        }
        if (search) search.addEventListener("input", apply);
        for (const select of selects) select.addEventListener("change", apply);
        apply();
      }
      const riskSeverity = document.getElementById("risk-severity");
      if (riskSeverity) riskSeverity.dataset.key = "severity";
      const changeKind = document.getElementById("change-kind");
      if (changeKind) changeKind.dataset.key = "kind";
      const changeType = document.getElementById("change-type");
      if (changeType) changeType.dataset.key = "type";
      wireFilter("[data-risk]", "risk-search", ["risk-severity"], "risk-count");
      wireFilter("[data-change]", "change-search", ["change-kind", "change-type"], "change-count");
      document.getElementById("risk-reset")?.addEventListener("click", () => {
        document.getElementById("risk-search").value = "";
        document.getElementById("risk-severity").value = "";
        document.getElementById("risk-search").dispatchEvent(new Event("input"));
      });
      document.getElementById("change-reset")?.addEventListener("click", () => {
        document.getElementById("change-search").value = "";
        document.getElementById("change-kind").value = "";
        document.getElementById("change-type").value = "";
        document.getElementById("change-search").dispatchEvent(new Event("input"));
      });
    </script>
`)
}

func writeHTMLDocumentEnd(b *strings.Builder) {
	b.WriteString(`  </main>
</body>
</html>
`)
}

func writeMetric(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, `<div class="metric"><div class="label">%s</div><div class="value">%s</div></div>`, e(label), e(value))
}

func writeHTMLList(b *strings.Builder, className string, items []string, limit int) {
	if len(items) == 0 {
		return
	}
	remaining := 0
	if limit > 0 && len(items) > limit {
		remaining = len(items) - limit
		items = items[:limit]
	}
	fmt.Fprintf(b, `<div class="%s">`, e(className))
	for _, item := range items {
		fmt.Fprintf(b, `<div>%s</div>`, e(item))
	}
	if remaining > 0 {
		fmt.Fprintf(b, `<div>+%d more</div>`, remaining)
	}
	b.WriteString(`</div>`)
}

func writeObjectCard(b *strings.Builder, title string, items []string) {
	fmt.Fprintf(b, `<article class="object-card"><h3>%s</h3><div class="small-list">`, e(title))
	if len(items) == 0 {
		b.WriteString(`<div class="subtle">None detected.</div>`)
	} else {
		limit := 8
		shown := items
		if len(shown) > limit {
			shown = shown[:limit]
		}
		for _, item := range shown {
			fmt.Fprintf(b, `<div>%s</div>`, e(item))
		}
		if len(items) > limit {
			fmt.Fprintf(b, `<div>+%d more</div>`, len(items)-limit)
		}
	}
	b.WriteString(`</div></article>`)
}

func writeDiffCodeLines(b *strings.Builder, lines []string, statuses map[string]string) {
	b.WriteString(`<pre>`)
	if len(lines) == 0 {
		b.WriteString(`<span class="empty">not present</span>`)
	} else {
		seen := map[string]int{}
		for _, line := range lines {
			seen[line]++
			status := statuses[lineKey(line, seen[line])]
			if status != "" {
				fmt.Fprintf(b, `<span class="line %s">%s</span>`, e(status), e(line))
			} else {
				fmt.Fprintf(b, `<span class="line">%s</span>`, e(line))
			}
		}
	}
	b.WriteString(`</pre>`)
}

func writePlainCodeLines(b *strings.Builder, lines []string) {
	b.WriteString(`<pre>`)
	if len(lines) == 0 {
		b.WriteString(`<span class="empty">not present</span>`)
	} else {
		for _, line := range lines {
			fmt.Fprintf(b, `<span class="line">%s</span>`, e(line))
		}
	}
	b.WriteString(`</pre>`)
}

func writeValidationItem(b *strings.Builder, value string) {
	fmt.Fprintf(b, `<li>%s</li>`, e(value))
}

func changeKinds(changes []BlockChange) []string {
	seen := map[string]bool{}
	for _, change := range changes {
		seen[change.Kind] = true
	}
	kinds := make([]string, 0, len(seen))
	for kind := range seen {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

func lineStatusRemoved(before, after []string) map[string]string {
	return lineStatusDiff(before, after, "removed")
}

func lineStatusAdded(before, after []string) map[string]string {
	return lineStatusDiff(after, before, "added")
}

func lineStatusDiff(subject, other []string, status string) map[string]string {
	otherCounts := countedLines(other)
	seen := map[string]int{}
	out := map[string]string{}
	for _, line := range subject {
		seen[line]++
		if seen[line] > otherCounts[line] {
			out[lineKey(line, seen[line])] = status
		}
	}
	return out
}

func countedLines(lines []string) map[string]int {
	out := map[string]int{}
	for _, line := range lines {
		out[line]++
	}
	return out
}

func lineKey(line string, index int) string {
	return fmt.Sprintf("%s\x00%d", line, index)
}

func touchedObjectTotal(a Analysis) int {
	return len(a.TouchedInterfaces) +
		len(a.TouchedVLANs) +
		len(a.TouchedRoutes) +
		len(a.TouchedACLFirewallRules) +
		len(a.TouchedNATObjects) +
		len(a.TouchedVPNObjects) +
		len(a.SwitchingChanges) +
		len(a.TouchedRoutingPeers) +
		len(a.TouchedSecurityBoundaries) +
		len(a.ManagementPlaneChanges) +
		len(a.AAAChanges) +
		len(a.LoggingSNMPNTPDNSChanges)
}

func interfaceItems(items []TouchedInterface) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Name+" - "+item.ChangeType)
	}
	return out
}

func vlanItems(items []TouchedVLAN) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, "VLAN "+item.ID+" - "+item.ChangeType)
	}
	return out
}

func routeItems(items []TouchedRoute) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		nextHop := item.AfterNextHop
		if nextHop == "" {
			nextHop = item.BeforeNextHop
		}
		if nextHop != "" {
			out = append(out, item.Prefix+" via "+nextHop+" - "+item.ChangeType)
			continue
		}
		out = append(out, item.Prefix+" - "+item.ChangeType)
	}
	return out
}

func ruleItems(items []TouchedRule) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		parts := []string{item.Name, item.ChangeType}
		if item.Action != "" {
			parts = append(parts, item.Action)
		}
		if item.Service != "" {
			parts = append(parts, "service "+item.Service)
		}
		if item.SourceZone != "" || item.DestinationZone != "" {
			parts = append(parts, item.SourceZone+" -> "+item.DestinationZone)
		}
		out = append(out, strings.Join(parts, " - "))
	}
	return out
}

func objectItems(items []TouchedObject) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Name+" - "+item.ChangeType)
	}
	return out
}

func switchingItems(items []SwitchingChange) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Category+" "+item.Subject+" - "+item.ChangeType)
	}
	return out
}

func routingPeerItems(items []TouchedRoutingPeer) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		label := item.Protocol + " " + item.Peer + " - " + item.ChangeType
		if item.RemoteAS != "" {
			label += " remote-as " + item.RemoteAS
		}
		if item.Area != "" {
			label += " area " + item.Area
		}
		out = append(out, label)
	}
	return out
}

func securityBoundaryItems(items []TouchedSecurityBoundary) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch item.Kind {
		case "zone_membership":
			out = append(out, item.Kind+" "+item.Zone+"/"+item.Member+" - "+item.ChangeType)
		default:
			label := item.Kind + " " + item.SourceZone + " -> " + item.DestinationZone + " - " + item.ChangeType
			if item.Policy != "" {
				label += " policy " + item.Policy
			}
			out = append(out, label)
		}
	}
	return out
}

func categoryItems(items []CategoryChange) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Category+" - "+item.ChangeType)
	}
	return out
}

func severityClass(severity string) string {
	switch strings.ToLower(severity) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "low"
	}
}

func e(value string) string {
	return html.EscapeString(value)
}

func attr(value string) string {
	return html.EscapeString(strings.ToLower(value))
}
