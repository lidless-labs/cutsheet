# Cutsheet - Network Change Intelligence Platform

## Context

Cutsheet exists to answer the question every network operator asks after an incident: "what changed on the network, and should I be worried?"

The current tooling landscape leaves a gap:

- **Oxidized / RANCID** back up configs but provide zero analysis. A diff is just colored lines; nothing tells you a trunk started carrying all VLANs or an ACL got broadened to any/any.
- **SolarWinds NCM** is expensive, heavyweight, and post-supply-chain-attack distrusted.
- **Batfish / IP Fabric** are powerful but far too heavy for the mid-size org. Standing up a network model is a project in itself.
- The underserved user is the network admin or small infra team at a mid-size org, school district, hospital, or MSP: PuTTY-and-spreadsheet change control, no NetDevOps pipeline, no budget for enterprise NCM.

The analysis core already exists: the `config-diff-explainer` engine (now `pkg/configdiff`), a deterministic Go library with 8 vendor parser paths (Cisco IOS full; Junos/FortiOS/PAN-OS/EdgeOS initial; EdgeSwitch/UniFi partial), typed facts (routes, ACLs, L2 switching, VLANs, NAT, VPN, AAA, management plane), structured risk findings with evidence, a stable JSON schema (v1.1), and 8 operator-ready report types (risk analysis, rollback plan, validation plan, operator checklist, stakeholder brief, HTML view). Cutsheet wraps that core in a continuously running platform.

## Decisions (2026-06-09)

| Decision | Choice |
|---|---|
| Win condition | Adoption first - a real org deploying it beats any feature checklist |
| Shape | Change intelligence platform ("Oxidized with a brain") |
| Seed | `config-diff-explainer` Go core, vendored as `pkg/configdiff` |
| Cloud story | AWS via later phases (Terraform deploy in v1.x, AWS network-state ingestion in v2.x) |
| v1 scope | Lean: collectors + git history + risk reports + web timeline + notifications, single-org, docker-compose |
| License | Apache-2.0 |
| Name | **Cutsheet** (first choice Trunkline is a live product at trunkline.dev; cutsheet namespace cleared 2026-06-09 across GitHub, npm, PyPI, cutsheet.dev/.io) |

## Product definition

**One-liner:** Cutsheet continuously snapshots your network device configs, keeps a git-backed history, and turns every change into a risk-analyzed report a human (or a change advisory board) can actually read. The name is the pitch: a cut sheet is the document a network engineer prepares for a change window; Cutsheet generates the evidence side of that document automatically, after every change.

**Target user:** the network admin / small infra team at a mid-size org, school district, hospital, or MSP. Wants to know "what changed last night, and should I be worried" without buying SolarWinds or learning Batfish.

**Wedge vs competitors:** Oxidized's install simplicity + the configdiff risk brain + reports written for humans. Later: the hybrid twist nobody has, AWS network state (security groups, route tables, NACLs) in the same change timeline as switch and firewall configs.

## Architecture (v1)

Single Go binary (server with embedded collector) + Postgres + git storage + React UI. Deploys via docker-compose in ~15 minutes.

```
┌─────────────────────────── cutsheet server (Go) ─────────────────────────────┐
│  Scheduler ──> Collector (agentless SSH/API) ──> Snapshot store (git)        │
│                                                      │                       │
│                                       change detected │                       │
│                                                      v                       │
│  REST API <── Postgres (devices, changes, findings) <── Analysis engine      │
│      │                                                  (configdiff core)    │
│      └──> Notifier (webhook/Slack/Discord/email)                             │
└──────────────────────────────────────────────────────────────────────────────┘
        ^
   React web UI (device list, change timeline, change detail, risk feed)
```

Components:

1. **`pkg/configdiff` (public Go library):** the analysis engine. The pure `Explain()` function and JSON schema v1.1 are the contract. No side effects, no network calls, ever.
2. **Collector:** agentless, runs inside the server process in v1. Per-vendor command runners over SSH (`golang.org/x/crypto/ssh`): Cisco `show running-config`, Junos `show configuration | display set`, FortiOS `show full-configuration`, PAN-OS set-format export, UniFi controller API (JSON), EdgeOS. Scheduled polling (cron-style per device) + manual "snapshot now". Credentials encrypted at rest (age or NaCl secretbox, key from env). Remote-site collector daemons are a later phase.
3. **Snapshot store:** one git repo (managed by the server, go-git) with per-device paths. Every snapshot = commit. Diff between consecutive commits feeds the analysis engine. Git gives history, blame, and offsite backup (push mirror) for free.
4. **Analysis engine:** on change detection, run the configdiff core, persist `Analysis` JSON + risk findings to Postgres, render the existing report set per change.
5. **API + UI:** Go REST API (chi or echo), React/TS frontend. Views: device inventory, change timeline (org-wide feed), change detail (rendered risk/rollback/validation/stakeholder reports, raw diff), device history. Single-org, simple local users + API tokens in v1 (OIDC later).
6. **Notifier:** webhook + Slack/Discord/email on new change, severity-filtered.

## Roadmap after v1

- **v1.x:** Terraform module + AWS deploy path (ECS Fargate + RDS), OIDC SSO, syslog-triggered instant snapshots, remote-site collector daemon (outbound-only, MSP-friendly).
- **v2 (compliance packs):** CIS/NIST 800-53/DISA STIG rule packs per vendor, continuous compliance + drift vs golden config, audit evidence export.
- **v2.x (hybrid cloud):** AWS network state ingestion (security groups, route tables, NACLs, TGW) into the same timeline and risk engine. The unique differentiator.
- **v3:** approval workflow / CAB mode (planned-change vs observed-change reconciliation), multi-tenant, optional hosted offering.

## Implementation plan (Phase 1 only)

Repo private until first release. Go for server, React/TS for UI.

1. **Name reservation:** register cutsheet.dev (and optionally .io); reserve npm/PyPI names if desired. Namespace cleared 2026-06-09.
2. **Repo bootstrap (done):** configdiff core vendored as `pkg/configdiff` + `cmd/cutsheet-cli` (existing CLI), fresh history, Apache-2.0, content-guard pre-push hook, `.claude/` untracked.
3. **Snapshot store + scheduler:** go-git managed repo, device registry in Postgres, per-device polling schedule, manual snapshot endpoint. TDD.
4. **SSH/API collectors, in order of available test infrastructure:** UniFi controller API first, then EdgeOS/VyOS (VyOS is free in containerlab), then Cisco IOS via containerlab/GNS3 images and recorded fixtures. PAN-OS and FortiOS stay fixture-replay until a virtual firewall image or community tester is available.
5. **Analysis pipeline:** change detection on new commit, run `Explain()`, persist findings, render reports.
6. **REST API + React UI:** inventory, timeline, change detail. Reuse the existing HTML report rendering as the change-detail core.
7. **Notifier:** webhook + Discord first.
8. **Dogfood:** a permanent containerlab topology (VyOS + FRR + cEOS) polled via the SSH collector is the primary live environment (no managed home hardware exists; the home network is eero mesh). A future eero collector against the unofficial eero cloud API (prior art: solomonneas/eero-cli) adds a real-gear story. Early outside adopters from homelab/networking communities expand real-world vendor coverage; the UniFi collector ships fixture-tested and gets its first live validation from an adopter.
9. **Release prep:** docker-compose install path, README with 15-minute quickstart, demo GIF, fixture-based demo mode (ship with sample devices so people can try it with zero hardware).

## Verification

- **Unit/golden:** existing configdiff tests + new golden fixtures per collector vendor (recorded real outputs, sanitized: no RFC 1918, use 198.18.0.0/15 or RFC 5737).
- **Integration:** docker-compose up from scratch, register a containerlab FRR or VyOS virtual device, force a config change, assert a risk-analyzed change appears in the timeline and fires a webhook.
- **Live:** poll a containerlab VyOS device via the SSH collector; make a real config change through the VyOS CLI; verify the stakeholder brief reads correctly. (No managed hardware available; an eero collector against the unofficial eero cloud API is the future real-gear path.)
- **Adoption test (the real one):** one outside person installs from the README in under 15 minutes without help.

## Out of scope (deliberately)

- Config PUSH to devices. Cutsheet observes and advises; it does not write to your network. This is the #1 trust barrier for the target audience and the #1 way to destroy a network. Maybe never.
- Kubernetes-native deployment in v1 (docker-compose first; ECS in v1.x; k8s manifests only if adopters ask).
- NETCONF/gNMI streaming (poll + syslog-trigger covers the target market; gNMI is a v3 question).
- Multi-tenancy, billing, hosted SaaS (v3 question, only after single-org adoption exists).
