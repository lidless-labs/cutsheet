# Roadmap

GitHub issues are the source of truth for filed work. This file lists what shipped,
what is active, what is next, and what stays deferred so README teasers and open
issues stay aligned.

## Shipped

Closed issues and major v1 capabilities already in the tree:

- [#17](https://github.com/lidless-labs/cutsheet/issues/17) eero `session_token` in API redaction list (closed)
- [#18](https://github.com/lidless-labs/cutsheet/issues/18) remove server filesystem paths from outbound notifications (closed)
- [#19](https://github.com/lidless-labs/cutsheet/issues/19) Go module identity at `github.com/lidless-labs/cutsheet` (closed)
- [#25](https://github.com/lidless-labs/cutsheet/issues/25) README render markers, purity contract, preflight docs, stale notes (closed)
- Syslog-triggered snapshots with UDP listener, debounce, and cooldown (see README Syslog-triggered snapshots)
- [#22](https://github.com/lidless-labs/cutsheet/issues/22) attribute config changes to users via syslog audit events
- Webhook and Discord notifications with configurable severity floor
- Offline `cutsheet-cli` `explain` and `preflight`
- Multi-vendor deterministic parsers (Cisco IOS, EdgeOS/VyOS, PAN-OS, Junos, FortiOS, UniFi, eero)
- Docker Compose install path and demo mode

Read-only collectors and no config push are permanent product boundaries, not roadmap items.

## Active

Reliability and UI bugs queued for the next fix slice:

- [#15](https://github.com/lidless-labs/cutsheet/issues/15) retry post-snapshot processing when report generation or SQLite recording fails after the git commit
- [#16](https://github.com/lidless-labs/cutsheet/issues/16) report-preview blob URL revoked by the rerender its own `setState` triggers

## Next

Enhancement backlog sized for single implementation slices:

- [#21](https://github.com/lidless-labs/cutsheet/issues/21) validate undefined-but-referenced config structures (dangling ACL and route-map references)
- [#23](https://github.com/lidless-labs/cutsheet/issues/23) track BGP/OSPF peers as first-class objects

## Deferred

Large or cross-cutting work. Open or extend a GitHub issue before starting:

- [#20](https://github.com/lidless-labs/cutsheet/issues/20) golden-state compliance and baseline-drift policies (README compliance packs teaser)
- [#24](https://github.com/lidless-labs/cutsheet/issues/24) security-zone and microsegmentation boundary changes (additive `pkg/configdiff` schema extension)
- AWS network state ingestion (security groups, route tables, NACLs) in the same timeline as on-prem devices (design doc v2.x, no issue filed)
- Remote-site collector daemons, outbound-only and MSP-friendly (design doc v1.x, no issue filed)
- OIDC SSO, Terraform or AWS deploy path, and CAB or approval workflow (design doc v1.x and v3, no issues filed)
