# Parser and Analysis Reference

Details on the `pkg/configdiff` parser paths, what they extract, and what
they flag. For the vendor support table see the main [README](../README.md).

## Supported Input Types

Use `--vendor auto` (CLI) or leave the device vendor on `auto` (server) to
select a parser when the config has strong vendor signals. If no confident
match exists, analysis falls back to `generic`.

UniFi controller configs are JSON rather than line-oriented CLI text. The
JSON parser flattens the export into deterministic pseudo-lines and emits
CLI-equivalent readable lines so the same risk findings apply.

Eero snapshots (from the server's eero collector) are a deterministic JSON
document assembled from the unofficial eero cloud API (network settings,
nodes, profiles, port forwards, DHCP reservations). The `eero-json` parser
normalizes those objects into stable blocks keyed by eero `url` values.
Port forwards map to NAT objects. DNS maps to observability. Main and guest
WiFi identity or security settings map to management-plane changes. Eero
nodes map to interface-like inventory blocks so node removal and topology
changes fit the existing touched-interface field.

Supported deterministic extraction includes:

- added, removed, and changed config blocks
- interfaces
- VLANs and trunk/access VLAN references
- Layer 2 switching semantics for Catalyst-style switches: switchport mode,
  trunk scope, native VLAN, spanning-tree mode, root/priority, PortFast,
  BPDU guard, EtherChannel/port-channel, VTP, and storm-control
- static routes and default routes
- route next-hop changes where detectable
- ACL/firewall-style permit and deny rules, including first-pass
  action/protocol/source/destination/service extraction
- NAT-like objects and lines
- VPN/tunnel/crypto-like objects and lines
- management-plane access such as SSH, SNMP, HTTP, and line access
- AAA/authentication, local users, RADIUS, and TACACS-like lines
- logging, SNMP, NTP, and DNS lines

## Risk Findings

The v1 risk engine flags at least:

- default route changes
- route removals
- ACL/firewall broadening such as `any any`, broad CIDRs, and exposed
  management ports
- VLAN removals and interface VLAN changes
- trunk allowed VLAN changes
- Layer 2 switching changes: switchport mode flips, trunks carrying all
  VLANs, native VLAN changes, spanning-tree mode and root/priority changes,
  reduced BPDU protection or PortFast on trunks, EtherChannel
  membership/mode changes, VTP mode/domain changes, and storm-control
  reductions
- shutdown/no shutdown changes
- NAT changes
- VPN peer/tunnel changes
- AAA/auth changes
- management access changes such as SSH/SNMP/HTTP
- logging/monitoring removal

## Parser Architecture

The parser layer is separated from analysis and reporting:

| Layer | Role |
| --- | --- |
| Parser | Normalizes text, groups sections and blocks, and detects generic platform signals |
| Analyzer | Diffs normalized blocks, extracts touched objects, assigns risks, and builds rollback facts |
| Explanation provider | Renders reports from deterministic facts |

The first explanation provider is offline and deterministic. A future
provider can use the same `ExplanationProvider` interface, but deterministic
analysis remains the source of truth.

`configdiff.Explain()` is a pure function: no side effects beyond the output
directory, no network calls. The JSON schema
(`schema/diff-analysis-v1.schema.json`) is a stable contract.

## Current Limitations

- Cisco IOS/IOS XE support is an initial deterministic parser path built on
  IOS-style section parsing and heuristics, not full semantic emulation of
  every platform feature.
- Ubiquiti EdgeSwitch/UbiquitiOS support rides the IOS-style parse path and
  is labeled `ubiquiti`; EdgeSwitch-native VLAN forms such as
  `vlan participation` are recognized for detection but do not yet produce
  typed VLAN findings.
- EdgeOS/VyOS support is an initial deterministic parser path for
  `set`/`delete` style gateway configs. Curly-brace hierarchical form is not
  yet parsed, and interface `disable` toggles are not yet flagged.
- Junos support is an initial deterministic parser path for `set`/`delete`
  style configs, not full semantic emulation of every platform feature.
- Palo Alto PAN-OS support is an initial deterministic parser path for
  set-style configuration form. XML exports, Panorama device-group/template
  hierarchy, and multi-vsys are out of scope.
- UniFi controller support reads JSON exports from common single-site
  collections such as `networkconf`, `port_overrides`, `firewallrule`, and
  `routing`. XML or `.unf` backups and multi-site exports are out of scope
  for the offline CLI; the server's UniFi collector handles live API fetches.
- Eero support reads the server collector snapshot shape:
  `eeros`, `forwards`, `network`, `profiles`, and `reservations`. Eero
  forwards are NAT/port-forward entries, not ACL or firewall policy rules,
  because the snapshot does not include source scope or the full firewall
  policy. A forwarded internal `443` or `22` service is not treated as router
  management-plane exposure. Default routes, VLANs, VPNs, AAA, switching
  semantics, and full ACL broadening are not represented in the eero snapshot.
  Password fields are redacted in parser evidence with a stable fingerprint,
  so reports can detect password changes without printing raw WiFi secrets.
- Fortinet support is an initial deterministic parser path for FortiOS
  `config`/`edit` blocks, not full semantic emulation of every platform
  feature.
- The parser uses deterministic heuristics and may miss vendor-specific
  semantics.
- Report prose is practical guidance, not a replacement for device-specific
  command validation.
- Rollback snippets preserve before-config facts and separate exact reapply
  snippets from candidate commands. Candidate commands are not authoritative
  and may require operator review.

## Testing

The test suite includes compact JSON golden summaries for Cisco IOS-style,
Junos-style, and other sample configs under `testdata/golden/`. Update those
fixtures only when an intentional parser, risk, or output-shape change
affects the expected summary.
