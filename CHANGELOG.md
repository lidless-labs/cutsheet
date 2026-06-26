# Changelog

All notable changes to Cutsheet are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pkg/configdiff` analysis engine (bootstrapped from config-diff-explainer):
  deterministic, offline config diff analysis with risk findings, rollback
  and validation plans, operator checklist, stakeholder brief, and HTML
  report, behind a stable JSON schema (`diff-analysis-v1`).
- Parser paths for Cisco IOS/IOS XE, Ubiquiti EdgeSwitch, EdgeOS/VyOS,
  Palo Alto PAN-OS, Juniper Junos, Fortinet FortiOS, UniFi controller JSON
  exports, and a generic fallback.
- `cutsheet-cli explain`, the offline diff CLI for one-off change review.
- Server platform: device registry, git-backed snapshot store, polling
  scheduler, and the analysis pipeline from snapshot changes to recorded
  findings (SQLite).
- Read-only collectors: `file` (fixtures and demo), `ssh` (vendor presets,
  host key verification), `unifi` (UniFi Network controller API), and
  `eero` (unofficial eero cloud API with out-of-band session token).
- Credential encryption at rest (NaCl secretbox) for passwords, private
  keys, and session tokens.
- REST API with bearer token auth (`cutsheet token create`) and on-demand
  snapshots.
- Severity-filtered webhook and Discord notifications.
- React web UI (timeline, devices, change detail, settings), embedded into
  the server binary via go:embed with SPA fallback.
- Zero-hardware demo mode seeding sample devices and analyzed changes.
- Docker image and compose deployment with healthcheck and non-root user.
- Version injection: `make build`, `make docker-build`, and the compose
  build report `git describe` (or `$VERSION`) via `/healthz`.
- cutsheet.dev landing page.

### Documentation

- README rewritten to the adoption standard: differentiator on the first
  screen, a keyword-rich "What it does" section, a real risk-finding output
  block, "Why not Oxidized, RANCID, or NetBox?" and "What Cutsheet is not"
  sections, and a prominent cutsheet.dev link.
- Added maintainer-health files: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue templates (bug, feature, and a blank-issue
  config with contact links), and a pull request template.
