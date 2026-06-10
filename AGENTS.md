# Cutsheet - Agent Guidance

Network change intelligence platform. Snapshots device configs, git-backed history,
risk-analyzed change reports. Design: `docs/superpowers/specs/2026-06-09-cutsheet-design.md`.
Decisions log: `implementation-notes.md` (keep it updated as you work - SOP).

## Ground rules

- Go 1.22+ server/library, React/TS UI (later). TDD: test first, then implementation.
- `pkg/configdiff` is the public analysis library. Its `Explain()` is a pure function
  and the JSON schema (`schema/diff-analysis-v1.schema.json`) is a stable contract.
  Do not add side effects or network calls to it.
- Cutsheet NEVER pushes config to devices. Read-only collectors only.
- No RFC 1918 IPs anywhere, including fixtures. Use 198.18.0.0/15 (RFC 2544) or
  RFC 5737 ranges. content-guard pre-push hook enforces this; do not bypass with
  --no-verify.
- `.claude/` is gitignored and must stay untracked. Memory handoffs go to
  `.claude/memory-handoffs/` on disk (the local memory ingester reads them from
  the filesystem, not from git).
- Commit style: conventional commits, no Co-Authored-By, no AI/tool mentions.
- This repo is private until first release. Before any public push: full
  content-guard history scan.

## Build and test

```bash
make test      # go test ./...
make vet
make build     # builds ./cutsheet from cmd/cutsheet-cli
make sample-report
```

## Environment constraints

- NO managed network hardware available at all: no Cisco/Palo Alto, no UniFi
  controller, no EdgeOS gateway. Home network is eero mesh only. Live testing:
  containerlab (VyOS/FRR via the SSH collector) is the primary testbed; a future
  eero collector (unofficial cloud API, prior art in solomonneas/eero-cli) is the
  only real-gear option. Everything else: testdata fixtures.
