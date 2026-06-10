# Cutsheet - Agent Guidance

Network change intelligence platform: snapshots device configs, git-backed history,
risk-analyzed change reports. Go 1.25+ server/library, React/TS UI in `web/`.
Design: `docs/superpowers/specs/2026-06-09-cutsheet-design.md`. Decisions log:
`implementation-notes.md`; update it as you work (SOP).

## Definition of Done

```bash
./scripts/verify
```

Runs gofmt check, `go vet ./...`, `go build ./...`, `go test ./...` (the unconditional
Go gates from CI). Report the actual result, paste failures verbatim, never claim a
gate passed without observing it pass.

## Rules

- Changing anything under `web/src`: `web/dist` is committed and embedded into the
  server binary via go:embed, and CI fails on drift. Run `make ui`, rebuild the
  server, and commit the regenerated dist in the same change.
- Touching `pkg/configdiff` (public analysis library): `Explain()` is a pure function
  and `schema/diff-analysis-v1.schema.json` is a stable contract. Do not add side
  effects, network calls, or breaking schema changes; extend additively instead.
- Writing any IP address, including in fixtures: no RFC 1918 ranges anywhere. Use
  198.18.0.0/15 (RFC 2544) or RFC 5737 documentation ranges. The content-guard
  pre-push hook blocks violations.
- Implementing a feature or bugfix: write the failing test first (TDD).
- Writing files under `.claude/`: it is gitignored and must stay untracked. The
  local memory ingester reads handoffs from the filesystem, not from git.
- Committing: conventional commits, no Co-Authored-By, no tool mentions.
- Repo is private until first release: full content-guard history scan before
  any public push.

## Hard prohibitions

- Never push with `--no-verify`. A content-guard pre-push hook exists in this repo;
  if it blocks, report the exact finding instead of bypassing it.
- Never weaken, skip, or delete a failing test to get green. Fix the code or report
  the failure verbatim.
- Never invent commands; use only the gates above and the Make targets below.
- Never work around a blocker silently; report the exact error and stop.

## Live services and destructive operations

- Collectors are read-only. Cutsheet NEVER pushes config to devices; do not add
  write paths to any collector.
- The eero collector (`internal/collector/eero.go`) talks to an unofficial live
  cloud API on the real home network. Never run it against real credentials
  without explicit approval; use testdata fixtures.
- `make demo` seeds `./demo-data` and refuses a non-empty directory. `make clean`
  deletes the built binaries and `./reports`. Run neither on paths you did not create.

## Build and test

```bash
make test            # go test ./...
make vet             # go vet ./...
make build           # builds ./cutsheet (server, cmd/cutsheet) and ./cutsheet-cli (diff CLI)
make sample-report   # offline demo report from testdata fixtures
make ui              # npm ci + build web/src into committed web/dist
```

## Environment constraints

No managed network hardware available: no Cisco/Palo Alto, no UniFi controller, no
EdgeOS gateway; the home network is eero mesh only. Live testing: containerlab
(VyOS/FRR via the SSH collector) is the primary testbed; the eero collector (prior
art in solomonneas/eero-cli) is the only real-gear option. Everything else uses
testdata fixtures.

## Memory Handoff

At the end of any substantial task, write a handoff to `.claude/memory-handoffs/`
using `.claude/memory-handoffs/TEMPLATE.md`. Durable facts only, no private
identifiers; the local ingester picks it up from disk.
