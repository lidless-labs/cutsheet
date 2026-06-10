# Implementation Notes

Running log of decisions, deviations, and tradeoffs not captured in the spec
(`docs/superpowers/specs/2026-06-09-cutsheet-design.md`). Newest entries at the bottom.

## 2026-06-09 - Bootstrap

- **Fresh history instead of imported history.** The spec allowed importing
  config-diff-explainer's git history. Chose to vendor the working tree at a single
  initial commit instead: the source repo's history contains tracked
  `.claude/memory-handoffs/` files, and scrubbing history before a future public
  release (filter-repo) has been painful on past projects. Cutsheet history is clean
  from commit zero. Provenance is recorded in the initial commit message.
- **Carried uncommitted WIP from the source repo.** config-diff-explainer had
  finished-looking uncommitted work on `feat/multi-vendor-expansion` (interactive
  HTML report sections, search/filter, escaping test). It builds and tests green, so
  it came along. The source repo was left untouched.
- **Layout:** `internal/configdiff` became `pkg/configdiff` (public library, the
  server will import it), `cmd/config-diff` became `cmd/cutsheet-cli`. Module path
  `github.com/solomonneas/cutsheet`. 30 tests passing after the move.
- **Fixture IP sanitization.** content-guard blocks all RFC 1918 even in fake
  fixtures. All `10.x` fixture/doc/test IPs were remapped into 198.18.0.0/15
  (RFC 2544 benchmark range) with a subnet-preserving mapping:
  `10.0.B.C -> 198.18.B.C`; other `10.A.B.C` prefixes got distinct `198.19.Y.C`
  third octets (10.10.0->198.19.10, 10.10.10->198.19.110, 10.20.0->198.19.20,
  10.20.20->198.19.120, 10.30.0->198.19.30, 10.50.0->198.19.50,
  10.255.0->198.19.255, 10.1.1->198.19.1, 10.9.0->198.19.9). Tests pass unchanged
  in behavior because the mapping is injective per /24.
- **`.claude/` is fully gitignored** in this repo (no tracked handoffs), unlike the
  source repo. Handoffs still get written to `.claude/memory-handoffs/` on disk for
  the local memory ingester; they just never enter git.
- **content-guard pre-push hook** installed from `~/repos/content-guard/hooks/pre-push`.
- **Dogfood constraint:** no enterprise lab hardware available (Cisco Catalyst /
  Palo Alto access ended). Collector order: UniFi API first, EdgeOS/VyOS second,
  Cisco IOS via containerlab/fixtures.
- **Name:** Trunkline was the first pick; burned (live MCP-infra product at
  trunkline.dev). Cutsheet cleared on GitHub/npm/PyPI/cutsheet.dev/.io as of
  2026-06-09. Domain registration is Solomon's action item.

## 2026-06-09 - Device registry, snapshot store, scheduler, server skeleton

- **SQLite instead of Postgres for v1.** The design spec says Postgres, but v1
  optimizes for adoption: a single binary with `modernc.org/sqlite` (pure Go,
  no cgo) means `cutsheet serve --data-dir ./data` works with zero external
  services. All persistence is behind the `internal/store` API, so swapping in
  Postgres for multi-tenant in v1.x is an implementation change, not an API
  change. Embedded SQL migrations (go:embed + schema_migrations table) keep the
  upgrade path honest from day one.
- **Single SQLite connection** (`SetMaxOpenConns(1)`) plus WAL and
  busy_timeout: modernc's driver returns SQLITE_BUSY under pooled concurrent
  writers; one connection sidesteps it at v1's write volume.
- **Snapshot store compares against HEAD, not the worktree.** Save() reads the
  previous content from the HEAD commit tree, so a dirty or hand-edited
  worktree file can't suppress (or fabricate) change detection. PrevCommitHash
  comes from `git log -- <file>` semantics (go-git LogOptions.FileName), so
  devices never see each other's commits. Save() is mutex-serialized: one repo,
  many device goroutines.
- **Collector factory is a registration map.** v1 ships only "file"
  (fixture-driven tests + zero-hardware demo mode); ssh/unifi slot in as new
  map entries in a later unit. Collector config is validated at `device add`
  time, not first poll.
- **Scheduler is deliberately dumb:** one ticker goroutine per enabled device
  with interval > 0, reconciled by Refresh() (stop removed/changed, start
  new). No cron parsing. Poll errors log and continue; a failed collector
  build logs and leaves the device unpolled until the next Refresh. 60s fetch
  timeout default. Tests inject sub-second intervals via Options.Interval
  instead of sleeping on real-time PollIntervalSeconds.
- **Change handler is a callback** (`func(ctx, device, SaveResult)`); the
  serve command just logs for now. The analysis pipeline (configdiff Explain +
  RecordChange + reports) plugs into that seam next.
- **go.mod jumped to go 1.25.0** because current go-git/modernc releases
  require it; toolchain auto-download handles the local 1.22 install.

## 2026-06-09 - Analysis pipeline (snapshot change -> recorded findings)

- **Temp-file bridge to Explain().** `configdiff.Explain` is path-based and
  must stay untouched (stable public API), so `internal/pipeline` writes
  `SaveResult.PrevContent` and the current content to a throwaway
  `os.MkdirTemp` dir and removes it after the call. The report dir is the
  product artifact and is kept.
- **Report dir naming:** `<reportsRoot>/<deviceID>/<UTC YYYYMMDD-HHMMSS>-<8-char
  commit hash>`. Timestamp sorts naturally, the short hash disambiguates and
  ties the bundle back to the snapshot commit. The serve command roots reports
  at `<data-dir>/reports`.
- **Severity ladder** none < low < medium < high lives in the pipeline (rank
  map), not configdiff: configdiff emits per-finding severities, the rollup is
  a storage/UX concern. Unknown severity strings rank as none, so a future
  configdiff severity can't crash the rollup (it would just rank low until the
  map learns it).
- **Summary line format:** `"3 findings (1 high) - 5 blocks changed"`, where
  the parenthetical counts findings at the max severity tier. Zero-finding
  changes record `"no findings - N blocks changed"`.
- **First snapshots get a change row too** (summary "initial snapshot",
  severity none, `{}` analysis, no report dir): the timeline shows when
  monitoring began, and the scheduler's Changed=true on first save means the
  handler fires anyway.
- **Handler reloads content via snaps.GetAt(commit)** rather than widening the
  scheduler's ChangeHandler signature with a content param; keeps the seam
  stable and reads exactly the committed bytes.
- **HandleChange returns the recorded Change** (with the new row id) so the
  upcoming REST/notifier layers can use it without a re-query.

## 2026-06-09 - UniFi + SSH collectors, credentials encrypted at rest

- **Secrets format and key resolution.** `internal/secrets` wraps NaCl
  secretbox; values are self-describing `enc:v1:<base64 nonce+box>` strings so
  they live inside collector config JSON unchanged. Key resolution:
  `CUTSHEET_SECRET_KEY` env (64 hex chars) wins; otherwise a key is
  auto-generated at `<data-dir>/secret.key` (0600) on first use and loaded
  thereafter. Tradeoff, on purpose: the auto-generated file means anyone with
  the whole data dir has the key, but the boomer-friendly default (no env-var
  ceremony) still protects against partial leaks (db-only backups, SQL access,
  copied registry dumps). Document `CUTSHEET_SECRET_KEY` as the hardening
  knob, not a requirement.
- **Encryption boundary is `device add`, decryption boundary is Fetch.** The
  collector factory takes an optional `*secrets.Box`; `New(type, config, nil)`
  still works for validation because constructors never decrypt. Plaintext
  credentials in config pass through `decryptIfNeeded` untouched, so dev/test
  setups and pre-encryption configs keep working. `collector.EncryptConfig`
  knows each type's sensitive fields (unifi: password; ssh: password +
  private_key) and is a byte-for-byte no-op for types without any, so `file`
  device adds never even generate a secret key.
- **UniFi collector output determinism is the contract.** Controllers do not
  guarantee array order, and any byte flutter would make every poll look like
  a change. Output is one JSON document marshaled from a fixed-order struct
  (top-level keys: networkconf, portconf, port_overrides, firewallrule,
  firewallgroup, routing, wlanconf - exactly the sections the configdiff
  unifi-json parser keys on), object keys sorted by encoding/json's map
  ordering, arrays sorted by `_id` with a compact-JSON fallback for entries
  without one (port_overrides). Golden + shuffled-server tests pin this.
- **UniFi endpoints:** `/api/s/<site>/rest/{networkconf,portconf,firewallrule,
  firewallgroup,routing,wlanconf}` plus `/api/s/<site>/stat/device`, from
  which all devices' `port_overrides` arrays are flattened into the one
  top-level key the parser expects. Empty sections marshal as `[]`, keeping
  the shape stable.
- **UniFi auth auto-detect:** try UniFi OS first (`POST /api/auth/login`,
  API prefix `/proxy/network`), fall back to legacy (`POST /api/login`, no
  prefix). `unifi_os: true|false` pins the style and skips the probe.
  Cookie-jar session; the `X-CSRF-Token` from the OS login response is echoed
  on subsequent requests (some UniFi OS versions require it, harmless
  elsewhere).
- **SSH host-key policy:** verify against the configured `host_key` (openssh
  authorized-key format) via `ssh.FixedHostKey`; skipping verification
  requires the literal `insecure_ignore_host_key: true`. There is no silent
  fallback to InsecureIgnoreHostKey, and config without either is rejected at
  add time.
- **SSH presets** map to the show command whose output the matching configdiff
  parser consumes (edgeos/vyos share the vyatta wrapper command). Explicit
  `command` overrides the preset; the preset still drives the vendor default
  at `device add` (`--vendor` omitted: unifi -> unifi-json, ssh preset ->
  same-named vendor mode). Explicit `--vendor` always wins (flag.Visit
  detection, so `--vendor auto` is respected as an explicit choice).
- **In-process SSH test server gotcha:** after writing output and sending
  `exit-status`, the server must close the channel or the client's stdout
  reader never sees EOF and `session.Output` hangs forever (found as a 600s
  test timeout, not a clever insight).

## 2026-06-09 - Notifications (webhook + Discord, severity-filtered)

- **Severity ladder canonicalized in `store.SeverityRank`.** The rank map was
  born unexported in the pipeline; with the notifier needing the same ladder
  for its min-severity filter, the ordering moved to `internal/store` as an
  exported function (store owns the `none/low/medium/high` vocabulary on
  Change/Finding anyway). Pipeline's `maxSeverity` now delegates to it; the
  unknown-severity-ranks-as-none rule is preserved and documented there.
- **Retry policy: one retry, 2s backoff, 10s per-request timeout.** Both
  notifiers retry once on a 5xx response or transport error and fail fast on
  4xx (a rejected payload won't get better by resending). Backoff is an
  unexported field so tests run in milliseconds; the HTTP client is
  injectable, the default carries the 10s timeout.
- **`Fanout.Notify` returns nothing on purpose.** Delivery failures are
  logged per notifier and swallowed: one dead webhook must not block the
  other sinks or fail the pipeline. The serve handler fires it in the same
  goroutine as `HandleChange` since the timeouts bound the worst-case delay
  to one poll loop, not the process.
- **Min-severity filter semantics:** `none` notifies on everything including
  initial snapshots (their changes record severity "none"); the default
  `low` means any finding-bearing change. Empty MinSeverity also falls back
  to `low` so a zero-valued Fanout is safe.
- **Flag/env precedence:** `--webhook-url`, `--discord-webhook-url`,
  `--notify-min-severity` win over `CUTSHEET_WEBHOOK_URL`,
  `CUTSHEET_DISCORD_WEBHOOK_URL`, `CUTSHEET_NOTIFY_MIN_SEVERITY`; the env var
  only fills in when the flag was omitted (flag.Visit detection, same trick
  as `device add --vendor`). Invalid severities are rejected at startup, not
  at first change.
- **Discord embed gotcha:** Discord rejects embeds with empty field values,
  and initial snapshots have no report bundle, so an empty ReportDir renders
  as `(none)` in the Report dir field.

## 2026-06-09 - REST API (stdlib mux, token auth, on-demand snapshots)

- **stdlib net/http instead of chi/echo.** The design spec says "chi or echo";
  Go 1.22 method patterns on http.ServeMux (`GET /api/v1/devices/{id}`) cover
  every route this API needs with zero new dependencies. The deviation buys a
  leaner go.sum and one less framework idiom for contributors to learn; if the
  UI phase ever needs route groups or per-route middleware stacks, chi can be
  introduced behind the same handler signatures.
- **Auth model: bearer tokens in a new `api_tokens` table** (0002 migration:
  id, name, sha256 token_hash, created_at). Plaintext (`cst_` + 64 hex chars)
  is printed exactly once by `cutsheet token create`; only the hash is stored.
  ValidateToken hashes the candidate and constant-time-compares against every
  stored hash (no hash-indexed lookup), so neither lookup nor compare leaks
  timing. Managed by CLI only (`token create|list|rm`); there are deliberately
  no token CRUD endpoints in v1, so an API-level attacker cannot mint tokens.
- **Zero-token localhost mode, on purpose.** While no tokens exist, requests
  from loopback addresses pass unauthenticated; everything non-loopback gets
  401. Rationale: the boomer-friendly first run (`cutsheet serve` then curl
  from the same box, default listen is loopback-only anyway) must work with
  zero ceremony, but the moment the listener is exposed the operator creates
  a token and the door closes everywhere, localhost included. /healthz is the
  only permanently unauthenticated route.
- **Credential redaction is universal, not per-collector.** Responses parse
  collector_config and replace any top-level `password`/`private_key` string
  with `***` regardless of collector type (defense in depth for future
  types); a config that fails to parse is returned as `{}` rather than risk
  echoing raw bytes. Neither plaintext nor `enc:v1:` ciphertext ever leaves
  the server. PATCH treats `***` as "keep the stored credential" so clients
  can round-trip a GET response without wiping secrets; a new plaintext value
  re-encrypts through the same collector.EncryptConfig path as `device add`.
- **Validation extracted to internal/deviceconfig** (ValidID, Validate,
  ApplyDefaults, SuggestedVendor): one shared rule set for the CLI and the
  API. `cmd/cutsheet` keeps thin flag plumbing and delegates; API create
  mirrors `device add` defaults (name=id, vendor suggested-or-auto, collector
  file, interval 300, enabled).
- **SnapshotNow is an injected callback** (`func(ctx, deviceID)
  (*store.Change, bool, error)`) built in cmd/cutsheet, which owns the
  collector/snapshot/pipeline wiring. The analyze+record+notify step is one
  shared closure (makeProcessChange) used verbatim by both the scheduler tick
  handler and SnapshotNow, so the two paths cannot diverge. The fetch+save
  prelude intentionally parallels scheduler.poll rather than sharing it: the
  scheduler caches one collector per device loop and reports through a
  fire-and-forget handler, while snapshot-now builds a fresh collector from
  the current registry row and must return the recorded change.
- **Device mutations refresh the scheduler** via the DevicesChanged hook
  (serve wires it to sched.Refresh), so an API-created device starts polling
  without a restart.
- **Report serving is allowlist-first:** `{name}` must match
  `^[A-Za-z0-9][A-Za-z0-9._-]*\.(md|html|json)$` with `..`, separators, and
  non-basename forms rejected before any filesystem touch, and the joined
  path is re-checked to stay inside the change's report_dir. Content-Type is
  text/html for `report.html` only; .json is application/json, everything
  else text/plain + nosniff, so a crafted file in a report dir cannot become
  stored XSS.
- **min_severity filtering happens in SQL** (store.ListChangesOptions
  .MinSeverity expands the ladder into an IN list) so it composes correctly
  with limit/offset; filtering after pagination would under-fill pages.
  Changes list default limit 50, hard cap 500.
- **serve flags:** `--listen` (env CUTSHEET_LISTEN, default 127.0.0.1:8633,
  loopback by default on purpose) and `--cors-origin` (env
  CUTSHEET_CORS_ORIGIN) for the future UI dev server; preflights are answered
  before auth because they never carry Authorization. Graceful shutdown:
  http.Server.Shutdown with a 5s budget inside the existing signal path,
  then scheduler stop.

## 2026-06-09 - Web UI (Vite + React + TS, embedded via go:embed)

- **Dependencies: react, react-dom, react-router-dom, nothing else.** No UI
  kit, no fetch library, no state manager; one hand-rolled stylesheet
  (`web/src/styles.css`) with CSS variables. Severity colors match the
  notifier exactly (high #E74C3C, medium #E67E22, low #F1C40F, none gray).
  Dev gate is `tsc --noEmit` inside `npm run build` instead of adding vitest:
  the UI logic is thin enough that the type checker plus the Go-side serving
  tests cover the seams, and it keeps node_modules small.
- **`web/dist` is committed to git.** `go build ./cmd/cutsheet` and
  `go install` must work without Node (single-binary adoption story, same
  reasoning as SQLite-over-Postgres), and go:embed needs the files present at
  compile time. No build tag guard; the dist is just always there. Rebuild
  with `make ui` (npm ci + vite build) after touching `web/src`, then rebuild
  the server.
- **Embed lives in `web/embed.go` (package web), serving logic in
  `internal/webui`.** go:embed cannot reference files outside the package
  directory, so `internal/webui` cannot embed `../../web/dist` directly. The
  `web` package is a two-line embed.FS holder; webui owns the SPA rules and
  is the tested surface.
- **Routing: `webui.Root(api)` wraps the API handler with a tiny mux** -
  `/api/` and `/healthz` go to the API (auth, CORS, logging untouched),
  everything else to the SPA handler. Static files serve from the embedded
  FS; extensionless paths fall back to index.html (client routes survive
  refresh); pathy-looking asset names that do not exist 404 instead of
  returning HTML. The SPA itself is unauthenticated by design: it is a
  static shell with no data in it, and every API call it makes goes through
  bearer auth.
- **Report iframe uses a blob URL, not a direct src.** `<iframe src>` cannot
  carry an Authorization header, so once tokens exist a direct iframe at
  `/api/v1/changes/{id}/reports/report.html` would 401. The UI fetches the
  HTML with the bearer header and renders it from a Blob object URL; other
  report files download the same way.
- **Finding evidence comes from the analysis document.** The findings table
  rows (and findings JSON) deliberately do not carry evidence/details; the
  change detail page merges `analysis.risk_findings` into the stored finding
  rows by finding id to render evidence lines in monospace.
- **Auth state probe = GET /devices.** "Open access" (zero-token localhost
  mode) is detected as: request succeeds with no token stored. 401 renders a
  paste-a-token banner; Settings stores the token in localStorage and the
  fetch wrapper attaches it as a Bearer header.
- **Timeline findings count parses the summary line** ("13 findings (4 high)
  - 12 blocks changed") because the list endpoint intentionally omits
  findings; a count regex beats widening the list payload.
- **Smoke-tested end to end:** built binary in a temp dir, seeded file
  devices from the sample fixtures via the API, verified SPA shell at `/`,
  index fallback at `/devices` and `/changes/{id}`, JSON `/healthz`,
  hashed-asset content types, and headless-Chrome renders of all four views
  including a 13-finding high-severity change detail.

## 2026-06-09 - Release prep (demo mode, Docker, README)

- **Demo fixtures are embedded copies, not testdata reads.** `cutsheet demo`
  must work from any install location (Docker image, `go install` binary), so
  `internal/demo/fixtures/` holds copies of the four before/after testdata
  pairs (catalyst, edgeos, unifi, fortinet) behind a go:embed. go:embed cannot
  reach `../../testdata` across package boundaries, and reading the repo
  checkout at runtime would break installed binaries. Cost: ~8 small files
  duplicated; they only change when the testdata pairs do, and the demo test
  pins severity "high" per device so drift surfaces immediately.
- **Demo inventory:** core-switch (cisco-ios), branch-gateway (edgeos),
  campus-unifi (unifi-json), dmz-firewall (fortinet); all four pairs verified
  to produce high-severity findings (11/10/4/6). Seeding goes through the real
  file collector + snapshot store + pipeline, not a shortcut, so the data dir
  is indistinguishable from a real one and stays pollable (configs live at
  `<data-dir>/demo-configs/`). Refuses non-empty data dirs.
- **Dockerfile: alpine runtime, not distroless.** The compose healthcheck
  needs an in-container HTTP probe (busybox wget) and the token-bootstrap flow
  is friendlier with a shell for `docker compose exec`; the static binary
  makes the base choice cosmetic (~8 MB delta). Non-root user, /data volume
  pre-created with matching ownership.
- **ENTRYPOINT/CMD split instead of the spec'd full-serve ENTRYPOINT.** With
  serve args baked into ENTRYPOINT, `docker compose run cutsheet demo ...`
  would append the demo args to the serve command line. ENTRYPOINT
  ["cutsheet"] + CMD ["serve", ...] keeps `up` behavior identical while
  making one-shot subcommands (demo seeding, token create on a stopped stack)
  work the standard way.
- **Docker auth caveat documented in README:** published-port requests reach
  the container from the Docker bridge, never loopback, so the zero-token
  localhost allowance cannot apply in compose; the quickstart makes
  `docker compose exec cutsheet cutsheet token create` a first-class step.
  Compose publishes on 127.0.0.1 by default. NOT smoke-tested here: no docker
  on this machine; the image build + healthcheck + exec flow need a pass on a
  docker host before release.
- **README rewritten as the adoption surface** (docker-compose quickstart
  first, demo mode, real-device examples on 198.18.x, notifications, security
  model, roadmap teaser). Deep parser content (extraction lists, risk-finding
  list, limitations, architecture) moved to docs/parsers.md; the vendor table
  stayed in the README. The old CLI-centric README content survives between
  the two files.
- **`make build` now builds both binaries** (`cutsheet` from cmd/cutsheet,
  `cutsheet-cli` from cmd/cutsheet-cli). The old target built only the CLI
  under the name "cutsheet", which collided with the server binary the README
  now leads with. Added `make demo` and `make docker-build`.

## 2026-06-09 - Docker smoke test + dogfood correction

- **Docker smoke test PASSED** on a Proxmox CT (Ubuntu 24.04, docker.io 29.1.3,
  compose 2.40): image builds from the multi-stage Dockerfile, compose comes up
  healthy, docker-bridge requests correctly hit the zero-token 401 (confirming
  the README caveat), `docker compose exec cutsheet cutsheet token create
  --data-dir /data --name x` works exactly as documented, authed API + embedded
  UI serve, and tokens survive `compose restart` (named volume persistence).
  One compose note: the file intentionally has both `image:` and `build:` keys;
  use `docker compose up -d --no-build` when supplying a pre-built tag.
- **Dogfood plan corrected:** there is no UniFi controller or EdgeOS gateway
  available (earlier docs assumed one; the real home network is eero mesh with
  no managed switch). Primary live testbed is now containerlab VyOS/FRR via the
  existing SSH collector. A future "eero" collector against the unofficial eero
  cloud API is the real-gear path; it should emit a stable-sorted JSON snapshot
  (generic parser first, dedicated eero-json parser later).
