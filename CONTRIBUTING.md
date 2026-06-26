# Contributing to Cutsheet

Cutsheet is a self-hosted network change intelligence platform: it watches device configs, keeps a git-backed history, and runs each change through a deterministic risk analyzer. Patches are welcome. Before you start, please skim this file so we both spend our time on the right things.

## What kinds of changes land easily

- **Bug fixes** in the analyzer, collectors, snapshot store, scheduler, API, or web UI.
- **Parser accuracy**: better extraction, new risk findings, or fixes to a vendor parser path, with a fixture pair that demonstrates the change.
- **New vendor parser modes** under `pkg/configdiff`, with tests.
- **New read-only collectors** that fit the existing `collector` interface.
- **Test coverage** for any of the above.
- **Docs**: clarifying the README, `docs/parsers.md`, or a confusing flag.

## What needs a conversation first

- **A new collector that talks to a device.** Open an issue describing the device and the read API or commands it uses. Collectors are read-only on purpose, and that boundary is load-bearing.
- **Breaking changes** to the `diff-analysis` JSON schema, the REST API surface, or the report bundle file set. Downstream tooling reads those.
- **A new runtime dependency.** Cutsheet ships as a single self-contained binary; keep the dependency tree lean.
- **Anything that could write to a managed device.** This will not be accepted. Collectors fetch config and nothing else, permanently.

## What does not land

- Real device IPs, hostnames, credentials, or RFC 1918 addresses in code, tests, fixtures, or docs. Use RFC 5737 (`192.0.2.0/24`) or RFC 2544 (`198.18.0.0/15`) ranges and generic device names. The whole point of this tool is to keep that data on your own hardware; do not paste yours into the public repo.
- Cron jobs, telemetry, or any code that calls out to the network without explicit operator opt-in (webhooks are configured by the operator, not baked in).
- AI co-authorship trailers on commits (`Co-Authored-By: <model>`). Conventional commits only.

## Local dev

```bash
git clone https://github.com/solomonneas/cutsheet.git
cd cutsheet
make test    # go test ./...
make vet     # go vet ./...
make build   # builds ./cutsheet (server) and ./cutsheet-cli (diff CLI)
```

Smoke-test the full pipeline with zero hardware:

```bash
make demo                              # seed ./demo-data with sample devices
./cutsheet serve --data-dir ./demo-data
# open http://localhost:8633
```

If you change the web UI under `web/src`, rebuild the embedded assets and
commit the result (CI checks `web/dist` for drift):

```bash
make ui
```

## Adding a vendor parser

The analyzer lives in `pkg/configdiff`. A vendor parser turns config text into a structured form the risk rules can reason over. To add one:

1. Add the parser path and its vendor-mode aliases in `pkg/configdiff`.
2. Add a before/after fixture pair under the package's testdata (or `internal/demo/fixtures` if it should feed demo mode) using safe addresses and generic names.
3. Add a test that asserts the expected risk findings on that pair.
4. Add a row to the vendor support table in `README.md` and update `docs/parsers.md`.

## Filing issues

Please use the templates under `.github/ISSUE_TEMPLATE/`. They exist to save you from re-typing the version and setup shape every time.

For a parser-accuracy report, the most useful thing you can attach is a **redacted before/after config pair** that reproduces the wrong (or missing) finding. Scrub device IPs, hostnames, and any credentials first; the analyzer is deterministic, so a clean fixture pair is usually enough to reproduce and fix the bug.

Do not file security issues publicly. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contribution is licensed under the Apache License 2.0, same as the rest of the repo.
</content>
