# Security Policy

## Supported versions

Cutsheet is pre-1.0 and moving fast. Only the latest commit on the `main` branch receives security fixes. Build from a known commit if you need a fixed reference point.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Email **me@solomonneas.dev** with: <!-- content-guard: allow pii/email -->

- A short description of the issue.
- Steps to reproduce (or a minimal proof of concept).
- The commit or image tag you tested against.
- Whether you would like to be credited in the release notes.

You should get an acknowledgment within 72 hours. If you do not, please follow up; the mail may have been filtered.

## In scope

- Credential disclosure: anything that exposes a stored device password, SSH private key, or session token in plaintext, in an API response, in logs, or on disk outside the secretbox-sealed column.
- Auth bypass on the REST API: reaching a protected endpoint without a valid bearer token, the constant-time comparison failing open, or the localhost tokenless allowance applying when it should not.
- A collector that writes to a managed device. Collectors are read-only by design; any code path that mutates device state is a security bug, not a feature.
- SSH host-key verification bypass, or the `insecure_ignore_host_key` path being reachable without the explicit opt-in.
- Path traversal or symlink-attack flaws in the data directory, snapshot store, or report bundle writer.
- Encryption-at-rest weaknesses: predictable keys, key material leaking into the database or logs, or the secret key file landing with permissions broader than owner-only.
- Server-side request forgery or injection through device config, collector config, or webhook URLs.

## Out of scope

- Issues that require an attacker to already have read or write access to the host, the data directory, or the `CUTSHEET_SECRET_KEY`.
- Findings from the deterministic analyzer being incomplete or wrong on a given vendor config. That is a parser-accuracy bug; file a normal issue with a redacted fixture pair.
- Exposing the server on a public interface without a token and without a reverse proxy. The server binds `127.0.0.1` by default for a reason; running it open is an operator choice, not a Cutsheet vulnerability.
- Denial of service from pointing a collector at a device that returns enormous or malicious config (still useful to report, but triaged as a robustness bug).
- Vulnerabilities in upstream dependencies without a demonstrated impact on Cutsheet. CI runs `govulncheck`; if it flags something exploitable here, that is in scope.

## Disclosure

We aim to ship a fix within 14 days of confirming a valid report. A coordinated disclosure timeline can be negotiated for issues that need longer.
</content>
