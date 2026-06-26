<!--
Thanks for sending a patch. Keep this short; delete sections that do not apply.
See CONTRIBUTING.md for what lands easily and what needs an issue first.
-->

## What and why

<!-- One or two sentences on the user-visible change and the problem it solves. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] Parser accuracy (new or corrected vendor finding)
- [ ] New read-only collector or vendor parser mode
- [ ] Docs
- [ ] Refactor with no behavior change
- [ ] Schema or API surface change (opened an issue first per CONTRIBUTING.md)

## Checklist

- [ ] `make test` and `make vet` pass locally
- [ ] Added or updated tests covering the change (a before/after fixture pair for analyzer changes)
- [ ] Updated the `Unreleased` section of `CHANGELOG.md` for any user-visible effect
- [ ] If I touched the web UI, I ran `make ui` and committed the rebuilt `web/dist`
- [ ] No real device IPs, hostnames, credentials, or RFC 1918 addresses in code, tests, fixtures, or this PR (use RFC 5737 `192.0.2.0/24` / RFC 2544 `198.18.0.0/15` and generic names)
- [ ] No code that writes to a managed device (collectors are read-only, permanently)
- [ ] Conventional commit messages, no AI co-authorship trailers
</content>
