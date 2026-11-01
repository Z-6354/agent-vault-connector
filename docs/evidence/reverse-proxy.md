# Reverse proxy implementation and verification status

Date: 2026-11-01. Scope: source changes and local synthetic verification only. No public deployment, port publication, real configuration, credentials or provider accounts were used. No commit or push was performed.

## Starting working tree

The supplied session status reported existing uncommitted changes in `src/cli.ts` and `src/server.ts`. Their contents were read before editing: the CLI accepted `--allowed-origin`, the server returned that value as its origin and used it for all Host/Origin checks. The implementation preserves that option as a strictly validated alias. Those preexisting edits were not reverted. A fresh git diff/status could not be obtained because shell tools were blocked as described below.

## Changes

- `src/server-config.ts`: validate a single canonical HTTPS public origin (explicit numeric loopback HTTP exception), reject URL extras, wildcards, lists and noncanonical forms; reject simultaneous public/alias options. Bind defaults to `127.0.0.1`; the explicit alternative is `0.0.0.0`, requiring a configured HTTPS origin. These two binds preserve the standard local execution socket. Validation precedes vault construction and listening.
- `src/cli.ts`: expose `--public-origin`, validated `--allowed-origin` compatibility alias and `--bind-host`; print the listening socket separately from the public UI and local execution URLs; warn on wildcard binding.
- `src/server.ts`: management Host/Origin and OAuth redirects use the validated public origin. Execution retains its exact local Host and requires an actual loopback peer, bearer authentication, and no browser Cookie/Origin. Proxy trust remains disabled and forwarded headers do not affect authorization. All session cookie issue, renewal, lock rotation and logout clearing share Secure/HttpOnly/SameSite options. Default loopback HTTP cookies remain non-Secure. Login and unlock remain separate.
- `README.md`: precise startup, TLS nginx Host/Origin preservation, proxy-only firewall requirement, container mapping, local bridge network namespace and OAuth callback registration guidance.

## Focused checks added

`tests/reverse-proxy.test.ts` adds configuration rejection, default behavior and an actual local HTTPS reverse proxy with a disposable self-signed certificate and freshly initialized synthetic vault. It exercises management login/unlock, cookies on issue/renew/lock/logout, public callback metadata/client persistence, Host/Origin/CSRF denials, forwarded spoof denial, peer-address denial and an official SDK stdio bridge request plus lock denial. It requires the existing configured `TMPDIR` and uses no fallback scratch location. OpenSSL is required for the disposable TLS fixture; certificate validation is disabled only in that test's local HTTPS client. This is protocol integration through a real local proxy, not a Chromium browser acceptance run.

`tests/cli.test.ts` adds invalid public origin/alias/bind option subprocess checks. Existing server-auth and CLI tests are intended to cover affected default behavior.

## Actual commands and results

The following shell requests were attempted:

- `pwd; git diff -- src/cli.ts src/server.ts; rg --files -g 'CLAUDE.md' -g 'package.json' -g '*auth*' -g '*cli*' -g '*server*' -g 'README*'; printenv TMPDIR`
- `git diff -- src/cli.ts src/server.ts; rg --files -g 'CLAUDE.md' -g '*test*'; printenv TMPDIR`
- `git diff -- src/cli.ts src/server.ts; rg --files tests; printenv TMPDIR; git status --short`
- `npm run build`
- Final retry: `npm run build && node --test --test-concurrency=1 dist/tests/reverse-proxy.test.js dist/tests/server-auth.test.js dist/tests/cli.test.js`

Every request was blocked before execution with: `claude-sonnet-5[1m] is temporarily unavailable, so auto mode cannot determine the safety of Bash right now.` A read-only Explore agent request was blocked for the same reason. Dedicated Read/Edit/Write calls succeeded.

**Build and test results: unavailable; no tests have run.** The focused test command below is planned, not executed:

```sh
# Requires the already configured TMPDIR; do not substitute another scratch directory.
node --test --test-concurrency=1 dist/tests/reverse-proxy.test.js dist/tests/server-auth.test.js dist/tests/cli.test.js
```

## Developer follow-up: actual verification completed

The implementation CLI could not execute shell commands because its automatic approval classifier was unavailable, as recorded above; it produced no build/test result. The developer subsequently invoked the normal terminal tool with its own approval handling, without bypass flags or changing the commands. That invocation executed successfully:

`npm run build && node --test --test-concurrency=1 dist/tests/reverse-proxy.test.js dist/tests/server-auth.test.js dist/tests/cli.test.js`

Actual result: exit 0; build passed; 7 tests passed, 0 failed, 0 cancelled, 0 skipped; duration 6223.429569 ms. The observed test names were:

- serve rejects invalid public origin and bind options before vault access
- built CLI initialization really uses a PTY, hides input, creates usable v3 and refuses overwrite
- network configuration rejects ambiguous origins before opening a vault
- default exact loopback Host, Origin and non-Secure HTTP cookie remain unchanged
- real local TLS reverse proxy preserves public management origin and local stdio execution isolation
- management S0/S1/S2, one admin, epoch cookie/CSRF rotation and execution idle expiry
- manual drafts require exact confirmation and cancellation; record/status CAS; no direct-save route

A fresh `git diff --stat` and `git status --short` also executed. Current changes are README.md, src/cli.ts, src/server.ts, tests/cli.test.ts and new src/server-config.ts, tests/reverse-proxy.test.ts, plus this report. No full suite, SHA check, commit, deployment or public certificate test was performed. Actual local TLS proxy integration passed; real external mapping/DNS/nginx deployment remains unverified. Designated review for this change is complete: qualified pass, with no confirmed source blocker. Opinion author: Hermes @reviewer; this entry was transcribed by developer from the reviewer's message, not written directly by reviewer. The reviewer used the designated review-tool read-only path (exit 0), inspected the changes, TLS fixture and developer execution evidence, and did not personally run build/tests, modify source, deploy or perform SHA checks. No additional TLS-termination boolean is required: explicit HTTPS origin, explicit wildcard bind, CLI warning and proxy-only firewall documentation define the deployment boundary without pretending to verify it. OAuth origin migration fails closed (`redirect_uri_changed`/provider disabled); provider callback registration and local client configuration must both be updated, then authorization restarted with a new session/state. Old client-bound material is not reusable. That migration scenario was not directly dynamically tested. The README's obsolete approval-outage statement was corrected after review; this was documentation-only and no test rerun was needed.
