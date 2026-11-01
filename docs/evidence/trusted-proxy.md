# Explicit trusted loopback reverse proxy

Date: 2026-11-02. Scope: source, documentation and focused synthetic tests. No commit, deployment, restart of port 3210, full suite or SHA check was performed. No production configuration or `<data-dir>` files were read. The existing diagnostic implementation and tests were preserved.

## Administrator-supplied gateway evidence

The administrator supplied this actual single anonymous gateway observation; it was not collected or independently reproduced in this implementation session:

```json
{"event":"host_denied","host_count":1,"host_values":["127.0.0.1:<port>"],"origin":[],"x_forwarded_host":["vault.example.com"],"x_forwarded_proto":["https"],"peer":"127.0.0.1"}
```

The observation supports one precise rewriting shape, not a general inference about proxy behavior or provenance. Absence of Origin in an anonymous navigation does not waive Origin or CSRF for management mutations.

## Implemented contract

- `--trusted-proxy loopback` is an explicit opt-in, default off, requiring a configured canonical HTTPS public origin. Invalid values/configuration fail before vault access. Fastify retains `trustProxy: false`.
- Rewritten Host must be exactly `127.0.0.1:<actual-listening-port>`. Exactly one raw Host is required. Exactly one raw X-Forwarded-Host must equal the fixed configured public origin's host, including any nondefault port, and exactly one raw X-Forwarded-Proto must equal `https`. Comparisons do not split lists or normalize case/ports. Missing, duplicate, comma/list and conflicting values fail closed. RFC Forwarded is rejected in trusted mode to avoid a conflicting forwarding dialect.
- The actual socket peer (`request.raw.socket.remoteAddress`) must be exactly one of `127.0.0.1`, `::ffff:127.0.0.1`, `::ffff:7f00:1`. The latter two explicitly represent IPv4-mapped 127.0.0.1. This is the complete string allowlist; IPv6 localhost, other 127/8 addresses, hostnames, alternative textual encodings and forwarded IP assertions are not accepted.
- Established direct public Host requests still pass without forwarding fields. In trusted mode, forwarding fields on that path must satisfy the complete tuple and peer checks; conflicts fail closed.
- Forwarded values never select an origin. Management mutating requests still require configured public Origin and the session's CSRF token. Static assets, OAuth metadata and callback paths retain that same fixed public origin.
- Execution requires exact local Host, accepted actual socket peer and valid execution bearer, and rejects either X-Forwarded-Host or X-Forwarded-Proto even with otherwise valid values. Browser Cookie/Origin remain forbidden. Official local stdio sends no such forwarding fields.
- A loopback peer does not establish gateway provenance. The deployment must restrict upstream access and make the gateway overwrite/strip client-supplied forwarding values. These headers are not authentication; local processes can forge them. README and CLI warn explicitly.

## Diagnostics and operation

The existing `src/proxy-diagnostic.ts` and `tests/proxy-diagnostic.test.ts` remain intact. Logging stays off by default and is bounded and allowlisted to Host/count, Origin, X-Forwarded-Host, X-Forwarded-Proto and actual socket peer on host denial. It receives no request/logger object and logs no cookie, authorization, URL/query or body. Existing tests check sanitization, duplicate counting, bounds and canary exclusion.

README documents the existing port 3210 and exact administrator-supplied public origin with `--trusted-proxy loopback --diagnose-proxy-headers false`, retaining operator-supplied existing data/product-config arguments. Disable temporary diagnostics after sampling by omitting the option or specifying false on the next operator-controlled startup. No running process or diagnostic setting was changed by this session.

## Focused checks prepared

`tests/reverse-proxy.test.ts` preserves the previous default and real local TLS preserved-Host tests and runs the TLS integration again in explicit trusted mode. The trusted fixture is a real local HTTPS-to-HTTP proxy that overwrites upstream Host and the two forwarding fields while preserving the browser's original Origin. It uses a disposable certificate and task-created synthetic vault. Both variants exercise S0/login/unlock/lock/logout, Secure cookies, callback metadata/client redirect, static assets and callback navigation, public-Origin/CSRF rejection, execution gateway denial, and a real official SDK `StdioClientTransport` child process against the built bridge, including successful local list and denial after lock.

Additional checks cover configuration opt-in, exact accepted/rejected peer strings, raw duplicate Host/forwarded values, lists, wrong upstream port/Host, protocol/case mismatch, conflicting direct-public forwarding, absent forwarding fields, RFC Forwarded, spoofed forwarded IP, execution rejection of either forwarding field, missing/invalid bearer and browser Cookie/Origin. CLI invalid-option cases were added to the existing CLI tests. Existing server-auth tests remain part of the requested focused command.

## Actual commands and results

Read-only discovery requests were attempted twice and blocked before execution by the automatic approval classifier. Dedicated Read/Edit/Write tools worked.

The following exact verification command was attempted twice:

```sh
npm run build && node --test --test-concurrency=1 dist/tests/proxy-diagnostic.test.js dist/tests/reverse-proxy.test.js dist/tests/server-auth.test.js dist/tests/cli.test.js
```

Both attempts were blocked before execution with:

> claude-sonnet-5[1m] is temporarily unavailable, so auto mode cannot determine the safety of Bash right now.

**Developer follow-up: verification completed in this session.** The implementation CLI's automatic approval service was unavailable, so its commands above did not execute. Developer subsequently used the normal terminal tool with its approval handling, without bypass flags, to execute that same focused command. First build exposed an actual literal Unicode line separator inside a test regex; it was changed to `\\u2028`. The next run built and passed 10/11; the sole failure was a test helper's default parameter replacing an explicitly supplied `undefined` peer, not the production guard. The test now passes `undefined` directly to `requestHostAllowed`. Final actual execution: build exit 0; 11 tests passed, 0 failed, 0 cancelled, 0 skipped; duration 13019.996474 ms. This includes real rewriting TLS proxy, preserved-Host TLS proxy, official stdio bridge, diagnostic canary exclusion, CLI validation and server authentication/CSRF/lock behavior. No full suite or SHA check was run. External gateway acceptance remains pending an operator-controlled restart; port 3210 was not changed and the only external header observation here remains administrator-supplied. Designated reviewer follow-up is pending.
