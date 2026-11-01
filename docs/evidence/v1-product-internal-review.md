# Internal independent product integration review

Date: 2026-11-01

Result: no remaining confirmed blocker in the reviewed current product integration after the fixes described below. This is an internal independent source review and focused diagnostic result. It is not the designated Hermes `@reviewer` review; the final designated reviewer remains pending.

## Scope and basis

Reviewed against `V1-PRODUCT-INTEGRATION-ADDENDUM.md`, `PROJECT-DESIGN.md` section 8A, and the production destination restriction in `PROJECT-DESIGN.md` line 41.

Source inspection covered the default CLI/server and stdio bridge, product configuration isolation, OAuth product coordination and adapter/store, browser product coordination and modified controlled-host behavior, OAuth client encryption/migration, and vault operation replay, lock/epoch, material lease/CAS and reconciliation boundaries. Principal files were `src/server.ts`, `src/cli.ts`, `src/bridge.ts`, `src/product-config.ts`, `src/registry.ts`, `src/network.ts`, `src/oauth-product.ts`, `src/oauth.ts`, `src/oauth-vault.ts`, `src/browser-product.ts`, `src/browser.ts`, `src/vault.ts`, `migrations/004-oauth-clients.sql`, `public/app.js`, and `public/oauth-callback.js`. Relevant focused tests were inspected.

No implementation code was edited by this reviewer. This report was written after the current compiled build was available, the final helper and caller were inspected, and the focused tests below passed. The full historical 134-test suite and the product stable acceptance script were not run by this reviewer.

## Confirmed findings and final disposition

1. Production OAuth HTTP originally used native `fetch`, bypassing shared public-address validation and DNS pinning. This was a confirmed design violation: fixed HTTPS endpoint strings and disabled redirects do not reject private DNS answers or bind the validated resolution to the connection. Fixed in `src/oauth.ts:204` and `src/network.ts:66`: production token exchange, identity, refresh and revoke use `restrictedOAuthRequest`; the helper invokes the shared destination policy, rejects nonpublic/mixed answers, connects to the validated IP, preserves the original Host and TLS SNI, disables redirect following and bounds DNS/TLS/body time and response size. Synthetic HTTP remains confined to the explicit literal-loopback factory. Source and focused tests verified the fix; no actual external provider call was made.

2. A revoked OAuth resource token originally remained `active` and `can_execute: true`. The reviewer reproduced this locally with a nonexpiring synthetic GitHub authorization, direct upstream fixture revocation, and two separate authenticated execution requests: both calls reached the identity endpoint and returned operation `outcome_unknown`, with no refresh or credential state transition. Fixed in `src/network.ts:174`, `src/oauth-product.ts:236`, `src/registry.ts:152`, and `src/vault.ts:344`: a sanitized typed 401 classification marks the exact current OAuth connection `needs_user_action`. The transaction checks epoch, record/status/material versions and absence of a material lease. A stale response cannot poison newer or concurrently refreshed material. Generic 403 remains generic because it can represent provider rate limiting. The operation journal conservatively retains unknown outcome without retrying. Final local diagnostic and both-provider product route regressions verified refusal of a second dispatch and fresh authorization recovery.

3. The synthetic product originally could execute a registered GitHub API-key operation against the production destination because only OAuth traffic used the fixture hook. Fixed at `src/registry.ts:122` before operation registration/dispatch: synthetic mode refuses nonfixture production execution. The product route regression confirms `synthetic_external_execution_denied`.

4. OAuth material/client generation binding and explicit upstream cleanup after local revocation were reviewed in their corrected form. `src/oauth-vault.ts:59` and `src/oauth-product.ts:88` bind encrypted material to client generation and trusted provider/mode/endpoint context; incompatible material cannot refresh, execute or carry an old Google refresh token into new client consent. `src/oauth.ts:367` permits explicit upstream revoke when local policy is already revoked and material is still retained. Relevant focused tests cover both providers.

5. Previously identified integration issues were inspected in their corrected form: the bridge deadline is 20 seconds (`src/bridge.ts:28`); browser approval cards display the controlled session reference (`public/app.js:234`); product policy imports shared frozen `OAUTH_EXECUTION_POLICY` from the trusted registry (`src/oauth-product.ts:9`); synthetic-marked vaults cannot restart in production mode (`src/product-config.ts:24`); `playwright-core` is a runtime dependency. No remaining blocker was confirmed for these items.

## Focused verification performed by this reviewer

Command run against the current compiled build:

```text
node --test --test-concurrency=1 dist/tests/oauth-network.test.js dist/tests/product-routes.test.js
```

Result: 40 tests passed, zero failed, zero skipped (14 top-level tests including nested subtests), approximately 4.3 seconds. Network tests mock DNS/HTTPS and make no external requests. Coverage includes private/metadata/mixed DNS refusal, one-resolution IP pinning with Host/SNI preservation, form POST and composed revoke DELETE, redirects, response limits, deadlines, cancellation, sanitized errors and 401 versus generic 403. Product route tests cover both providers' actual management/execution routes, callback state/CSRF, concurrent refresh coalescing, unknown rotation recovery, explicit revoke, provider-side resource rejection, lock, startup isolation and schema-3-to-4 migration.

A separate ephemeral Chromium diagnostic used the actual server and callback relay, with a committed `localhost` synthetic provider page navigating back to the product at `127.0.0.1`. Observed request sequence:

| Request | Fetch site | Fetch mode | Management cookie present |
| --- | --- | --- | --- |
| Callback GET | cross-site | navigate | No |
| Relay callback POST | same-origin | cors | Yes |

The existing management cookie had `SameSite=Strict`. Authorization completed with exactly one code exchange and the Google fixture connection became active. This confirms that the static cross-site callback GET plus subsequent same-origin CSRF POST works with the actual default product server, rather than assuming that the Strict cookie accompanies the cross-site navigation.

The same final diagnostic then revoked the Google fixture grant directly upstream and invoked the authenticated execution route twice with different server-issued tickets. The first operation remained conservatively `outcome_unknown`, the connection changed to `needs_user_action` with `can_execute: false`, and the second request returned 409. Only one resource identity call occurred and no refresh occurred.

Diagnostic temporary vaults and browsers were closed and removed. No tokens, client secrets, callback codes or raw upstream bodies are recorded in this report.

## Boundary assessment

Operation replay is consulted before OAuth preparation, so completed/unknown replays do not refresh or contact a provider. In-process refresh coalescing is backed by a persistent exclusive lease and material/version CAS; an uncertain rotating result leaves a durable blocking lease and requires explicit reconciliation rather than retrying old refresh material. Lock/epoch and live administrator session checks prevent stale callback/refresh completion. These paths reuse the existing adapter and vault state machines.

Management and execution route authentication remain separate. The bridge exposes fixed operations and fixed controlled browser sites/actions; no management approval tool, arbitrary endpoint, selector, script, cookie or secret DOM output is exposed. Browser fill and submit require separate human approvals; the host binds the exact original document, context, principal, record/status versions, epoch and TTL and rechecks before use. Product replay reconstructs the durable submit input before consulting expired ephemeral approval state.

## Plausible concerns and limits

No additional plausible security/correctness concern was elevated to a blocker in this review. Real GitHub/Google registration, live provider consent behavior and production TLS interoperability remain unverified; the production network checks use deterministic fake DNS/HTTPS tests. The Chromium callback diagnostic used local synthetic providers. Five-Agent integration, external deployment and optional model input are outside this internal review. The separate product CLI/UI/stdio acceptance result and final designated reviewer must be recorded independently; this report does not substitute for either.

## Final lock-error contract follow-up

After the review above, the coordinator reported that actual stdio acceptance exposed the legacy `Vault locked` message being replaced by the bridge's generic error sanitizer. The final delta at `src/server.ts:96` now checks `vault.unlocked` after validating the execution credential and throws HTTP 423 with the controlled code `vault_locked`. The reviewer inspected this source change, the bridge's existing controlled-error forwarding at `src/bridge.ts:45`, and the exact assertions at `tests/server-auth.test.ts:70` and `tests/browser-product.test.ts:252`. `vault.unlocked` retains the vault's epoch invalidation behavior; credential validation still precedes the lock response, and denial still occurs before execution rate accounting or dispatch. No blocker was found in this delta. No further tests were run by this reviewer.

Coordinator-provided validation is separate from the reviewer's own checks: the coordinator reports the final build and 13/13 directly affected tests passed after this delta, following the earlier combined 88/88 focused run. The reviewer read `docs/evidence/v1-product-acceptance.json`, which records `result: passed`, completed `2026-11-01T08:37:48.279Z`, actual CLI initialization/serve and official SDK stdio bridge, both-provider synthetic authorization/one concurrent refresh/revoke paths, separately approved browser fill/submit and cookie reuse, `vault_locked` denial and stale approval refusal after unlock. The coordinator also reports inspecting `docs/evidence/v1-product-acceptance.png`. This reviewer did not rerun that acceptance driver or independently inspect its screenshot. These remain local synthetic acceptance results. This follow-up preserves the internal review verdict of no remaining confirmed blocker in the reviewed scope; designated Hermes `@reviewer` approval remains pending.
