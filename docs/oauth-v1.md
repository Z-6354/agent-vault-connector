# V1 OAuth adapters

Status on 2026-11-01: implemented and locally tested with an actual isolated HTTP OAuth simulator and encrypted SQLite storage. No GitHub or Google account, real application credentials, real provider token exchange, or production deployment was used. Passing synthetic tests are not real-provider validation.

## Scope and registration requirements

This implementation targets **GitHub.com OAuth Apps** and **Google OAuth Web application clients**. It does not implement GitHub Apps, Enterprise Server, native/public clients, device flow, service accounts, DPoP, or platform credential extraction.

Requirements below were checked against the public official sources on 2026-11-01. Exact source URLs and selected page excerpts are retained in `evidence/v1-oauth-official-sources.json`.

| Requirement | GitHub OAuth App | Google Web application |
|---|---|---|
| Registered client | Register an OAuth App and exact callback. Client ID and client secret are required for this web authorization-code exchange even with PKCE. | Register a Web application OAuth client, consent/audience configuration and exact authorized redirect URI. This confidential adapter requires client ID and secret. Google's REST parameter table labels the secret optional, while web-server examples supply it; this adapter does not implement public-client exceptions. |
| Authorization endpoint | `https://github.com/login/oauth/authorize` | `https://accounts.google.com/o/oauth2/v2/auth` |
| Token endpoint | `https://github.com/login/oauth/access_token` | `https://oauth2.googleapis.com/token` |
| Callback and state | Official page strongly recommends unpredictable state. Codes expire after 10 minutes. Current GitHub callback settings support exact or configurable wildcard matching, with older-app migration rules; configure exact matching. | Redirect URI must exactly match registration, including scheme/case/trailing slash. State binds the browser request to the callback and prevents CSRF. |
| PKCE | Official OAuth App page now documents `code_challenge`, S256 only, and the original `code_verifier` at token exchange. Both challenge parameters are paired. | Official Google discovery advertises S256. Google's desktop guide describes verifier/challenge syntax; its app registration rules are not used for this web client. The web-server guide itself does not describe PKCE. This adapter adds S256 and requires it in local tests; real web-client interoperability remains unverified. |
| Refresh availability | Current docs describe optional expiring OAuth App tokens. App settings or the `offline_access` scope opt in. Access tokens last eight hours, refresh tokens six months without use. A non-expiring token has no refresh token; absence does not mean an implementation failure. | Request `access_type=offline`. Issuance is conditional, commonly on the first authorization. Later authorization or refresh responses can omit `refresh_token`; preserve an existing usable same-subject refresh token. `prompt=consent` is explicit opt-in, not silently forced. |
| Refresh behavior | Refresh at the same token endpoint using `grant_type=refresh_token`, client ID, client secret and refresh token. Save the new access **and** refresh token atomically; the old pair is replaced. Scope cannot be changed during refresh. `bad_refresh_token` requires authorization again. | Refresh at the same endpoint with confidential client credentials. Preserve an omitted refresh token; save any returned replacement atomically. No claim that Google always rotates refresh tokens. Honor returned `expires_in` and conditional `refresh_token_expires_in` for time-based grants. |
| Revocation | `DELETE https://api.github.com/applications/{client_id}/grant`, HTTP Basic client ID/secret, JSON `{access_token:...}`, success 204. This adapter revokes the whole app grant; it does not use the single-token `/token` variant. | Form POST `token` to `https://oauth2.googleapis.com/revoke`, success 200. Prefer the refresh token when present. Current Google docs warn revocation removes project-granted scopes and invalidates access/refresh tokens across clients under the project. |
| Provider subject | Authenticated fixed `GET https://api.github.com/user`, bind stable `id`, not mutable login/account alias. | Fixed authenticated `GET https://openidconnect.googleapis.com/v1/userinfo`, require `openid`, bind `sub`. No unverified ID-token decoding. |

Google refresh tokens can fail after user revocation, inactivity, account/security or administrator changes, token-count limits, or time-based grant expiry. External projects in Testing normally issue seven-day refresh tokens, except qualifying basic identity-only scopes. These provider policies are documented requirements, not simulated production policy enforcement.

Official sources:

- [GitHub authorizing OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [GitHub OAuth application token/grant REST APIs](https://docs.github.com/en/rest/apps/oauth-applications)
- [GitHub authenticated user API](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)
- [Google web-server OAuth](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Google public OpenID configuration](https://accounts.google.com/.well-known/openid-configuration)
- [Google desktop PKCE syntax](https://developers.google.com/identity/protocols/oauth2/native-app)
- [Google token expiration](https://developers.google.com/identity/protocols/oauth2#expiration)
- [Google OpenID Connect scope and callback examples](https://developers.google.com/identity/openid-connect/openid-connect)
- [Google OAuth2 API scope definitions](https://www.googleapis.com/discovery/v1/apis/oauth2/v2/rest)

Google identity scopes have two explicit normalized spellings here: `https://www.googleapis.com/auth/userinfo.email` maps to `email`, and `https://www.googleapis.com/auth/userinfo.profile` maps to `profile`. Google's OpenID guide shows `openid email` authorization with the full email URI also present in its callback example, and the official OAuth2 API discovery defines both URI scopes. `normalizeOAuthScopes` applies these two aliases consistently to approved, requested and returned scopes; it does not rewrite arbitrary scope URLs or scopes of another provider. A real local simulator returns the URI spelling in both protocol and SQLite integration tests.

## Trusted adapter interface and storage

`src/oauth.ts` exports `createProductionOAuthAdapter`, `createSyntheticOAuthAdapter`, `OAuthAdapter` and `OAuthMaterialStore`. The trusted management caller supplies an authenticated binding containing owner, stable principal, management session and security epoch. `begin` returns only the authorization URL and expiry; `callback`, `refresh` and `revoke` return metadata without tokens.

The production factory uses a frozen source-controlled HTTPS registry. Endpoint, transport, arbitrary header and discovery overrides are rejected. Production token, identity and revocation requests reuse the shared public-address/DNS validation and connect to the validated IP with the original Host and TLS SNI. Private, metadata, mixed public/private and rebinding destinations are denied. Redirects are rejected; the complete request has a five-second deadline and 64 KiB response maximum. The explicit synthetic transport stays separate and literal-loopback only. Provider errors are mapped to bounded error codes, never descriptions or raw responses. Production callback configuration permits HTTPS, or the local product's literal-IP loopback HTTP callback with an explicit nondefault port and non-root path. Neither permits query, fragment or userinfo; exact origin/path binding is enforced locally regardless of a provider's more permissive registration settings. This exception concerns the local redirect only; production authorization, token, identity and revocation endpoints remain immutable HTTPS.

The separate explicit synthetic factory accepts only literal `127.0.0.1`/`[::1]` HTTP endpoints and callback. It rejects hostnames (including `localhost`), remote addresses, URL credentials, queries and fragments. `src/oauth-simulator.ts` binds an ephemeral `127.0.0.1` listener. The simulator checks registered callback, confidential client credentials, code lifetime/single use and the actual S256 verifier; it issues access/refresh tokens, rotates and invalidates refresh material, serves identity and processes revocation. Its authorization UI is an automatic synthetic approval/denial fixture, not a real user or browser consent test.

Authorization state and the 86-character random PKCE verifier live only in memory for 10 minutes. State binds the full target versions, approved requested scopes, owner/principal/session/epoch and configured callback. A bound denial, expired callback or successful callback consumes the state once. Duplicate code/state/error parameters, state mismatch and callback target changes are rejected. Restart loses pending authorization; lock/logout should call `invalidatePending` and always invalidate the security epoch in storage. The callback rechecks current authentication before exchange and before identity lookup.

`src/oauth-vault.ts` implements the typed storage interface over the core vault's `readMaterial`, `reserveMaterial` and `completeMaterial`. The `resolveAuthority` callback must validate a live trusted management session and derive the authenticated principal; it must not accept client-supplied authority as proof.

A user-approved existing record is mandatory. Its encrypted initial secret envelope is, for example:

```json
{"schema":1,"provider":"github","approvedScopes":["read:user"]}
```

For Google, the initial scopes used by tests are `["email","openid"]`. Core resource origins remain the registry's `https://api.github.com` and `https://www.googleapis.com`; authorization server origins are separate. A callback cannot create a connection or expand the approved scope ceiling. Product-issued material additionally binds its encrypted client ID/version and exact provider/mode/endpoints context. Replacing a client disables active grants until fresh authorization; old refresh material is never carried into another client generation. Confirmed resource authorization rejection moves only the matching current epoch/record/status/material to `needs_user_action`, preserving newer material and in-flight leases. Scope/provider changes require a separate confirmed record replacement. OAuth subject is obtained by authenticated identity lookup and a later authorization for another subject is rejected.

A durable exclusive material lease is reserved with record/status/material CAS **before** a token or revocation request. Competing refreshes cannot dispatch the same rotating refresh token twice. Completion checks the lease, versions and current epoch in one vault transaction, encrypts the updated envelope, and increments status/material versions without changing the user-approved record version. Execution must intersect local approved operations/scopes and provider-granted scopes; token presence does not grant arbitrary API access.

Google refresh responses that omit a refresh token preserve the old material. GitHub rotating responses require a new refresh token and expiry. Refresh scope expansion, malformed responses, redirects, network failure or lost rotation responses stop execution. Ambiguous dispatch is `outcome_unknown` (core `needs_user_action`) with an unresolved durable lease, retained across restart. There is no timer release or automatic retry. Confirmed `invalid_grant`/`bad_refresh_token` requires a new authorization. Successful revoke removes current token material and marks revoked. Local lock/epoch failure during completion leaves the blocking lease rather than writing after lock.

An unknown grant requires explicit administrator reconciliation before another authorization. Connection metadata exposes `material_change_unresolved`; while it is true, `can_execute` is false and material changes, including replacement, remain blocked. The core provides the recovery API and the management UI exposes it as **Reconcile OAuth material**. This action requires an unlocked authenticated administrator session, CSRF protection, a nonsecret evidence note and explicit confirmation that all old token material is abandoned. It never retries an uncertain rotating refresh or claims that the remote grant was revoked.

For a trusted management client, send `POST /management/connections/{id}/reconcile-material` with the current versions from connection metadata:

```json
{
  "expected_record_version": 1,
  "expected_status_version": 3,
  "expected_material_version": 2,
  "evidence_note": "Synthetic rotation response lost; abandon uncertain tokens",
  "abandon_old_material": true
}
```

The evidence note must contain 8–500 characters to satisfy both the public route and core checks; include only a nonsecret reference or explanation, never token/callback data. All three expected versions are mandatory CAS checks. A stale version, an ordinary execution identity, or an attempt to reconcile a current in-flight lease is rejected. Recovery is available for a lease recorded as outcome unknown, a lease invalidated by an epoch change, or a lease whose bound versions no longer match the record.

Successful reconciliation atomically discards the uncertain access/refresh material, preserves the approved provider/scope ceiling and already-bound subject, removes the blocking lease, sets core status to `needs_user_action`, and increments status/material versions while leaving record version unchanged. The returned connection has `material_change_unresolved: false` and remains non-executable. In the UI, enter the evidence note and confirm abandonment; the connection then requires a new provider authorization through the trusted adapter using the returned current versions. The previous rotating refresh token must never be retried. This is local abandonment and preparation for fresh authorization, not an upstream status query or revocation guarantee.

Retained encrypted comparison material follows the core retention policy; reconciling, revoking or deleting current material does not claim to erase historical encrypted idempotency comparison copies or backups. The separate management purge action controls retained comparison copies.

## Verification and remaining integration work

Run from the repository:

```sh
npm run build
node --test --test-concurrency=1 dist/tests/oauth.test.js dist/tests/oauth-vault.test.js
```

The captured command outcomes are in `docs/evidence/v1-oauth-validation.json` and `v1-oauth-tests.log`. Tests use random synthetic application secrets and new temporary encrypted SQLite directories only. Production factory tests inspect constructors/registry and rejection paths; they never begin production authorization or call provider endpoints.

Tests cover both provider profiles, callback/state/PKCE binding, code/refresh reuse, authorization and refresh expiry, denial/error/replay, scope approval, independent versions, refresh omission/rotation, concurrent refresh reservation, revocation, malformed/redirect/ambiguous response handling, encrypted database/audit non-disclosure, lock and restart. These are local protocol tests; no real provider or browser consent flow is validated.

The default local management routes and executor integration are now implemented and tested through explicit synthetic startup configuration; see [product acceptance](acceptance.md) for current commands and evidence. Actual registered provider applications, real client provisioning, specifically authorized accounts and live provider authorization/revocation remain unverified and were not used. Historical adapter test evidence above describes its own earlier snapshot. No production runtime configuration or secrets were inspected, and synthetic evidence does not establish production interoperability.
