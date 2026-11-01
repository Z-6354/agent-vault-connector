# Agent Vault Connector — local V1

A single-user credential center with a loopback management UI, encrypted SQLite storage and a standard MCP stdio execution bridge. The core starts and runs without a model or ASR. Current implementation follows [V1-IMPLEMENTATION-PLAN.md](V1-IMPLEMENTATION-PLAN.md) and [PROJECT-DESIGN.md §8A](PROJECT-DESIGN.md); historical pause/scope documents are not the current authorization.

The default CLI/server/UI and stdio MCP now wire controlled-browser approvals and GitHub/Google OAuth configuration, authorization, callback, execution refresh and revocation, as required by the [product integration addendum](V1-PRODUCT-INTEGRATION-ADDENDUM.md). Validation passed **build, 88/88 focused tests, a final 13/13 overlapping lock/browser check, and actual CLI + Chromium UI + official stdio MCP product acceptance** against separate GitHub/Google loopback providers. Exact commands, evidence and the two corrected acceptance failures are recorded in the [acceptance report](docs/acceptance.md). The historical **134/134** suite and library demos remain valid evidence for their earlier snapshot, not a full-suite result for this changed code. Internal implementation reviews are separate from the designated Hermes `@reviewer`, whose final assessment remains pending. The [five-agent compatibility matrix](docs/compatibility.md) remains unverified for actual tasks. No real secrets, existing agent configuration, real provider/account calls, tunnels, deployment or commits were used.

## Install and build

Use Linux, Node **22.13 or later within Node 22**, and npm. `better-sqlite3` may require a C++ toolchain and Python if its native prebuild is unavailable. Browser acceptance requires `/usr/bin/chromium` and Python 3 for PTY initialization. Run commands from the project directory.

```sh
npm ci --no-audit --no-fund
npm run build
```

For an isolated install that avoids personal npm configuration, create separate empty user/global npmrc files in a private scratch directory and pass them through `npm_config_userconfig` / `npm_config_globalconfig`. Do not copy existing agent configuration or `.env` into this project. `package-lock.json` records dependency resolution. Dependency vulnerability auditing is not part of the recorded acceptance.

## Initialize and start

```sh
node dist/src/cli.js init --data-dir ./data
node dist/src/cli.js serve --data-dir ./data --port 43120
```

`init` requires a real interactive terminal and prompts twice without echo for a 12–1024 character passphrase. It accepts no passphrase CLI argument or environment variable. It refuses a nonempty data directory. The data directory must be current-user-owned `0700`; files are `0600`, regular and not symlinks. Initialization creates an encrypted database, an execution access key and a separate persistent request-signing key. Never place these keys in prompts, command arguments or logs.

Open **http://127.0.0.1:43120** on the same machine, using the exact IP and port. The server listens only on `127.0.0.1`; `localhost`, alternate Host values, cross-origin access and proxy rewriting are unsupported. Every restart starts locked. The management flow is:

1. Log in with the initialization passphrase: S0 → S1 (authenticated, still locked).
2. Unlock with the passphrase: S1 → S2 (authenticated and unlocked).
3. Enter the type, registered service/origin, account and operation grants. Review the secret-free confirmation card before saving. A replacement binds the target's current `record_version`; a conflict requires a fresh review.
4. Pause/revoke using the current `status_version`, replace/delete using the current `record_version`, or explicitly lock/log out when finished.

The management UI includes recent audit events and a **Recover save result** panel. It remembers only the opaque signed save request ID in tab `sessionStorage`, never the secret, draft, transcript or approval. If a save response is lost or the server restarts, log in/unlock and recover using that request ID: the server returns retained completed metadata without saving again or requiring the old approval. Recovery is scoped to the stable authenticated administrator and returns unavailable after retention/purge; an uncommitted draft cannot be recovered after restart.

Lock returns the current administrator to a restricted S1 session with a rotated cookie/CSRF token; old cookies, drafts and approvals fail. Logout, a 15-minute administrator idle timeout or process restart enters S0 and globally locks execution. MCP traffic does not extend administrator idle time. Closing a tab does not immediately log out. There is at most one active administrator session. Failed passphrase attempts and request rate limits return controlled errors.

The registry separates fixed synthetic HTTP fixtures from source-controlled production HTTPS destinations. API keys and passwords work without a model. `external_reference` stores metadata with no secret envelope and always has `can_execute=false`.

### Controlled browser configuration

The browser host is disabled unless explicitly enabled. Save a current-user-owned regular `0600` JSON file outside the vault directory, for example:

```json
{"mode":"production","browser":{"enabled":true,"executablePath":"/usr/bin/chromium","headless":true}}
```

Start with `node dist/src/cli.js serve --data-dir ./data --port 43120 --product-config /absolute/private/product.json`. The only registered browser site is the known synthetic login fixture at **http://127.0.0.1:43122**; this does not add arbitrary website support. The acceptance script starts that fixture automatically. An unconfigured host reports `unsupported`.

MCP requests a session and a pending `browser_fill` or `login_submit` approval. In the management UI choose **Refresh approvals**, inspect the authenticated execution principal, exact fixed site, record/version, action and expiry, then approve that action. Fill and submit require separate single-use approvals; MCP has no approval tool. Fill does not submit. After an approved login, safe session status verifies host-owned cookie reuse at the fixed account page. Original document identity, five-minute handle TTL, 60-second approvals, record/status/rules versions and epoch checks remain enforced. No URL, selector, script, cookie or secret DOM interface is exposed.

### GitHub and Google OAuth

Without a saved client, each provider is disabled with `client_not_configured`. In **OAuth provider setup**, manually register the appropriate provider application using the exact displayed callback, then enter its client ID and secret. The product configures that registered client locally; it does not register a remote application. Client configuration is encrypted in SQLite with version CAS; secrets are password inputs, cleared after submission and never read back. The fixed production upstream endpoints cannot be changed by management or startup configuration. Local callbacks are `http://127.0.0.1:<port>/management/oauth/callback/github` and `/google`; changing the serve port requires updating both provider registration and local client configuration.

Create and review an OAuth connection through the ordinary save flow. Its fixed minimum scopes are GitHub `read:user`, or Google `openid email`. The saved placeholder starts `needs_user_action`. Choose **Authorize**, review the optional consent-screen checkbox, and click the expiring provider link. The protected callback binds the initiating management session, owner, connection/versions, state, PKCE, epoch and expiry. A static navigation relay strips code/state from the address and completes authorization through an authenticated same-origin CSRF POST, preserving strict cookies. Lock/logout/restart invalidates pending authorization.

Actual stdio `execute_operation` uses the encrypted material for fixed `github.current_user` or `google.userinfo`. Expired access material refreshes under durable lease/CAS before dispatch; concurrent requests for one connection share one refresh. Token material binds the exact client generation and provider/mode/endpoints; replacing a configured client requires fresh authorization and cannot reuse the old refresh token. Resource authorization rejection moves the current matching material to `needs_user_action` without an automatic retry. Missing refresh material requires authorization again. An unknown rotating-refresh result remains blocked as `needs_user_action`; **Reconcile OAuth material** abandons old material with reviewed evidence, then **Reauthorize** starts fresh. It never retries the uncertain refresh token. **Revoke OAuth** calls the provider revocation flow and removes local token material. Local generic record revocation/deletion alone is not provider-side revocation. Production registration, account consent and provider interoperability remain untested in this authorized synthetic run; see [OAuth requirements](docs/oauth-v1.md).

## Synthetic operation and MCP

Start the fixed local mock in another terminal:

```sh
node dist/src/cli.js mock
```

It binds **http://127.0.0.1:43121** only. In the UI choose `synthetic-mock`, enter an account alias and a token such as `synthetic_example_token_123456`, and grant `mock.account_summary`. The synthetic token format is deliberately restricted to `synthetic_[A-Za-z0-9_-]+` (16–512 characters). The mock's reflection/redirect/oversize/timeout behaviors test filtering and denial; never put real credentials in it.

A local MCP host should launch Node directly so stdout contains only MCP protocol:

```json
{
  "mcpServers": {
    "local-vault": {
      "command": "node",
      "args": [
        "/absolute/project/path/dist/src/cli.js", "bridge",
        "--origin", "http://127.0.0.1:43120",
        "--credential-file", "/absolute/project/path/data/execution.key"
      ]
    }
  }
}
```

The bridge reads only the explicitly supplied protected execution credential file. The server maps it to a stable execution principal; request arguments cannot select another identity. This credential grants center execution access, not upstream provider access or management rights, and it cannot unlock the vault.

Execution clients discover `list_connections`, `list_operations`, `get_connection_status`, `prepare_request`, `execute_operation` and `get_operation_status`, plus `browser_sites`, `browser_open_session`, `browser_session_status`, `browser_request_approval`, `browser_approval_status`, `browser_fill` and `browser_submit`. Obtain a server-issued ticket with `prepare_request({"operation_name":"mock.account_summary"})`, then call:

```json
{
  "connection_id": "<connection UUID>",
  "operation_id": "mock.account_summary",
  "expected_record_version": 1,
  "request_id": "<server-issued ticket>",
  "args": {}
}
```

The center injects authentication only inside the fixed executor and returns reviewed fields. There is no arbitrary URL/header/path/script, shell, secret-read, unlock or management tool. Reuse the same ticket for retry/status; it returns the persisted state/result and does not dispatch again. After a timeout/disconnect following dispatch, `outcome_unknown` means **possibly executed, needs reconciliation**. It is not a safe automatic retry, and changing the request ID does not establish that repeating a side effect is safe. The management operation history lets an authenticated administrator record reviewed upstream evidence as confirmed success/failure, or explicitly authorize a new attempt while accepting duplicate risk. Reconciliation uses the current operation status version; it does not itself dispatch the operation.

These internal authenticated HTTP routes are not a Streamable HTTP MCP service or MCP OAuth authorization server. Remote cloud clients cannot reach this machine by naming localhost. No remote endpoint, tunnel, public port or TLS deployment is supplied. OAuth-only remote clients remain unsupported.

## Optional components and explicit limits

`src/delegation.ts` keeps external references nonexecuting and defines a separate `TrustedDelegationHost`/`DelegationExecutor`. A formal grant binds owner, center and upstream identities/account, grant source/evidence, audience, resources, scopes, operations, endpoints, expiry and revocation. Each call checks the intersection with local policy and verifies current host state. The actual HTTP loopback fixture authenticates both directions and tests denial; it is an explicitly synthetic protocol, not an invented platform API. Production delegation is not wired into MCP or any of the five agents. A real adapter must be formally authorized and use the core's durable A3 dispatch state machine; no token export or shell workaround is supported.

`src/local-draft.ts` is an optional injectable component. `LocalDraftSession` requires an explicit numeric loopback inference interface; ASR is separately injectable. `bindVaultLocalDraftCore` calls the actual immutable draft/approval APIs and requires a trusted session/CSRF validator. `src/enrollment-mcp.ts` supplies a separate trusted official-SDK in-memory MCP channel exposing only `save_credential`; the real core consumes the approval atomically. Tests exercise draft → confirmation → actual MCP save and replay. This enrollment channel is not exposed to inference or ordinary execution clients. Inference cannot self-approve. A confirmation uses the retained exact secret; cancellation, timeout, editing and lock invalidate pending drafts. The component stores no transcript/audio/history. It is a library integration point, not a configured model service or an enabled UI/CLI voice flow. Tests inject deterministic **synthetic fixtures**; no model or ASR inference ran. No approved model/ASR endpoint exists, no endpoint was guessed, and no cloud fallback is provided. A loopback URL alone does not prove a backend never forwards data; completely-local operation is **unverified**.

## Storage, migration and retention

Secrets use AES-256-GCM with independent random nonces and authenticated record/request contexts. Scrypt derives encryption material from the passphrase; administrator authentication uses an independent salt/domain. Master key material stays in process memory and the retained key Buffer is zeroed on lock. JavaScript strings, browser input, native buffers, OS swap/core dumps and same-UID processes are outside any guaranteed memory erasure boundary. Metadata, record/account labels, origins, operation grants, timestamps and audit identifiers are not encrypted; do not put secrets in metadata.

Startup applies migrations through schema v4 transactionally. The new `oauth_clients` table encrypts client configuration separately from credential material. Before upgrading a v3 database it creates the private `vault.pre-v3-to-v4.sqlite` backup. Existing v1/v2 upgrades retain their `vault.pre-v1-to-v3.sqlite` or `vault.pre-v2-to-v3.sqlite` original backup and continue through v4. Existing backups are never overwritten. Legacy records are paused with no operation grants; review/regrant them explicitly. Existing v2 audit history is preserved in `legacy_audit_events_v2`, with sanitized identifier/time preservation events in the current audit table. Newer/unknown schema versions fail closed. Do not edit version pragmas or migration SQL to force a database open. A failed initialization can leave a partial directory which is intentionally not overwritten; inspect before removing task-created partial data.

Request tickets are scoped to owner, stable principal and operation. New registration expires after 24 hours. Completed results and encrypted canonical comparison copies have a 7-day availability/retention boundary; cleanup runs at startup and every minute while the server runs. Request tombstones prevent reexecution after comparison removal. Unresolved external-operation records are not automatically discarded. Deleting a current credential does **not** immediately erase retained encrypted request comparison copies, backups, or upstream tokens. The administrator's **Purge retained copies** action removes retained request comparison copies/results for the connection while keeping tombstones; subsequent retries return `result_unavailable`. This action does not delete backup copies and is not an ordinary MCP tool. Audit events contain identifiers/actions/versions/outcomes, not request bodies or secret digests; no automatic audit expiry is configured. See [acceptance](docs/acceptance.md) for the actual cleanup integration and remaining limitations.

## Backup and recovery

Stop the server and all bridges before copying or restoring. For a consistent cold backup copy the **whole private data directory** to trusted local storage while preserving `0700`/`0600` permissions, including `vault.sqlite`, `execution.key` and **`request-signing.key`**. Keep the passphrase separately. The database contains encrypted current secrets and retained comparison material plus unencrypted metadata; both database and access keys are sensitive. No backup or recovery command uploads files or bypasses encryption.

To restore, copy a cold backup into a new empty current-user-owned directory (mode `0700`), preserve file modes (`0600`), then launch `serve --data-dir /absolute/restored-directory --port 43120` and log in/unlock with the original passphrase. A schema-v3 signing key is required; if it is lost the center refuses operation rather than regenerating a key and allowing ambiguous retries. The execution key must match the database. Test restore on a separate directory with synthetic data before depending on a backup; cold backup restoration is not claimed verified unless listed in the acceptance evidence.

For migration rollback, stop every process and restore the private pre-migration database together with its matching original keys into a separate directory, using the matching older application version. This V1 automatically migrates older data again when opened, so merely starting it against a pre-v3 or pre-v4 backup performs an upgrade. Keep original backups unchanged. Restoring an older snapshot can lose recent request outcomes and cannot undo an upstream operation; reconcile unresolved operations before any new attempt. Forgotten passphrases cannot be reset to recover ciphertext. Local deletion/revoke is not provider-side token revocation.

## Validation and license

```sh
# The full test command is available; the current report records focused checks.
npm run acceptance

# Integrated product paths use fresh short private scratch directories automatically.
node scripts/v1-product-acceptance.mjs
```

For the integrated product acceptance after building, run `node scripts/v1-product-acceptance.mjs`. It initializes a fresh synthetic vault with the actual CLI through a PTY, launches the default CLI server, drives Chromium management actions and uses the actual stdio MCP bridge. Separate GitHub/Google loopback simulators cover configuration → authorization/callback → fixed operation → real expiry/concurrent refresh → revoke; the controlled browser path covers reviewed password save → separate human fill/submit approval → cookie reuse → lock denial. It writes sanitized JSON and a screenshot, then stops children and removes scratch data. Chromium and Python must be installed; fixed port 43122 must be free.

Synthetic endpoint injection is accepted only with `mode:"synthetic"` and a vault freshly initialized using `init --synthetic true`; a protected `.synthetic-product` marker prevents treating an existing ordinary vault as that fixture. A marked vault requires synthetic startup configuration on every serve; it cannot fall back to production/default mode. Synthetic execution also blocks production API-key destinations. Synthetic configuration requires separate `github` and `google` endpoint sets (`authorize`, `token`, `identity`, `revoke`), all literal `127.0.0.1` HTTP with explicit ports. The acceptance script creates this private configuration automatically. Production config rejects provider endpoint fields.

`node scripts/v1-app-smoke.mjs` remains the older CLI/CRUD smoke; `node dist/src/browser-demo-run.js` remains a library-host demo. Neither substitutes for product acceptance.

Tests use task-created synthetic vaults and local fixtures. The suite includes the real CLI PTY, management UI through Chromium, official SDK stdio MCP, core transactions/replay and local adapter tests; results belong to the exact recorded run. Missing browser/PTY prerequisites are failures or explicit skips, not evidence of passed coverage. [docs/acceptance.md](docs/acceptance.md) and `docs/evidence/v1-delivery*` contain current commands, results and blockers; older acceptance logs remain historical evidence.

The project source is licensed under [MIT](LICENSE). Dependencies retain their own licenses. This local source delivery is not a registry publication or remote release.
