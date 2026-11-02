[English](PROJECT-DESIGN_EN.md) | [中文](PROJECT-DESIGN.md)

# Unified Credential Center: full design review draft

Status: design draft, pending review; it does not mean implementation is complete or that clients are compatible.

This draft supersedes the earlier plan that made a local model a dependency of the main body. The design revision is complete; the user's latest authorization allows independent progress on version one per V1-IMPLEMENTATION-PLAN.md with no additional confirmation, and the historical pause instruction is revoked. Implementation is still forbidden to read real secrets, write remotely or deploy externally. Existing exploration code is retained but has not been verified item by item against this draft and is not evidence of completed implementation.

## Current security goal update: secrets do not enter the LLM

Per the controller's latest explicit goal, passwords and other real credential secret values are entered only by the user, directly, through a separate WebUI into the trusted center, and do not enter the LLM, ordinary MCP parameters, chat or model tool logs. The propose_enrollment/save_credential designs that carry a secret are withdrawn and are not restored by older messages; this section overrides any later statement in the historical design that lets a model handle secrets or that offers optional natural-language entry containing a secret.

Ordinary MCP accepts only metadata such as service, account alias, type, target record, version and requested permissions; it strictly rejects extra fields such as secret/password/token/confirmed and does not echo input in validation errors. The user checks the source, exact service domain and permissions in the management WebUI, then types the secret directly and confirms; the trusted server reuses the existing draft, approval and atomic-save mechanisms. MCP can query only redacted status within the requester's permissions, cannot read secrets, and cannot self-approve on the strength of a chat confirmation. If confirm_enrollment is kept, it may only consume a metadata handle already approved by the trusted UI and must not accept or replace a secret; whether that tool is actually needed is decided by the final product flow, and no extra steps are invented merely to retain an old tool.

The center may still decrypt inside the trusted executor and use the value for fixed APIs, OAuth or browser filling, but must not return the secret to the model. OAuth authorization codes/tokens travel over the trusted callback and the provider channel; browser filling runs in the trusted host. The optional model only organizes intent and metadata that contain no secret; the path in which a secret is spoken aloud and then sent to a model is no longer supported. If a user has already sent a secret in another chat, the center cannot withdraw that exposure; the interface should warn against entering secrets that way.

Work currently continues on conflict-free localization and the necessary baseline validation, and the halted secret-bearing MCP work must not be restarted on the strength of older authorization. Code and actual runtime state must still be reported separately; this paragraph is a design contract and does not mean the functionality is implemented.

## 1. Goals and scope

Build an open-source, self-hosted, personal-first unified credential center that lets Muse, Grok Bot, Dot, Hermes and DSH use authorized credentials through standard MCP plus thin adapters where necessary, reusing each platform's existing connections and logins as far as possible.

The main body must run without a local model, ASR or model service: the user can save a password or API key, start an OAuth authorization, manage permissions and execute operations from a compatible client, all directly through the management interface. Local natural-language/voice entry is an optional extension and does not block deployment or acceptance of the main body.

Unified means unified credential records, permissions, status and onboarding contract; it does not require every secret to be physically migrated into one store. OAuth/token/browser sessions held by a platform and not exportable stay on the original platform, represented as external connection references, and must not be disguised as keys the center can use directly.

Version one is single-user with shared trust and does not claim isolation within the same UID. Multi-user support comes later through owner attribution and interface evolution; version one builds no complex tenancy system. A license of MIT or Apache-2.0 is suggested, and no license release is claimed before the final choice.

Non-goals: universal automatic website login, exporting tokens from closed platforms, bypassing MFA/captchas, turning every operation into an arbitrary HTTP proxy, giving agents a generic plaintext password reading tool, and remote publication at this stage.

## 2. Experience and credential types

### 2.1 Default management flow: no model dependency

The local CLI initializes the administrator passphrase; the user signs in to the management interface, chooses the credential type, exact service origin, account and usage scope, enters the secret or starts OAuth, reviews the add/replace information and submits. Detail views return metadata only and never read a secret back. Listing, replacing, deleting, pausing a connection and querying the audit log are supported. Plaintext input fields are not auto-filled; version one offers no bulk export of existing secrets.

If bulk file import is needed later, it gets its own explicit import preview and field mapping, and never automatically scans existing .env files, browser directories, platform credential stores or production configuration.

### 2.2 Passwords and browser sessions

Passwords serve website login; Cookie, browser storage and persistent sessions are secrets as well. Storing a password, securely filling it into a particular browser, and reusing an already signed-in session are three separate capabilities, each reported with its own support status.

Prefer the platform's existing secure login/credential tooling. When the center must fill, a trusted browser adapter obtains the controlled page identity and performs the fill, and the model sees only account candidates, handles and status. Passing a password as an ordinary tool parameter is forbidden, as is arbitrary reading of password fields; the user is prompted on first fill or when the credential choice is ambiguous.

The trusted adapter must verify the exact origin (scheme, host, port) of the real top-level and target frame, use fixed per-site field rules, and reject cross-origin iframes, approvals that are stale after a page navigation, non-approved sites, and any selector/script chosen by the model. The page target is re-checked during the fill, and secret-related DOM readback, screenshots, traces, recordings and console forwarding are disabled. How much of this is implementable depends on the specific browser host; where it cannot be met the capability is marked unsupported rather than bypassing the native security interface.

Prefer letting the existing browser host manage sessions; only a separate browser profile managed by the center makes the center responsible for session encryption and lifecycle. Session expiry, MFA, captchas or risk controls require human intervention, and permanent usability after a first login is not promised.

### 2.3 API key/token

The user enters them directly and they are stored encrypted; the trusted executor injects authentication per predefined operation, and the agent passes a record handle plus constrained parameters, never a target URL, auth header or arbitrary script. An internal lease does not change the upstream permissions of the original API key; the center can only constrain requests that pass through it.

The fixed operation registry contains the target origin, method, path, parameter schema, authentication injection method, required scope and output allowlist. Production uses HTTPS; arbitrary proxying, cross-origin credential forwarding, unapproved addresses, intranet/metadata targets and following all redirects by default are rejected. DNS resolution and the actual connection must be constrained consistently to prevent rebinding. Parameter encoding must not change the fixed target path or the permission semantics. The test-only loopback mock exception is separate from production rules.

### 2.4 OAuth

Register a client per provider with an exact callback address; use one-time state, replay protection and server-side code exchange, applying PKCE and client secret according to what the provider actually supports. Access/refresh tokens are stored encrypted, with scope, expiry, rotation, revocation and re-authorization handled; token endpoints and related redirects are never specified arbitrarily by the model.

GitHub and Google are separate adapter tasks, and PKCE, refresh tokens or revocation behavior must not be assumed identical. Google's offline-access/refresh issuance conditions, GitHub's specific application type and its renewal mechanism all need to be checked against the current official documentation before implementation. Without a registered test application and authorization, no real integration success is reported.

Speaking a password is not an OAuth authorization; existing platform tokens are not migrated out unless a formally supported interface and explicit authorization exist. A successful website login is not treated as holding an API scope.

## 3. Architecture and data flow

```text
Management UI / optional local entry client
                 |
         management auth, confirmation, CSRF
                 |
      shared core service: records, policy, audit, lock state
          |                    |
     encrypted SQLite    trusted executor / adapters
                               |
                  fixed API / OAuth / browser host

five agents → MCP stdio or authenticated HTTPS MCP → execution permission check → shared core
platform-native connection → the platform's own authorization and execution chain; the center manages only verifiable references/status
```

Candidate implementation: a single TypeScript/Node project, Fastify, SQLite, the official MCP SDK, a simple server-side management interface, and the mature AEAD/scrypt implementations in Node crypto. Playwright or native host capabilities are enabled for browsers on demand. Candidate technology is not a user directive and does not mean the existing code matches the design.

A core record contains at least id, owner_id, service_id, credential_type, account_alias, storage_mode (managed/external_reference), version, status, created_at/updated_at. Secrets are stored separately as AES-256-GCM ciphertext with a random nonce, and the AAD binds the record identity, the owner and the format version. External references carry no fake ciphertext, and local state is not treated as live remote state; last_verified_at and states such as unknown/disconnected are returned.

Deduplicate on owner+service+type+the account identifier the user defines; the account alias is not a verified upstream identity. An OAuth subject is bound only after it is obtained through a legitimate callback. A conflicting add must not overwrite silently; replacement uses a transactional CAS on expected_version, and a repeated request_id is idempotent. Audit records capture record id, action, policy version, result and time, avoiding secrets, secret hashes, request bodies and full account names in logs.

## 4. MCP and trusted internal interfaces

All tool schemas strictly reject unknown fields, enforce length limits and return structured error codes instead of raw exceptions. Tool names are a design contract; protocol compatibility is verified against the chosen SDK during implementation.

| Interface | Purpose and boundary |
|---|---|
| list_connections | Returns redacted metadata, storage mode, status and available operations; returns no secret |
| get_connection_status | Returns the last verified status, capabilities and items requiring manual action; external state cannot be inferred out of thin air |
| list_operations | Returns the fixed operation definitions available to the current execution identity |
| execute_operation(connection_id, operation_id, args, request_id) | Executes an authorized operation; it accepts no arbitrary target or authentication data and does not pass the response through verbatim |
| request_browser_fill(connection_id, browser_session_id) | Only for a trusted browser host that has been integrated; returns unsupported when no host is available |
| propose_enrollment | Optional extension: submits an enrollment intent/draft pending confirmation; it is not approval and does not save |
| save_credential | Withdrawn: no save tool that receives secrets is exposed to the model or ordinary MCP; secrets are entered only through the separate WebUI |

An ordinary execution client discovers only execution tools by default and receives no enrollment, management or plaintext-read capability. Revocation, deletion, rotation and starting OAuth go through the management surface by default; if MCP management operations are exposed later, they need separately granted permissions and confirmation, and must not be granted to every agent by default.

The management surface and MCP may share a process, but authentication credentials and route permissions are kept separate. An MCP connection token is a token for reaching the center, not an upstream service token. The stdio bridge may read execution credentials from a protected file and must not put their values into model messages or command lines. In a single-user setup these logical limits prevent misuse; they are not isolation from a malicious process running under the same UID.

## 5. Onboarding matrix for the five agents

What follows is evidence from documents or tool schemas that have been read, plus designs still to be verified; none of it equals an actual compatibility pass.

| Agent | Existing connection/login reuse | New onboarding candidate | Uncertainty and test requirements |
|---|---|---|---|
| Muse | Official material describes authd/privsep custody and brokered credentials plus Sentinel decisions; native login preferred | The official help material supports API/CLI custom connectors; a thin adapter if needed | General MCP, an external authd interface and token export are unproven; needs the real product's custom-connector entry point and network/security policy validation |
| Grok Bot | App OAuth stays in the Cursor backend; a web login on the cloud machine can be reused persistently and is shared by Bots on the same account | The cloud machine officially supports command MCP or URL MCP | The machine running commands is the Grok cloud machine; the URL's protocol/authentication still needs testing and cannot reach the user machine's localhost; exporting the backend OAuth is not assumed |
| Dot | The official FAQ describes shared ChatGPT plugin authorization and reusing the session after a secure login | In-product plugin/custom connection paths are still to be checked | The Agents API MCP documentation proves only API product capability and cannot replace the Dot product entry point; stdio, remote custom MCP and token export are not assumed |
| Hermes | The current browser_vault schema for list/fill/save_login/enter_code/unlock has been checked; it has domain validation and protected input | Native MCP stdio/HTTP is a candidate; filling continues along the native path | A custom backend or external service interface for browser_vault is unproven and is not assumed to accept the center; the local version and real calls must be recorded again |
| DSH | Per the administrator's material, the private-repo bridge uses an HTTP Bearer; upstream provider credentials are a separate set | First verify how DSH actually consumes MCP; if the bridge drives DSH externally it cannot be treated as reverse adaptation | The body of the designated private-repo README was not obtained; another public bridge explicitly has no authentication and no redaction, and its full tool prints plaintext, so it cannot be adopted directly |

Each row's test records the version, entry point, extension evidence, connection direction, deployment machine, authentication, reproduction command, redaction evidence and blockers. An MCP SDK tester does not replace a real agent. Day-to-day connections are not read or modified automatically; reuse tests on existing connections that involve real accounts need separate authorization, and only synthetic environments are used for now.

## 6. Deployment and lifecycle

Default personal single machine: the core stays resident on the local loopback with the management UI on the same origin; local agents use the stdio bridge. The CLI initializes the administrator passphrase with no echo, and the web interface has no first-run registration that could be hijacked. scrypt derives the master key; the salt and parameters may be stored, but the master key never touches disk and lives only in memory; startup requires a manual unlock, with active locking and session expiry supported. Master-key unlock state is separate from any single browser session, so closing a page is not mistaken for a global revocation; locking explicitly blocks further operations and clears references on a best-effort basis.

Management surface: exact Host/Origin validation, CSRF (including on unlock), HttpOnly/SameSite cookies, rate limiting, no open CORS, no third-party resources, no-store. Non-local deployment requires HTTPS, secure cookies and a separate authentication review. The database directory is 0700 and files are 0600, and writes avoid symbolic links and wrong ownership. Backups copy only encrypted data and necessary metadata, and restore still requires the original passphrase; restore steps should be verified, but no complex backup system is built by default. Recovery from a forgotten passphrase cannot bypass encryption, and version one states plainly that recovery may be impossible.

Remote cloud agents: the user machine's localhost is not directly reachable. Candidates are a thin bridge placed in an approved environment, or an authenticated HTTPS Streamable HTTP tool endpoint. Each client is checked for Bearer/custom header or MCP OAuth support; Bearer authentication is not full MCP OAuth. If a client supports only OAuth, a separate task covers a standard discovery/authorization server or the reuse of a mature authentication component, and the capability is marked unsupported until that is done. The management surface is not exposed together with the tool endpoint.

A public domain, TLS, tunnels, service exposure and remote testing all require explicit deployment authorization; at present they are design only and are not implemented. Unattended unlock is a later option that requires a system key store/KMS and a re-assessment of host trust; auto-unlock with the master key in the same directory as the ciphertext is not claimed to be equivalently secure.

## 7. Withdrawn historical design: the model handling secrets

This section keeps the historical discussion for traceability only; none of it remains a development or acceptance requirement. The single current entry boundary is the "Current security goal update" at the top of this document. The secret-bearing model/MCP paths described below must not be implemented.

The main body does not depend on this extension. The intended interaction: the user speaks or types natural language containing a secret once → a local model organizes the service, account, secret and storage method → a redacted confirmation card → the user confirms → the real MCP saves; it does not degrade into a manual form that asks for the password again.

A dedicated client could intercept the model's save tool call as a short-lived in-memory draft, calling no real save and writing nothing to the credential store before confirmation. The confirmation card shows the exact origin, type, distinguishable account, add/replace and operation scope; the secret is masked with a fixed mask by default, showing no length, trailing characters or digest, and the confirmation page carries no hidden secret field. The process/browser where the user first typed the secret has already seen it, so zero exposure cannot be claimed.

The trusted UI confirms the draft id/version through the authenticated session and CSRF; a trusted orchestrator maintains short-lived, single-use approval state bound to the original draft and the target record, and after confirmation reuses the draft secret to call save_credential. A model's self-reported confirmed is void. Editing a field invalidates the old approval; cancel, timeout or lock clears draft references without persisting them; complete memory erasure is not promised. On conflict the target is re-selected and confirmed without re-entering the secret. ASR/the model must not on their own trim, normalize or guess a secret, and any recognition ambiguity must be clarified.

The secret in fact enters model input and MCP parameters. Call it fully local only when ASR, model, transport, history, logs and telemetry have all been actually verified as local; a loopback backend may still forward to the cloud, and a browser voice interface cannot be assumed local either. Each hop displays local/external/unknown. Cloud fallback is not allowed at present; an unknown endpoint blocks only this extension, not the main body.

The dedicated client stores no recordings, transcripts or conversation history and avoids localStorage/IndexedDB; the model service, ASR, MCP and proxy are forbidden to trace bodies, parameters or secret exceptions. Log redaction cannot rest on the center alone; if an external agent forces parameter persistence, it must be stated clearly that this path does not meet the no-secret-logs goal. The real limits of memory, swap and crash dumps must be described honestly, and fully local is not equated with leaving no trace.

No local model/ASR entry point is approved at present. An earlier read-only PATH probe found no common executable, and an unknown port is not evidence of a service; a routing warning returned by the designated coding tool cannot prove local inference. A simulated ASR or a cloud model must not be used to claim this extension passes end to end.

## 8. Trust boundaries and failure handling

Trusted: the individual administrator, the center process, approved executors/browser adapters and the optional local entry process; host root and a controllable process under the same UID may read secrets. The logical agent identity is mapped from connection authentication, and a self-reported agent_id in a request is not trusted; but version one does not claim resistance to active theft from a shared UID.

Untrusted: model suggestions, web page content, email, tool responses, arbitrary selector/URL and unreviewed community bridges. Web page text cannot authorize import or use, and the model cannot widen its own scope. External platform credential boundaries remain, and secure login and approval are not bypassed.

Execution authorization binds the principal, connection, environment, fixed operation and exact origin. Default deny, and deny when there is no identity. New requests after lock/revocation are rejected; an in-flight request may already have reached upstream and cannot be guaranteed to be recalled, so its in-flight state is recorded and cancellation is attempted. Deleting a local record is not upstream token revocation, and local deletion/remote revocation results are shown separately. Upstream failure, expired authorization and captchas go to an explicit needs_user_action state; errors contain no secrets.

## 8A. Execution contract completed through independent review

This section turns the shorthand above into an implementable contract; where ambiguity arises, this section governs. The following is still a design requirement and does not mean code or live testing is complete. The core does not depend on a model, and optional model entry must be confirmed by the user before anything is saved.

### A1. Complete draft, approval and atomic save

A draft is an immutable server-side snapshot containing the full raw secret bytes, type, service/origin, account, owner, the originating stable authenticated principal, the trusted client principals allowed to submit, the confirming administrator session, the operation (add/replace), the target record with expected_record_version, the permissions to be granted and the draft version. It must not be bound only to card-visible metadata or a draft_id. The card is generated from this snapshot; the secret is not returned to the confirmation page and does not appear in logs. Any change to the secret or to any metadata creates a new version and invalidates the old approval. A confirmation request must verify the authenticated session, CSRF, draft ownership and version; the model cannot approve on its own.

A draft is valid for 10 minutes by default; an approval is valid for 2 minutes and may not outlast the draft. Approval is server-side state bound to the complete snapshot above and to the current security epoch, and does not use a replaceable client secret parameter as its sole source of truth. When MCP save receives the full payload, it is compared field by field and byte by byte against the approval snapshot inside the trusted process; any mismatch is rejected. The approval credential is provided only to the trusted submitting process and never to the model. Approval does not expand execution permissions.

The actual save transaction performs all of the following together: confirm the current lock state/security epoch, that the approval is valid and unconsumed, the target CAS/uniqueness check, the ciphertext write, the record/status version write, the approval-consumed marker, the idempotent completion record and a secret-free audit event. It uses a database transaction and a serialized commit boundary; locking also changes the epoch through that same boundary, so that a check followed by a lock cannot still write. Any transaction failure rolls everything back, and an approval consumed without a save is not allowed. Once the transaction commits, a lost response does not cause a rollback or a second save.

A repeated submission first verifies current authentication, owner and permissions, then looks up the request_id in the same scope: if it is already complete and the payload matches, only the original redacted result is returned and the approval is not consumed again; at that point the approval may already be consumed or the original draft may have expired. While locked, secret payload comparison is refused and the caller retries after unlocking again; re-authentication may retry with the same stable principal but does not restore the old approval. A different payload returns idempotency_conflict. For concurrent identical requests only one transaction can commit.

Uncommitted drafts and approvals live only in memory; cancel, timeout, lock or restart invalidates them, and after a restart the proposal and confirmation must be repeated. Committed idempotent results persist in the database, and a restart does not depend on the original draft. Secret drafts are not persisted before confirmation; the optional extension may not write transcripts to disk on the grounds of draft recovery. Complete erasure of process memory cannot be promised.

### A2. CAS, request scope, retention and status versions

The stable authenticated principal_id is mapped by server-side authentication and does not change when credentials rotate; a client-reported agent_id must not be used. The unique scope of a request_id is (owner_id, principal_id, operation_name, request_id). The target record, environment, parameters, permissions, expected version and secret all belong to the complete payload and are not part of a scope that could be bypassed by swapping the target. Requests with the same name from different principals are independent of each other; the same principal sending a request under a new ID must still pass the record uniqueness and version checks.

Request IDs are opaque server-issued tickets containing an issue time, a random value and a MAC, using a separate, persistent instance request-signing key protected by file permissions (not derived from a secret). The registration window for new requests is 24 hours; completion results and comparison material are retained for 7 days, including tombstones for requests that were registered but never explicitly completed. An expired ID must not be registered again: outside the window with no retained result it returns request_expired and cannot be treated as a new request. The signature-verification key is retained at least until every corresponding ticket has expired; if the key is lost or cannot be verified the request is rejected, with no lenient re-execution. Records of external operations that never terminated are not cleaned up automatically; they are archived under the record's retention policy after manual review. list/status queries may offer ticket issuance, or a separate prepare_request interface that performs no operation may exist; the execution side cannot generate unknown IDs by itself.

Payload consistency for the same ID uses trusted server-side canonicalization: raw secret bytes are preserved, field encoding is fixed, missing and empty values are distinguished, and the secret is not normalized on the server's own initiative. A write operation carrying a secret persists the encrypted canonical payload in the same save transaction for comparison during retention (reusing the store's AEAD, with an independent nonce/AAD for each item); no ordinary hash that would allow offline guessing of a short password is stored, and neither the payload nor a digest is logged to the audit. That comparison copy is also a secret and is subject to the same lock, deletion and retention constraints; the user is told that deleting the current credential is not the same as immediately deleting the retained idempotency comparison copy. If the administrator chooses to purge the copy immediately, a secret-free request tombstone should be retained and later calls return only result_unavailable, never a re-execution.

record_version is the monotonic version of record content and authorization configuration: 1 on add, incremented after a successful replace/account change/scope change; every corresponding change must carry expected_record_version. status_version is a separate monotonic version for availability state and verification information: pause, revocation, authorization expiry, refresh results and changes to last_verified_at each increment it transactionally; status administration changes use expected_status_version, so background status changes cannot masquerade as user content replacement. An operation request pins the expected record_version and also checks the latest status/policy before execution, so an old status still being available does not grant excess rights. Automatic token refresh uses a separate CAS on an internal encrypted material version, avoiding overwriting a concurrent refresh and never posing as a new scope the user approved. Reads return these versions; the legacy field version is renamed to record_version uniformly before the interface lands, and the two meanings are not allowed to coexist.

### A3. Upstream side effects, timeouts and unknown outcomes

Local idempotency can only guarantee that the center does not register/submit a local save twice; it cannot guarantee exactly-once external operations. Every operation is explicitly marked read_only, upstream_idempotent or non_idempotent, and business semantics are not inferred from GET/POST names.

Execution records persist the states accepted, dispatching, succeeded, failed_before_dispatch, failed_confirmed, outcome_unknown; state changes increment operation_status_version. dispatching is written before sending; a crash after that write is treated as an unknown outcome even if nothing may have been sent. failed_before_dispatch may be used only when it is certain that nothing was sent; a timeout after sending, a dropped connection, a service crash or an ambiguous error is outcome_unknown rather than a safe failure.

Where upstream formally supports idempotency keys, pin the same upstream key, identity, target and payload, follow its retention period and retry rules, and verify through its query interface when necessary; never blind-retry beyond the upstream key's validity. Without that support, an unknown outcome after sending is not retried automatically, and changing request_id does not clear a duplicate side effect on its own; conflicts on the same connection/operation/business target must be reviewed first. The interface shows "may already have executed, verification needed", and the administrator may, after seeing the evidence, explicitly approve a new attempt and accept the duplication risk. Cancel/lock can only do their best to stop unsent requests and cannot withdraw a side effect that has already occurred.

An MCP retry with the same request_id returns the current execution status or the original result and does not dispatch again; outcome_unknown is retained until it is reconciled. Results are filtered for secrets first; the raw upstream body is not saved automatically for troubleshooting. The default allow conditions for side-effecting operations are stricter than for pure reads.

### A4. Management authentication, unlock and three states

Administrator authentication and ciphertext unlock are two separate judgments. Version one allows the same administrator passphrase as the user-facing entry point, but the implementation uses independently salted/domain-separated KDF parameters to derive authentication verification material and the encryption key separately; the authentication verifier must not serve directly as the master key. Initialization happens only in the local CLI. Management authentication obtains only a management session, and unlock must submit the passphrase again to derive the master key; there is no model dependency.

The three states are: S0 unauthenticated and store locked; S1 administrator authenticated but store locked; S2 administrator authenticated and store unlocked. Login moves from S0 to S1, unlock moves from S1 to S2; the login page may take the passphrase once and explicitly choose to unlock at the same time, while internally still performing both checks. S1 allows only minimal management functions that contain no secrets, such as lock state, unlock and logout, and cannot list full accounts, submit enrollments or execute. Version one allows at most one active administrator session, and an authenticated session expires after 15 minutes idle; MCP activity does not extend the management session.

An active lock moves from S2 to S1: the store locks immediately, key/draft/approval references are cleared, security_epoch increments, old administrator and browser approval cookies become invalid; only the currently authenticated management client is issued a new, restricted S1 cookie in rotation. logout, management session expiry or a process restart return to S0: globally locked, with no new cookie issued. Closing a page does not itself trigger logout immediately; locking only happens at timeout. A fourth state of "unauthenticated but store unlocked" must not be kept; long-term unattended background use is left to a separate later design.

A cookie is a random server-side session identifier, HttpOnly, SameSite=Strict, Path=/; HTTPS adds Secure, and the local HTTP exception does not pretend to be transport encryption. Session records bind security_epoch, so an old cookie is rejected even if replayed after a lock, and the CSRF token is updated in step after rotation. An anonymous pre-authentication session can only protect the login/unlock flow and grants no management rights. MCP execution credentials do not unlock the store; locking does not delete their configuration, but calls return vault_locked, and after unlocking the current policy authorization is still required. Approvals, browser handles and in-flight actions follow the same epoch and the external non-recallable boundary in A3.

### A5. External connection references and formal delegation

external_reference by default can only list metadata and the last verified status and prompt the user to act on the original platform; can_execute=false. The center does not gain a platform token/execution identity merely because a reference exists, the user gave verbal authorization or the upstream is already signed in. When get_connection_status has no official query path it returns unknown/user-declared status and does not pretend to have verified it.

Only when a platform provides a formally supported call interface/proxy host and delegation has actually been authorized is a separate delegation record created: owner, center calling principal, upstream executing principal and account, source of the formally authorized credential, audience, resources/scope/operation, reachable endpoint, expiry and revocation information, and verification evidence. The request path is: agent's authenticated principal → center authorization → trusted delegation adapter → platform's formal execution API/host → upstream service; the platform executes under its own account identity and original approval rules. The center does not read/export its secrets, nor does it bypass platform restrictions through a generic shell or web scraping.

Center execution permissions are the intersection of local policy and the upstream delegation scope, and delegation status is checked on every call; the actual upstream identity is stated in the operation card and result metadata, and a shared platform account must not be called an agent's independent identity. Expiry, revocation, unclear authentication or an unreachable interface all stop execution. Without the evidence above the call returns external_execution_unsupported and can only guide the user to the original platform; reusing an existing connection in the five-agent matrix is accepted separately from "the center can execute on its behalf".

### A6. Browser handles and fill authorization

browser_session_id is an opaque reference registered on the server, not an authorization by possession. The registration binds the trusted host adapter_id/instance, owner, the authenticated requesting principal, browser profile/context ID, tab ID, frame ID, document/navigation ID, the exact origins of the top-level and the frame, and security_epoch. Only the host's trusted channel may register/update it; an ID supplied by the model cannot forge the host page identity or be reused across principals/hosts/contexts.

A handle is valid for 5 minutes by default and does not renew automatically; a fill approval separately binds connection_id, record_version, the site field-rule version and the context above, and is valid for 60 seconds by default with single use. The host re-checks the page before every dispatch and before actually writing a field; top-level/target-frame navigation, reload, document replacement, context/tab close, origin change, host reconnect, record replacement/revocation, lock or approval timeout invalidate it immediately, including a new document on the same origin. Navigation and the write must be validated by the same controlled execution unit in the host; if that cannot be done, the request is refused. A host that has not registered such a handle or does not support this guarantee returns unsupported.

A fill by default does not click login, press Enter or submit a form; automatic submission cannot be derived from a fill approval. When submission is needed, a separately approved login_submit operation binds the same record, host and document, verifies a fixed same-origin form action/allowed submission target, and is short-lived and single-use; a page change invalidates it and requires approval again. A fill can itself trigger page events and let that site's scripts see the password, so that site and the fixed rules remain a trust boundary, and the password cannot be claimed to be invisible to the site. The session produced after submission is managed by the host, and later agent operations remain bound by permissions; any unknown submission result is handled per A3, with no blind refill or resubmission.

### A7. New design acceptance items

- Inject a crash/rollback into the save transaction and prove that approval consumption, the database write and the idempotent result are consistent; simulate a committed save with a lost response and a restart, where the same ID returns only the original result; a replay with different content/a different target conflicts.
- Verify principal/operation scope, the independent CAS for record/status/material versions, refusal to re-execute after ticket expiry and retention cleanup, and the tombstone behavior when the comparison copy is purged immediately.
- Simulate upstream execution followed by a timeout/center crash, so that outcome_unknown is returned and nothing is re-sent automatically; where formal upstream idempotency exists, verify key reuse and its expiry boundary, without claiming exactly-once external effects.
- Verify every S0/S1/S2 transition, the separation of login and unlock, global lock on idle expiry, rejection of old cookie/CSRF/approval, and that MCP does not execute while locked.
- Refuse execution for an external reference without delegation; with a synthetic formal delegation verify both-end identities, scope intersection, revocation/expiry and refusal when the platform is unreachable, without reading cloud tokens.
- Browser tests: cross-principal/host/context, same-origin navigation/reload, frame change, timeout, record replacement, lock and handle replay are all refused; a fill does not submit, submission is separately authorized, and an unknown result is not retried automatically.

## 9. Implementation phases and acceptance gates

The order below is the currently approved implementation sequence; the specific tasks and the gap against the code actually read are in V1-IMPLEMENTATION-PLAN.md. Complete the model-free core first, then verify the type adapters, the five agents and the optional extension item by item; anything not yet passed must not be called complete.

### Phase A: design review and evidence completion

Confirm the core/extension boundary and check the gap between the existing code and this draft; obtain isolated test entry points for the five agents, the secret-free DSH README/checkout, the first API and browser test targets, and the conditions for an OAuth test application. Produce the interfaces, the operation registry and the compatibility matrix. Unknown items stay blockers; no facts are fabricated to fill them.

### Phase B: model-free core

Deliver initialization, manual unlock, management CRUD, encrypted storage, execution policy, audit and standard MCP stdio. Run synthetic values for real through UI→store→MCP→fixed local mock; verify that the new value is used after replacement, that deletion takes effect, restart lock/unlock, nonce non-reuse, rejection of tampered ciphertext, CAS/idempotency, and rejection of CSRF/Host/Origin/anonymous/unknown-operation/redirect/SSRF. The mock exception does not spread to production. Check that the DB, logs and tool output contain no synthetic plaintext. Start no model or ASR at all, proving the main body is independent.

### Phase C: type adapters

Browser: a controlled site plus a real trusted browser fill, proving that it fills only at the correct origin, does not fill cross-origin or after a navigation, returns no password in the result, that a manual first login is reused by later tasks, and that session expiry requires a human. A standalone Playwright demo does not equal support for the five agents' own browsers.

OAuth: for GitHub/Google separately, complete the check of client registration conditions, local simulated protocol tests and real authorization on an approved test account; record code/state replay, scope, refresh availability, rotation/invalidation/re-authorization item by item. Without conditions for a real integration, only simulated passes are reported.

### Phase D: five agents and deployment acceptance

Each of the five agents is really started and calls the completed capabilities: connection/discovery, a successful fixed operation, refusal while locked/revoked, refusal of an unknown operation, and no secrets in logs/output; reuse of an existing connection, password filling and new MCP onboarding are reported separately, and no single path is required to pretend to cover every function. After cloud-side network/authentication is authorized, verify separately TLS, refusal of unauthenticated calls, tool permissions and the unreachability of the management surface. Only when all five pass is five-agent compatibility claimed; unsupported product capabilities are listed explicitly as gaps.

### Phase E: optional local entry

Synthetic text passes through the real local model and synthetic audio through the real local ASR+model; before confirmation there are zero save calls and no DB record, after confirmation the real MCP saves exactly once, and cancel/edit/expiry/fake approval/replacement races behave correctly; after a restart and unlock, a fixed mock proves the exact value matches, and no plaintext-read tool is exposed. Check the client/ASR/model/MCP/proxy logs and network for canary leaks or cloud fallback. Verification items that lack endpoints/permissions are marked blocked and must not delay the independent delivery of core phase B.

## 10. Unverified items and current delivery boundary

- None of the five agents has a complete end-to-end compatibility acceptance conclusion under this draft; documented capability does not equal a test pass.
- Muse's external authd/general MCP, Dot's product custom MCP and a Hermes browser_vault backend extension are unproven.
- The body of the DSH designated private repository was not obtained; the two-layer token relationship needs independent verification against code/a secret-free document.
- Remote MCP client authentication methods, network reachability, deployment domain and TLS are all untested, and none is deployed in this round.
- GitHub/Google's specific client types, PKCE/refresh/scope and product review conditions await official confirmation and approved testing.
- The first browser host and supported site are not chosen, and the connection between the center's password store and the host's secure fill is unproven.
- The optional extension's real local model/ASR and its no-forwarding, no-secret-logs conditions are unverified.
- The developer reports exploratory implementation in the existing code, which has not been reviewed/accepted against this draft; no claim is made that a deliverable system is already running.

## 11. Evidence sources

Public material is used only as design input; text actually accessed is recorded separately from information supplied by the user:

1. Muse architecture (read): https://research.meta.ai/blog/security-and-safety-for-ai-agents-our-approach-with-muse
2. Muse custom connection help (read): https://www.meta.com/help/artificial-intelligence/1687253048996149/
3. Grok Bot security (read): https://docs.x.ai/grok-bot/security
4. Grok Bot computer and apps (read): https://docs.x.ai/grok-bot/computer-and-apps
5. Dot privacy/security FAQ (read): https://help.openai.com/en/articles/20001529-dots-privacy-security-and-safety-faqs
6. Agents API MCP (read, API capability only): https://developers.openai.com/api/docs/guides/agents-api/tools/mcp
7. DSH designated private-repo README (body not obtained): https://github.com/example-org/private-repo/blob/<commit>/README.md
8. DSH community bridge README at a pinned commit (read, risk evidence): https://github.com/sanshanya/dsh-dot-mcp/blob/a6d4ddac3ca7ec1b0d2baf334f1df5f7d1a81a56/README.md
9. Hermes official documentation: https://hermes-agent.nousresearch.com/docs/; this round relies on the loaded native-mcp skill reference and the actual browser_vault tool schema, without enumerating a real vault.

Planning execution note: the designated <coding-tool> was used to generate design review suggestions; its warning states that the actual model is <model-route>, so this cannot be used to claim the Sonnet route took effect, nor does that call prove the optional extension is fully local.
