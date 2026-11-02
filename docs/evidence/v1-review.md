# Independent V1 implementation review

Date: 2026-11-01. Author: Claude Code internal review subagent `a47afa99311b7819d`, within implementation session `17cb46b0-9032-4910-8715-7a077af8a177` (Hermes process `proc_2780e87b5fbc`). This is an implementation-task internal review, not a signoff by the designated Hermes `@reviewer` session; that separate review is pending. Primary reviewed source snapshot recorded at 05:35:36 UTC; the later MCP validation followup and internal review tests are recorded below. Node v22.23.3, Linux.

Provenance: Internal implementation review records were checked locally. Session paths and identifiers are omitted from this public report; this internal review does not substitute for the designated reviewer’s independent assessment.

**Verdict after fixes: no remaining verified correctness/security finding that blocks the declared local V1 scope.** The reviewer independently read implementation code and executed synthetic local tests; this is not a documentation-only signoff. The management save-recovery defect found during this review is fixed and independently retested. The browser HTTP-error outcome defect returned by the code-review skill is also fixed and independently retested. This verdict covers the no-model local core, its exposed local management/execution boundaries, and the specified trusted adapter/library demonstrations. It does not certify real provider authorization, named-agent compatibility, arbitrary websites, or a complete remotely deployed product.

## Scope and method

Read `V1-IMPLEMENTATION-PLAN.md` and `PROJECT-DESIGN.md` section 8A before implementation inspection. Directly read the current `src/vault.ts`, `src/contracts.ts`, `migrations/003-v1-contracts.sql`, `src/server.ts`, `src/registry.ts`, `src/browser.ts`, `src/oauth.ts`, `src/oauth-vault.ts`, `src/delegation.ts`, and `src/local-draft.ts`. Also inspected `src/crypto.ts`, `src/network.ts`, `src/bridge.ts`, `src/enrollment-mcp.ts`, the OAuth simulator, relevant UI recovery handlers, and core/management/browser/OAuth/delegation/local-draft/security/enrollment test coverage. Searched CLI/bridge/server entrypoints to determine which adapters are actually wired.

The code-review skill ran an additional independent inspection and returned one browser outcome-classification finding. The primary reviewer then inspected the actual fix and ran its regression, rather than adopting that result as untested assurance. Coordinator reports about earlier fixes were checked against current source and the relevant tests; historical pre-fix implementations were not reconstructed.

The reviewer edited no implementation or test source. This evidence document is the only project file written by the reviewer. Builds regenerated normal `dist` output; tests created and removed isolated synthetic temporary vaults. Tests were coordinated with the implementer and ran serially. The reviewer avoided the acceptance/execution suites that bind the fixed mock port 43121. Browser/OAuth/delegation fixtures used ephemeral loopback ports. No real secret, production configuration, external account, agent installation, external API, public port, tunnel, deployment, or repository commit was used.

## Findings and final disposition

### P2 — management save result could not be recovered after restart or reauthentication — fixed

Pre-fix location: `src/server.ts:188-194` at the time of the probe, the confirmation route's in-memory `pending` and exact-session check. The underlying `Vault.saveApproved` result already survived restart, but the exposed management route could not reach it after its old pending confirmation disappeared.

Reproduced independently with a temporary synthetic vault and `createServer(..., 0)`: log in, unlock, propose, confirm a save, close/restart the server, log in/unlock as the same stable administrator, and repeat the original confirmation ticket. Observed `initial_status=200`, `restart_replay_status=403`, `restart_replay_error=confirmation_denied`, with exactly one record remaining. Thus a committed save with a lost response could not recover its original result through the management flow after restart. No duplicate save occurred; the defect was result recovery required by A1.

Current fix: `Vault.getSaveResult` at `src/vault.ts:321` and `POST /management/save-result` at `src/server.ts:175`. The endpoint checks a live management session, CSRF and S2, then validates the signed owner/principal/`save_connection` ticket and returns only the retained completed metadata. It performs no save, approval restoration, secret comparison, or operation dispatch. The UI remembers only the request ticket before sending confirmation, and offers recovery after a reload/relogin. The old draft remains invalid.

Independent verification: rebuilt current source and ran `server-recovery.test`, `core-contract.test`, and `server-auth.test`: 14 passed, 0 failed, 0 skipped. The recovery test uses actual loopback HTTP and a full server restart. It recovers the original ID/version without a draft or secret, rejects S0/S1, bad CSRF, unsigned/wrong-principal tickets and extra secret fields, returns 404 for an uncommitted ticket and 410 after comparison purge, and leaves one record. Core checks additionally reject expired retained results and operation-mismatched tickets.

### P2 — browser HTTP errors incorrectly proved failure after a potentially committed submit — fixed

The code-review skill identified `login_submit` treating every HTTP status >=400 as `failed_confirmed`. Scenario: a login commits a session, then response rendering returns HTTP 500; classifying that response as confirmed failure releases the durable conflict marker and permits an unreviewed second side effect under a new ticket.

Current fix at `src/browser.ts:448-451`: all non-2xx submit responses remain `outcome_unknown`. The administrator must reconcile uncertainty before a new attempt. Independent review inspected this branch and ran the actual Chromium `commit_then_500` regression at `tests/browser.test.ts:289`; it passed, including the same-ticket/new-ticket dispatch protection. The simulated site commits the login and issues a valid cookie before returning 500.

### P2 — SDK tool validation reflected unexpected argument keys — fixed

The coordinator/component owner discovered that the high-level SDK's automatic schema validation could include an unrecognized argument key in its error before the application callback's catch handler ran. A malformed, protocol-valid tool call using a secret as an unexpected field name could therefore reflect that value in model-visible diagnostics. This issue was not originally discovered by the primary reviewer.

Current fixes: execution MCP uses the official lower-level `Server`, retains the six explicit discovery schemas, and performs `safeParse` inside its controlled `CallToolRequestSchema` handler (`src/bridge.ts:72`). Enrollment retains discovery registration but overrides the tools/call handler and parses inside its controlled error boundary (`src/enrollment-mcp.ts:31`). Invalid tool names, task calls and malformed argument objects return only `invalid_tool_request` or `enrollment_denied`.

The reviewer read both final handlers and independently tested the compiled execution bridge with the official stdio client, a generated temporary execution key, and no upstream server. Six tools were discoverable. Three protocol-valid malformed calls exercised an unknown top-level key, a nested `args` key, and an unknown tool name. All returned generic denials with neither key nor value canary reflected; stderr was empty. The separate enrollment suite passed 4/4, including its own malformed/nested-key/unknown-tool canary regression and zero saves. These checks concern valid JSON-RPC tool calls; no broader guarantee about diagnostics for arbitrary invalid JSON-RPC envelopes is inferred.

## Six-contract assessment

| Contract | Actual code and evidence | Assessment within reviewed local scope |
| --- | --- | --- |
| A1 — immutable approval and atomic save | Drafts are cloned server-side, contain the complete exact secret and metadata, and bind owner/principal/client/session/epoch. Save compares the full canonical payload. The SQLite transaction includes record/CAS writes, encrypted comparison/result, consumed-draft row, and audit. In-memory drafts are removed only after commit. Fault tests roll back at all three injected boundaries; full-payload changes, double consumption, lost response and restart replay are covered. The management recovery endpoint now bridges durable results across fresh sessions. | Satisfied by inspected paths and synthetic tests. Trusted internal authority callbacks remain part of the embedding boundary; the Vault object is not an independently authenticated remote service. |
| A2 — CAS, scoped signed tickets, retention | Tickets bind server-mapped owner/principal/operation and use a separate protected persisted signing key. New registration expires after 24 hours; completed comparison/results expire after 7 days. Canonical comparison material is AEAD encrypted with request-specific AAD; purge/cleanup retain tombstones. Unknown external outcomes are retained. Content, status and token-material versions are distinct. Replacement preserves newer pause/revoke state and refuses unresolved material leases. Missing signing keys fail rather than regenerate for a V3 store. | Satisfied for tested local transitions. Retention is an application/database policy, not a claim that backups or forensic disk copies are erased. |
| A3 — durable external uncertainty, no redispatch | Accepted/dispatching transitions persist before dispatch; restart converts dispatching to unknown and accepted to failed-before-dispatch. Same request replays a journal result; unresolved non-read-only same-target requests block new tickets. Explicit admin reconciliation uses operation-status CAS and requires duplicate-risk acknowledgement for a new attempt. Browser post-commit disconnect and 500 are unknown. OAuth rotating-refresh uncertainty leaves a blocking lease. | Satisfied for registered/demonstrated operations. No production operation claiming upstream idempotency is registered; no provider exactly-once delivery guarantee was inferred. Delegation library callers must supply the documented durable core wrapper before enabling a side-effecting adapter. |
| A4 — authentication/unlock states and epoch | Authentication KDF uses a separate salt and domain from encryption. Login produces S1, unlock requires the passphrase again and produces S2. Management authority is server-mapped; CSRF/origin/host checks and strict cookies apply. One admin session, idle expiry, global lock, epoch/cookie/CSRF rotation, old-cookie refusal and MCP inability to unlock are tested. Persisted epoch invalidates other open Vault keys and asynchronous stale unlocks. | Satisfied for the exact loopback HTTP server. TLS/Secure-cookie remote hosting is outside this implementation's exposed transport. |
| A5 — external references and formal delegation | External-reference validation requires empty secret/no operations, metadata reports external storage and `can_execute=false`, and token/operation paths refuse execution. Formal delegation is a separate trusted component: verified grant evidence, center/upstream/requester identities, policy/upstream intersection, audience/resource/scope/endpoint, expiry/revocation, fresh host verification and authenticated synthetic HTTP replies. | Default refusal and local formal-host demonstration verified. No real platform delegation API or production delegated MCP executor is claimed. |
| A6 — browser handle/document and separate submit | Fresh dedicated Chromium contexts; host-created opaque handles bind principal/owner/context/tab/frame/loader/document/top origin/epoch/rules. Host events invalidate navigation changes, and retained actual DOM/root references are checked in an isolated world in the same synchronous renderer task as native field writes/submit. Five-minute handles, 60-second single-use approvals, current record/status/policy checks and independent submit approval are exercised. Fill does not submit. | Verified with actual Chromium against the synthetic fixed-rule site, including same-origin reload/document replacement/frame changes/concurrent fills/restart unknown outcomes. This does not establish arbitrary-browser or arbitrary-website support. |

OAuth review additionally checked the one-use in-memory state and PKCE verifier, exact callback and owner/principal/session/epoch bindings, provider identity verification, local approved-scope ceiling, documented Google identity-scope aliases, refresh/revoke lease CAS, and immutable HTTPS production endpoint factories. Production factory options reject endpoint/transport overrides; only the explicit synthetic factory accepts literal loopback HTTP. Constructor/factory tests made no production request. Actual synthetic authorization-code/refresh/revoke tests used both providers and the real encrypted Vault bridge.

Optional drafting review checked strict model-output parsing, exact secret bytes, memory-only unconfirmed state, trusted session/CSRF confirmation, core save reuse, cancellation/expiry/lock/late-result rejection, and the trusted official-SDK enrollment MCP channel. A late cancelled ASR result is checked before invoking inference. Synthetic inference/ASR is explicitly labeled and does not prove a real backend is fully local.

## Tests personally executed

These are separate reviewer invocations, not a combined full-suite count. Test output was observed directly through the command tool; no separate reviewer TAP artifact was written. The coordinator's final full-suite logs are separate evidence and should be used for the release snapshot's aggregate count.

1. `npm run build && node --test --test-concurrency=1 dist/tests/core-contract.test.js dist/tests/server-auth.test.js dist/tests/browser.test.js dist/tests/oauth.test.js dist/tests/oauth-vault.test.js dist/tests/delegation.test.js dist/tests/local-draft.test.js`
   - Build exit 0; 109 tests passed, 0 failed, 0 skipped; 21.373 seconds. Includes real sandboxed system Chromium and ephemeral loopback provider/host fixtures.
2. `node --test --test-concurrency=1 dist/tests/security.test.js dist/tests/enrollment-mcp.test.js`
   - Exit 0; 9 tests passed, 0 failed, 0 skipped; 3.968 seconds. DNS safety tests use injected addresses without external requests; enrollment uses the official SDK in-memory transport and actual Vault.
3. Independent inline synthetic management restart probe described above.
   - Confirmed the original recovery defect before the fix. Temporary test data removed.
4. After the recovery and external-reference changes: `npm run build && node --test --test-concurrency=1 dist/tests/server-recovery.test.js dist/tests/core-contract.test.js dist/tests/server-auth.test.js`
   - Build exit 0; 14 tests passed, 0 failed, 0 skipped; 4.898 seconds. This rerun verifies the final relevant changed paths rather than relying on the earlier passing build.
5. Final MCP validation followup: independent inline official-SDK stdio probe against the owner's newly compiled bridge, then `node --test --test-concurrency=1 dist/tests/enrollment-mcp.test.js`.
   - Probe: 6 tools discovered; 3/3 malformed calls denied with `invalid_tool_request`, no canary reflection, empty stderr, no upstream server started. Enrollment: 4 passed, 0 failed, 0 skipped; 0.913 seconds. The owner supplied the compiled build for this followup; the reviewer did not claim a separate build invocation here.

## Snapshot and limitations

SHA-256 identifiers of the final primary source files inspected, captured at 05:35:36 UTC:

| File | SHA-256 |
| --- | --- |
| `src/vault.ts` | `74e563aa61bffc656dedfd551d150d81956426ab8fae9f0951b5278cb9d9313c` |
| `src/contracts.ts` | `8a38942f91d161fbb59a1c0476ff0d2e63bb1c44a31edca623cd56a18043935c` |
| `migrations/003-v1-contracts.sql` | `63bd0aabf74a634843c2473d83ec1ab3e087a067e8c3eccea913608775bc80fa` |
| `src/server.ts` | `6076513d8ba158966057dc8acdc9aef090cafcbfef77cfbfe1ca2017aa1a647c` |
| `src/registry.ts` | `6d87553d769507e325e7754fcccfe1749381c1b314a33fa72d2f83fb634216ca` |
| `src/browser.ts` | `e6719287c5da08fdc9a6a6731e5a617505b0209653e86a9ab4230f26448c24b5` |
| `src/oauth.ts` | `69c4abe2f3c3eabec53fabe3cff9014f905c15a74c73b7b2a4e54c099cd45508` |
| `src/oauth-vault.ts` | `0ed037b62f7551f7e5f454016bde1c8c1296d39389c67f8050877d1bce773950` |
| `src/delegation.ts` | `f88542ba8ffcb8f45ef92530e6a5c2d8020ee9c0643bf000a328504c79c8ca68` |
| `src/local-draft.ts` | `8b0dab5cc08862fd611a33b69411eeb1321e18f933f5f99069bfd535ce86796b` |
| `src/bridge.ts` — final MCP followup | `a14be8e6bec34b67070b430127837a2b873d6d1a188e4edc4d16b7cb8cd0efa9` |
| `src/enrollment-mcp.ts` — final MCP followup | `88ce46bd254747894b02cc40dcbf5f46d339d058e99bf3152d7781bbfcd834fc` |

The code evolved while review ran. The first broad run predates the final recovery/external-reference changes; the last focused rebuild/rerun covers those changes. Subsequent source edits require the coordinator to keep final validation hashes and this verdict's scope aligned. The review did not independently run the fixed-port full acceptance/CLI/execution suite; it read relevant test scope and relied on its own targeted executions for the assertions above. No claim of exhaustive interprocess race exploration or formal proof is made.

The default server/stdio bridge does not instantiate provider client registration/callback/automatic-refresh routing, browser management approval/MCP routes, production delegation, or a natural-language/voice UI. These are explicit product-integration boundaries. The implementation plan permits local trusted library/host/simulator demonstrations for these V1 adapter tasks; the absence of default routing is not labeled an external-account blocker or silently promoted to complete end-user integration. Adding those local routes is feasible software work if later required. Real provider accounts/registered applications, named-agent runtime access, approved external deployment, and actual model/ASR endpoints remain separate unverified prerequisites; none was simulated into a compatibility pass.

No dependency vulnerability audit, real upstream revocation, remote MCP OAuth transport test, five-agent task, existing browser-profile import, real model/ASR inference, or production secret/log inspection was performed. Site scripts and the trusted browser necessarily can see filled credentials; process-memory forensic erasure and resistance to a malicious same-UID/root process are not promised.
