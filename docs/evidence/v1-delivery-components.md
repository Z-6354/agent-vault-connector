# V1 delegation, optional drafting and trusted enrollment MCP evidence

Recorded 2026-11-01. These components were implemented against PROJECT-DESIGN §8A A1/A5 and the actual core contracts. The component tests use actual Node HTTP, SQLite Vault and official MCP SDK transports where stated; inference/ASR outputs are deterministic synthetic fixtures, with no actual model/ASR inference or external platform call.

## Files and trusted boundaries

- `src/delegation.ts`, `tests/delegation.test.ts`: `external_reference` always nonexecuting. `DelegationExecutor` takes trusted registry connection/grant/operation and server-mapped `Authority`, intersects local policy with formally bound grant fields, validates host/upstream identities and checks current grant/epoch/policy per call. Synthetic loopback transport pins numeric 127.0.0.1, fixed paths, no redirects or arbitrary targets, and HMAC authenticates requests/replies with a dedicated fixture key. Actual loopback fixture verifies center identity, upstream principal/account and grant capabilities independently at dispatch. No shell or upstream-token export interface exists. Production delegated execution is not wired into the center registry/MCP; a real adapter must use the core durable A3 operation state machine.
- `src/local-draft.ts`, `tests/local-draft.test.ts`: explicit injected local inference and optional transcription interfaces, with no service discovery/network fallback. `bindVaultLocalDraftCore` uses actual Vault drafts/approvals/atomic saves; trusted callback validates administrator session and CSRF. Inference output cannot contain confirmation flags or approval credentials. Cards omit secret/approval and display one fixed mask. Secret whitespace survives exactly. Cancel/edit/expiry/lock reject pending drafts; inference timeout/abort ignores late results and saves nothing. Client keeps temporary references in memory only and cannot promise forensic memory erasure.
- `src/enrollment-mcp.ts`, `tests/enrollment-mcp.test.ts`: distinct trusted enrollment MCP with official SDK `McpServer`, `Client` and `InMemoryTransport`; only `save_credential` is exposed. Authority comes from a server-side current-session/epoch closure, not tool arguments. Core immutable approval is required. Strict tool discovery remains SDK-generated; a controlled `tools/call` handler validates inside a generic-error boundary because the SDK's default validation formats unknown argument keys into its error text. Regression probes place secret canaries in unknown top-level/nested keys and unknown tool names, and require zero echo/save. Tests exercise synthetic text fixture → memory draft → explicit trusted confirmation → actual MCP save, forged/missing approval and altered-payload refusal, revoked session/lock, identical request replay and conflicting payload refusal. Ordinary stdio execution tools remain separate.

The inference `endpoint` value in tests is a label supplied to the deterministic injected fixture; no service was probed or started there. The synthetic prewritten transcript is not ASR evidence. Numeric loopback validation alone does not establish that an arbitrary injected implementation avoids cloud forwarding, history or telemetry, so the component always reports completely-local verification as false.

## Actual results

The successful recorded component run used:

```sh
npm run build
node --test --test-concurrency=1 dist/tests/delegation.test.js dist/tests/local-draft.test.js dist/tests/enrollment-mcp.test.js
```

Build exited 0. Focused tests exited 0: **19 tests passed, 0 failed, 0 skipped**, duration 3.973 seconds. The test runner uses synthetic fixtures only, with temporary private vaults removed in cleanup. [Build output](v1-delivery-component-build.log), [TAP output](v1-delivery-components.log), [exact command/status/timestamps](v1-delivery-components-status.json). The final consolidated delivery run supersedes this focused run for cross-module results.

Coverage includes no-host external-reference refusal, successful formal synthetic delegation with separate requesting/center/shared-upstream identities, local/upstream operation/scope/audience/resource/endpoint intersections, missing formal evidence, wrong identities, grant expiry/revocation, host signature/changed grant/unreachable/timeout denial, revocation between verification and dispatch, and core lock/policy recheck. Negative tests assert zero successful host executions. Draft tests assert zero preconfirmation save calls/records, protected confirmation, no secret in cards or vault files, exact trusted callback secret proof, single save, cancel/expire/edit/lock invalidation, late inference denial, cancelled late ASR causing zero inference calls, no ASR when absent, remote endpoint rejection and actual approved MCP saves.

## Remaining blockers

No formally supported interface or delegated grant from Muse/Grok/Dot/Hermes/DSH was available. No real agent CLI was launched; no installed runtime config, production secret, token, account or existing browser profile was opened. No real local inference/ASR endpoint has been supplied or audited. End-to-end real text/audio inference, process/telemetry locality and five-agent compatibility therefore remain blocked. These blockers do not affect the no-model management UI/MCP core checks.
