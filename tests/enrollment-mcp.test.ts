import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Authority, SavePayload, SaveRequest } from '../src/contracts.js';
import { Vault, initialize } from '../src/vault.js';
import { createTrustedEnrollmentMcp } from '../src/enrollment-mcp.js';
import { LocalDraftSession, bindVaultLocalDraftCore } from '../src/local-draft.js';

const auth: Authority = { owner_id: 'local', principal_id: 'admin:trusted', client_id: 'trusted-enrollment', session_id: 'fixture-session' };
const canary = 'synthetic_enrollment_mcp_exact_secret_123';
const payload: SavePayload = { mode: 'create', label: 'MCP fixture', service_id: 'synthetic-mock', credential_type: 'api_key',
  account_alias: 'fixture-account', secret: canary, origin: 'http://127.0.0.1:43121', environment: 'local', granted_operations: ['mock.account_summary'] };

async function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'avc-enroll-mcp-'));
  const directory = path.join(root, 'vault');
  await initialize(directory, 'synthetic enrollment passphrase');
  const vault = new Vault(directory);
  await vault.unlock('synthetic enrollment passphrase');
  const epoch = vault.epoch;
  let liveSession = true, saves = 0;
  const mcp = await createTrustedEnrollmentMcp({ currentAuthority: () => {
    if (!liveSession || !vault.unlocked || vault.epoch !== epoch) throw new Error('session_expired');
    return auth;
  }, saveApproved: (authority, request) => { saves++; return vault.saveApproved(authority, request); } });
  return { vault, mcp, directory, revoke: () => { liveSession = false; }, saves: () => saves,
    close: async () => { await mcp.close(); vault.close(); fs.rmSync(root, { recursive: true, force: true }); } };
}

test('optional synthetic draft confirms through real official SDK MCP save_credential exactly once; execution tools absent', async () => {
  const f = await setup();
  const core = bindVaultLocalDraftCore(f.vault, (session, csrf) => {
    if (session !== auth.session_id || csrf !== 'fixture-csrf') throw new Error('confirmation_denied');
    return auth;
  });
  const session = new LocalDraftSession({ authority: auth, security: () => ({ unlocked: f.vault.unlocked, epoch: f.vault.epoch }),
    inference: { endpoint: 'http://127.0.0.1:9999/synthetic-fixture', evidence: 'synthetic_fixture', infer: async () => structuredClone(payload) },
    core: { ...core, save: (_authority, request) => f.mcp.save(request) } });
  try {
    const tools = await f.mcp.client.listTools();
    assert.deepEqual(tools.tools.map(tool => tool.name), ['save_credential']);
    assert(!JSON.stringify(tools).includes(canary));
    const card = await session.fromText(`synthetic input ${canary}`);
    assert.equal(f.saves(), 0);
    assert.equal(f.vault.list().length, 0);
    const result = await session.confirm({ administrator_session: auth.session_id!, csrf: 'fixture-csrf', draft_id: card.draft_id,
      draft_version: card.draft_version, request_id: f.vault.prepareRequest(auth, 'save_connection') });
    assert.equal(f.saves(), 1);
    assert.equal(f.vault.list().length, 1);
    assert(!JSON.stringify(result).includes(canary));
    await f.vault.withToken(result.id, async secret => { assert.equal(secret, canary); });
    for (const name of fs.readdirSync(f.directory)) assert(!fs.readFileSync(path.join(f.directory, name)).includes(Buffer.from(canary)));
  } finally { session.dispose(); await f.close(); }
});

test('MCP save denies absent approval, altered payload, revoked session and lock; no secret error output', async () => {
  const f = await setup();
  try {
    const card = f.vault.createDraft(auth, payload);
    const request: SaveRequest = { request_id: f.vault.prepareRequest(auth, 'save_connection'), draft_id: card.draft_id,
      draft_version: card.draft_version, approval_token: 'model-fabricated', payload };
    const denied = await f.mcp.client.callTool({ name: 'save_credential', arguments: request as unknown as Record<string, unknown> });
    assert.equal(denied.isError, true);
    assert(!JSON.stringify(denied).includes(canary));
    const approval = f.vault.approveDraft(auth, card.draft_id, card.draft_version);
    await assert.rejects(f.mcp.save({ ...request, approval_token: approval.approval_token, payload: { ...payload, secret: canary + '_changed' } }), /enrollment_denied/);
    assert.equal(f.vault.list().length, 0);
    f.revoke();
    await assert.rejects(f.mcp.save({ ...request, approval_token: approval.approval_token }), /enrollment_denied/);
    assert.equal(f.vault.list().length, 0);
    f.vault.lock();
    await assert.rejects(f.mcp.save({ ...request, approval_token: approval.approval_token }), /enrollment_denied/);
  } finally { await f.close(); }
});

test('MCP malformed arguments and unknown tool names never echo attacker-supplied secret keys', async () => {
  const f = await setup();
  try {
    const secretKey = 'synthetic_malformed_secret_key_canary_12345';
    for (const request of [
      { name: 'save_credential', arguments: { [secretKey]: canary } },
      { name: 'save_credential', arguments: { request_id: 'invalid', payload: { [secretKey]: canary } } },
      { name: secretKey, arguments: {} },
    ]) {
      const result = await f.mcp.client.callTool(request);
      assert.equal(result.isError, true);
      assert(!JSON.stringify(result).includes(secretKey));
      assert(!JSON.stringify(result).includes(canary));
      assert(JSON.stringify(result).includes('enrollment_denied'));
    }
    assert.equal(f.saves(), 0);
    assert.equal(f.vault.list().length, 0);
  } finally { await f.close(); }
});

test('approved MCP retry returns original redacted result; different payload never rewrites', async () => {
  const f = await setup();
  try {
    const card = f.vault.createDraft(auth, payload);
    const approval = f.vault.approveDraft(auth, card.draft_id, card.draft_version);
    const request: SaveRequest = { request_id: f.vault.prepareRequest(auth, 'save_connection'), draft_id: card.draft_id,
      draft_version: card.draft_version, approval_token: approval.approval_token, payload };
    const first = await f.mcp.save(request);
    const retry = await f.mcp.save(request);
    assert.deepEqual(retry, first);
    assert.equal(f.vault.list().length, 1);
    await assert.rejects(f.mcp.save({ ...request, payload: { ...payload, account_alias: 'changed' } }), /enrollment_denied/);
    assert.equal(f.vault.list()[0]!.account_alias, 'fixture-account');
  } finally { await f.close(); }
});
