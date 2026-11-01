import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { initialize } from '../src/vault.js';
import { createServer } from '../src/server.js';

const passphrase = 'synthetic save recovery test passphrase';
const secret = 'synthetic_save_recovery_secret_123';

test('lost save response can be recovered after actual server restart and fresh login without secret or draft', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-save-recovery-')); const directory = path.join(root, 'vault');
  await initialize(directory, passphrase); let server = await createServer(directory, 0);
  let cookie = ''; let csrf = '';
  const request = async (url: string, method = 'GET', body?: unknown, extra: Record<string, string> = {}) => {
    const origin = server.origin;
    const response = await fetch(`${origin}${url}`, { method, headers: { ...(cookie ? { cookie } : {}), ...(method === 'GET' ? {} : { origin, 'x-csrf-token': csrf, 'content-type': 'application/json' }), ...extra }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const set = response.headers.get('set-cookie'); if (set) cookie = set.split(';')[0]!;
    const text = await response.text(); const data = JSON.parse(text); if (data.csrf) csrf = data.csrf;
    return { status: response.status, text, data };
  };
  const login = async () => { assert.equal((await request('/management/session')).status, 200); assert.equal((await request('/management/login', 'POST', { passphrase })).status, 200); };
  const unlock = async () => { assert.equal((await request('/management/unlock', 'POST', { passphrase })).status, 200); };
  try {
    await login(); await unlock();
    const payload = { mode: 'create', label: 'Recover committed save', service_id: 'synthetic-mock', credential_type: 'api_key', account_alias: 'recovery-account', secret, origin: 'http://127.0.0.1:43121', environment: 'local', granted_operations: ['mock.account_summary'] };
    const draftResponse = await request('/management/drafts', 'POST', payload); assert.equal(draftResponse.status, 201); const { draft, request_id } = draftResponse.data;
    const confirmed = await request(`/management/drafts/${draft.draft_id}/confirm`, 'POST', { draft_version: draft.draft_version, request_id }); assert.equal(confirmed.status, 200);
    // The response is deliberately not used by recovery. Persisted result, not pending/draft/session memory, must survive.
    const originalId = server.vault.list()[0]!.id; const originalVersion = server.vault.list()[0]!.record_version;
    const execution = { owner_id: 'local' as const, principal_id: 'execution:local', client_id: 'execution' };
    const wrongPrincipalTicket = server.vault.prepareRequest(execution, 'save_connection');
    await server.app.close(); server = await createServer(directory, 0); cookie = ''; csrf = '';
    assert.equal((await request('/management/save-result', 'POST', { request_id })).status, 401);
    await login(); assert.equal((await request('/management/save-result', 'POST', { request_id })).status, 423);
    await unlock();
    assert.equal((await request('/management/save-result', 'POST', { request_id }, { 'x-csrf-token': 'invalid' })).status, 403);
    assert.equal((await request('/management/save-result', 'POST', { request_id: 'unsigned-ticket-long-enough-to-pass-shape' })).status, 400);
    assert.equal((await request('/management/save-result', 'POST', { request_id: wrongPrincipalTicket })).status, 403);
    assert.equal((await request('/management/save-result', 'POST', { request_id, secret })).status, 400);
    const recovered = await request('/management/save-result', 'POST', { request_id }); assert.equal(recovered.status, 200); assert.equal(recovered.data.connection.id, originalId); assert.equal(recovered.data.connection.record_version, originalVersion);
    assert(!recovered.text.includes(secret)); assert(!recovered.text.includes('approval_token')); assert(!recovered.text.includes('encrypted'));
    assert.equal(server.vault.list().length, 1); assert.equal(server.vault.list()[0]!.record_version, 1);
    assert.equal((await request(`/management/drafts/${draft.draft_id}/confirm`, 'POST', { draft_version: draft.draft_version, request_id })).status, 403);
    const admin = { owner_id: 'local' as const, principal_id: 'admin', client_id: 'management', session_id: cookie.split('=')[1]! };
    assert.throws(() => server.vault.draftPayload(admin, draft.draft_id));
    const another = await request('/management/save-result', 'POST', { request_id }); assert.deepEqual(another.data.connection, recovered.data.connection); assert.equal(server.vault.list().length, 1);
    const notSaved = await request('/management/drafts', 'POST', { ...payload, account_alias: 'not-saved' });
    assert.equal((await request('/management/save-result', 'POST', { request_id: notSaved.data.request_id })).status, 404); assert.equal(server.vault.list().length, 1);
    await request(`/management/connections/${originalId}/purge-retained`, 'POST', {});
    assert.equal((await request('/management/save-result', 'POST', { request_id })).status, 410); assert.equal(server.vault.list().length, 1);
  } finally { await server.app.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
