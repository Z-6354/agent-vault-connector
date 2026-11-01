import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { initialize } from '../src/vault.js';
import { createServer } from '../src/server.js';

const passphrase = 'synthetic management acceptance passphrase';
const payload = { mode: 'create', label: 'Synthetic connection', service_id: 'synthetic-mock', credential_type: 'api_key', account_alias: 'account-one', secret: 'synthetic_server_auth_secret_123', origin: 'http://127.0.0.1:43121', environment: 'local', granted_operations: ['mock.account_summary'] };

test('management S0/S1/S2, one admin, epoch cookie/CSRF rotation and execution idle expiry', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-server-auth-'));
  const directory = path.join(root, 'vault'); let now = Date.now();
  await initialize(directory, passphrase);
  const server = await createServer(directory, 0, { clock: () => now });
  const origin = server.origin;
  let cookie = ''; let csrf = '';
  const request = async (url: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) => server.app.inject({ method: method as any, url, headers: { host: new URL(origin).host, ...(cookie ? { cookie } : {}), ...(method === 'GET' ? {} : { origin, 'x-csrf-token': csrf, 'content-type': 'application/json' }), ...headers }, ...(body === undefined ? {} : { payload: body as any }) });
  const adopt = (response: Awaited<ReturnType<typeof request>>) => { const set = response.headers['set-cookie']; if (set) cookie = (Array.isArray(set) ? set[0]! : set).split(';')[0]!; if (response.json().csrf) csrf = response.json().csrf; };
  try {
    let response = await request('/management/session'); adopt(response);
    assert.equal(response.json().state, 'S0'); const anonymousCookie = cookie; const anonymousCsrf = csrf;
    assert.equal((await request('/management/audit')).statusCode, 401);
    assert.equal((await request('/management/unlock', 'POST', { passphrase })).statusCode, 401);
    assert.equal((await request('/management/login', 'POST', { passphrase }, { 'x-csrf-token': 'wrong' })).statusCode, 403);
    assert.equal((await request('/management/login', 'POST', { passphrase }, { origin: 'http://evil.test' })).statusCode, 403);
    response = await request('/management/login', 'POST', { passphrase }); adopt(response);
    assert.equal(response.statusCode, 200); assert.equal(response.json().state, 'S1'); assert.equal(server.vault.unlocked, false);
    assert.notEqual(cookie, anonymousCookie); assert.notEqual(csrf, anonymousCsrf);
    assert.equal((await request('/management/connections')).statusCode, 423);
    assert.equal((await request('/management/audit')).statusCode, 423);
    assert.equal((await request('/management/drafts', 'POST', payload)).statusCode, 423);
    const lockedCookie = cookie; const lockedCsrf = csrf;
    response = await request('/management/unlock', 'POST', { passphrase }); adopt(response);
    assert.equal(response.json().state, 'S2'); assert.notEqual(cookie, lockedCookie); assert.notEqual(csrf, lockedCsrf);
    assert.equal((await request('/management/connections', 'GET', undefined, { cookie: lockedCookie })).statusCode, 401);
    const oldCookie = cookie; const oldCsrf = csrf; const oldEpoch = response.json().security_epoch;
    response = await request('/management/drafts', 'POST', payload);
    assert.equal(response.statusCode, 201); const draft = response.json();
    assert.equal((await request('/management/connections')).json().connections.length, 0);
    response = await request('/management/lock', 'POST', {}); adopt(response);
    assert.equal(response.json().state, 'S1'); assert(response.json().security_epoch > oldEpoch);
    assert.notEqual(cookie, oldCookie); assert.notEqual(csrf, oldCsrf);
    assert.equal((await request('/management/connections', 'GET', undefined, { cookie: oldCookie })).statusCode, 401);
    assert.equal((await request('/management/unlock', 'POST', { passphrase }, { 'x-csrf-token': oldCsrf })).statusCode, 403);
    response = await request('/management/unlock', 'POST', { passphrase }); adopt(response);
    assert.equal((await request(`/management/drafts/${draft.draft.draft_id}/confirm`, 'POST', { draft_version: 1, request_id: draft.request_id })).statusCode, 403);
    const executionKey = fs.readFileSync(path.join(directory, 'execution.key'), 'utf8').trim();
    const bearer = { authorization: `Bearer ${executionKey}` };
    for (const url of ['/management/session', '/management/connections', '/management/login', '/management/unlock', '/management/drafts', '/management/logout', '/']) {
      assert.equal((await request(url, url.includes('login') || url.includes('unlock') || url.includes('drafts') || url.includes('logout') ? 'POST' : 'GET', {}, bearer)).statusCode, 403);
    }
    // A second authenticated client replaces the sole administrator and locks the vault.
    const firstAdmin = cookie;
    cookie = ''; response = await request('/management/session'); adopt(response);
    response = await request('/management/login', 'POST', { passphrase }); adopt(response);
    assert.equal(response.json().state, 'S1'); assert.equal(server.vault.unlocked, false);
    assert.equal((await request('/management/connections', 'GET', undefined, { cookie: firstAdmin })).statusCode, 401);
    response = await request('/management/unlock', 'POST', { passphrase }); adopt(response);
    const lastCookie = cookie;
    now += 5 * 60_000;
    response = await request('/management/connections');
    assert.equal(response.statusCode, 200); assert.match(String(response.headers['set-cookie']), /Max-Age=900/); assert.match(String(response.headers['set-cookie']), /HttpOnly/); assert.match(String(response.headers['set-cookie']), /SameSite=Strict/i); assert(String(response.headers['set-cookie']).startsWith(lastCookie));
    now += 14 * 60_000;
    const execution = () => server.app.inject({ method: 'GET', url: '/execution/connections', headers: { host: new URL(origin).host, ...bearer } });
    assert.equal((await execution()).statusCode, 200);
    now += 60_001;
    const expiredExecution = await execution();
    assert.equal(expiredExecution.statusCode, 423); assert.deepEqual(expiredExecution.json(), { error: 'vault_locked' }); assert.equal(server.vault.unlocked, false);
    assert.equal((await request('/management/connections', 'GET', undefined, { cookie: lastCookie })).statusCode, 401);
    response = await request('/management/session'); adopt(response); assert.equal(response.json().state, 'S0');
    response = await request('/management/login', 'POST', { passphrase }); adopt(response);
    response = await request('/management/logout', 'POST', {}); assert.equal(response.json().state, 'S0');
    assert.equal(server.vault.unlocked, false); assert.match(String(response.headers['set-cookie']), /Max-Age=0|Expires=Thu, 01 Jan 1970/i);
  } finally { await server.app.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('manual drafts require exact confirmation and cancellation; record/status CAS; no direct-save route', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-server-draft-')); const directory = path.join(root, 'vault');
  await initialize(directory, passphrase); const server = await createServer(directory, 0);
  let cookie = ''; let csrf = ''; const origin = server.origin;
  const request = async (url: string, method = 'GET', body?: unknown) => {
    const response = await server.app.inject({ method: method as any, url, headers: { host: new URL(origin).host, cookie, ...(method === 'GET' ? {} : { origin, 'x-csrf-token': csrf, 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { payload: body as any }) });
    const set = response.headers['set-cookie']; if (set) cookie = (Array.isArray(set) ? set[0]! : set).split(';')[0]!;
    if (response.json().csrf) csrf = response.json().csrf; return response;
  };
  try {
    await request('/management/session'); await request('/management/login', 'POST', { passphrase }); await request('/management/unlock', 'POST', { passphrase });
    assert.equal((await request('/management/credentials', 'POST', payload)).statusCode, 404);
    assert.equal((await request('/management/connections', 'POST', payload)).statusCode, 404);
    let response = await request('/management/drafts', 'POST', payload); assert.equal(response.statusCode, 201); const cancelled = response.json();
    assert(!response.body.includes(payload.secret)); assert(!response.body.includes('approval_token'));
    assert.equal((await request(`/management/drafts/${cancelled.draft.draft_id}`, 'DELETE', {})).statusCode, 200);
    assert.equal((await request(`/management/drafts/${cancelled.draft.draft_id}/confirm`, 'POST', { draft_version: 1, request_id: cancelled.request_id })).statusCode, 403);
    response = await request('/management/drafts', 'POST', payload); const draft = response.json();
    const confirm = { draft_version: draft.draft.draft_version, request_id: draft.request_id };
    assert.equal((await request(`/management/drafts/${draft.draft.draft_id}/confirm`, 'POST', { ...confirm, secret: payload.secret })).statusCode, 400);
    assert.equal((await request(`/management/drafts/${draft.draft.draft_id}/confirm`, 'POST', { ...confirm, draft_version: 2 })).statusCode, 403);
    response = await request(`/management/drafts/${draft.draft.draft_id}/confirm`, 'POST', confirm); assert.equal(response.statusCode, 200); const connection = response.json().connection;
    assert.equal(connection.record_version, 1); assert.equal(connection.status_version, 1);
    assert.deepEqual((await request(`/management/drafts/${draft.draft.draft_id}/confirm`, 'POST', confirm)).json().connection, connection);
    assert.equal((await request('/management/connections')).json().connections.length, 1);
    assert.equal((await request('/management/operations')).statusCode, 200);
    const audit = await request('/management/audit'); assert.equal(audit.statusCode, 200); assert(audit.json().events.length > 0); assert(audit.json().events.length <= 100);
    assert(!audit.body.includes(payload.secret)); assert(!audit.body.includes('secret')); assert(!audit.body.includes('payload')); assert(!audit.body.includes('evidence_note'));
    for (const event of audit.json().events) assert.deepEqual(Object.keys(event).sort(), ['action', 'id', 'owner_id', 'principal_id', 'record_id', 'record_version', 'status_version', 'time']);
    assert.equal((await request(`/management/connections/${connection.id}/purge-retained`, 'POST', {})).statusCode, 200);
    response = await request(`/management/connections/${connection.id}/status`, 'PATCH', { status: 'paused', expected_status_version: 1 });
    assert.equal(response.statusCode, 200); assert.equal(response.json().connection.record_version, 1); assert.equal(response.json().connection.status_version, 2);
    assert.equal((await request(`/management/connections/${connection.id}/status`, 'PATCH', { status: 'active', expected_status_version: 1 })).statusCode, 409);
    assert.equal((await request(`/management/connections/${connection.id}`, 'DELETE', { expected_record_version: 2 })).statusCode, 409);
    response = await request(`/management/connections/${connection.id}`, 'DELETE', { expected_record_version: 1 });
    assert.equal(response.statusCode, 200); assert.equal(response.json().upstream_revoked, false);
    assert.equal((await request('/management/connections')).json().connections.length, 0);
    // Simulate an already-dispatched uncertain side effect in the journal, then exercise the management reconciliation boundary.
    const auth = { owner_id: 'local' as const, principal_id: 'execution:local', client_id: 'execution' };
    response = await request('/management/drafts', 'POST', { ...payload, account_alias: 'reconciliation' }); const secondDraft = response.json();
    response = await request(`/management/drafts/${secondDraft.draft.draft_id}/confirm`, 'POST', { draft_version: 1, request_id: secondDraft.request_id }); const second = response.json().connection;
    const input = { request_id: server.vault.prepareRequest(auth, 'mock.account_summary'), connection_id: second.id, operation_id: 'mock.account_summary', expected_record_version: 1, args: {} };
    server.vault.beginOperation(auth, input, { id: 'mock.account_summary', service_id: 'synthetic-mock', origin: payload.origin, semantics: 'non_idempotent', business_target: 'account' });
    server.vault.markDispatching(auth, input); server.vault.finishOperation(auth, input, 'outcome_unknown');
    const history = (await request('/management/operations')).json().operations; const unknown = history.find((item: any) => item.request_id === input.request_id); assert.equal(unknown.principal_id, 'execution:local');
    const reconcile = { request_id: input.request_id, operation_name: input.operation_id, principal_id: auth.principal_id, expected_operation_status_version: unknown.operation_status_version, resolution: 'authorize_new_attempt', evidence_note: 'synthetic upstream evidence reference' };
    assert.equal((await request('/management/operations/reconcile', 'POST', reconcile)).statusCode, 403);
    assert.equal((await request('/management/operations/reconcile', 'POST', { ...reconcile, accept_duplicate_risk: true, expected_operation_status_version: 1 })).statusCode, 409);
    response = await request('/management/operations/reconcile', 'POST', { ...reconcile, accept_duplicate_risk: true }); assert.equal(response.statusCode, 200); assert.equal(response.json().operation.state, 'failed_confirmed');
    assert.equal((await request('/management/operations/reconcile', 'POST', { ...reconcile, accept_duplicate_risk: true })).statusCode, 409);
    // The material route abandons an uncertain OAuth lease with independent record/status/material CAS.
    response = await request('/management/drafts', 'POST', { ...payload, service_id: 'github', credential_type: 'oauth', account_alias: 'synthetic-oauth-reconcile', origin: 'https://api.github.com', granted_operations: ['github.current_user'], secret: JSON.stringify({ schema: 1, provider: 'github', approvedScopes: ['read:user'] }) });
    const oauthDraft = response.json(); response = await request(`/management/drafts/${oauthDraft.draft.draft_id}/confirm`, 'POST', { draft_version: 1, request_id: oauthDraft.request_id }); const oauth = response.json().connection;
    const admin = { owner_id: 'local' as const, principal_id: 'admin', client_id: 'management', session_id: cookie.split('=')[1]! };
    const lease = server.vault.reserveMaterial(admin, oauth.id, { record_version: 1, status_version: 1, material_version: 1 }, 'authorize');
    server.vault.completeMaterial(admin, oauth.id, lease.lease_id, { status: 'needs_user_action', outcome_unknown: true });
    assert.equal(server.vault.get(oauth.id).material_change_unresolved, true);
    const materialRequest = { expected_record_version: 1, expected_status_version: 2, expected_material_version: 1, evidence_note: 'synthetic provider no-result evidence', abandon_old_material: true };
    assert.equal((await request(`/management/connections/${oauth.id}/reconcile-material`, 'POST', { ...materialRequest, abandon_old_material: false })).statusCode, 400);
    assert.equal((await request(`/management/connections/${oauth.id}/reconcile-material`, 'POST', { ...materialRequest, expected_material_version: 2 })).statusCode, 409);
    const csrfResponse = await server.app.inject({ method: 'POST', url: `/management/connections/${oauth.id}/reconcile-material`, headers: { host: new URL(origin).host, cookie, origin, 'content-type': 'application/json', 'x-csrf-token': 'wrong' }, payload: materialRequest }); assert.equal(csrfResponse.statusCode, 403);
    response = await request(`/management/connections/${oauth.id}/reconcile-material`, 'POST', materialRequest); assert.equal(response.statusCode, 200); const reconciled = response.json().connection;
    assert.equal(reconciled.status, 'needs_user_action'); assert.equal(reconciled.material_version, 2); assert.equal(reconciled.status_version, 3); assert.equal(reconciled.material_change_unresolved, false);
    assert.equal((await request(`/management/connections/${oauth.id}/reconcile-material`, 'POST', materialRequest)).statusCode, 409);
    for (const entry of fs.readdirSync(directory)) assert(!fs.readFileSync(path.join(directory, entry)).includes(Buffer.from(payload.secret)));
  } finally { await server.app.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
