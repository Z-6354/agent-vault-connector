import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { initialize, Vault } from '../src/vault.js';
import Database from 'better-sqlite3';
import { startOAuthSimulator } from '../src/oauth-simulator.js';
import { markSyntheticProduct, readProductConfig } from '../src/product-config.js';

const passphrase = 'synthetic-product-route-passphrase';
for (const provider of ['github', 'google'] as const) {
  test(`product routes ${provider}: session/CSRF/config/callback, executor refresh coalescing, unknown recovery, revoke and lock`, async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'product-routes-'));
    const directory = path.join(root, 'vault');
    let now = Date.now();
    await initialize(directory, passphrase);
    markSyntheticProduct(directory);
    const fixture = await startOAuthSimulator({ provider, clock: () => now, googleScopeAliases: true });
    const server = await createServer(directory, 0, { clock: () => now, productConfig: { mode: 'synthetic', providers: { github: { endpoints: fixture.endpoints }, google: { endpoints: fixture.endpoints } } } });
    // This trusted fixture must register the exact product callback; no production endpoint changes.
    Object.defineProperty(fixture, 'redirectUri', { value: `${server.origin}/management/oauth/callback/${provider}` });
    const host = new URL(server.origin).host;
    let cookie = '', csrf = '';
    const manage = async (url: string, method = 'GET', body?: unknown, extra: Record<string, string> = {}) => {
      const result = await server.app.inject({ method: method as any, url, headers: { host, cookie, ...(method === 'GET' ? {} : { origin: server.origin, 'content-type': 'application/json', 'x-csrf-token': csrf }), ...extra }, ...(body === undefined ? {} : { payload: body as any }) });
      const set = result.headers['set-cookie']; if (set) cookie = (Array.isArray(set) ? set[0]! : set).split(';')[0]!;
      const data = result.headers['content-type']?.includes('application/json') ? result.json() : {};
      if (data.csrf) csrf = data.csrf;
      return result;
    };
    const credential = fs.readFileSync(path.join(directory, 'execution.key'), 'utf8').trim();
    const execution = (url: string, body?: unknown) => server.app.inject({ method: body === undefined ? 'GET' : 'POST', url, headers: { host, authorization: `Bearer ${credential}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { payload: body as any }) });
    try {
      assert.equal((await manage('/management/oauth/providers')).statusCode, 401);
      await manage('/management/session'); await manage('/management/login', 'POST', { passphrase });
      assert.equal((await manage('/management/oauth/providers')).statusCode, 423);
      await manage('/management/unlock', 'POST', { passphrase });
      assert.equal((await execution('/execution/browser/sites')).json().supported, false);
      assert.equal((await execution('/execution/browser/session', { site_id: 'synthetic-login' })).json().error, 'unsupported');
      const disabled = (await manage('/management/oauth/providers')).json().providers.find((p: any) => p.provider === provider);
      assert.equal(disabled.enabled, false); assert.equal(disabled.reason, 'client_not_configured');
      const config = { provider, clientId: fixture.clientId, clientSecret: fixture.clientSecret, expectedVersion: 0 };
      assert.equal((await manage('/management/oauth/client', 'POST', config, { 'x-csrf-token': 'bad' })).statusCode, 403);
      assert.equal((await execution('/management/oauth/client', config)).statusCode, 403);
      assert.equal((await manage('/management/oauth/client', 'POST', { ...config, endpoints: fixture.endpoints })).statusCode, 400);
      if (provider === 'github') {
        const apiPayload = { mode: 'create', label: 'Synthetic cannot reach production', service_id: 'github', credential_type: 'api_key', account_alias: 'synthetic-api-key', secret: 'synthetic_no_production_network', origin: 'https://api.github.com', environment: 'local', granted_operations: ['github.current_user'] };
        const draft = (await manage('/management/drafts', 'POST', apiPayload)).json();
        const apiConnection = (await manage(`/management/drafts/${draft.draft.draft_id}/confirm`, 'POST', { draft_version: 1, request_id: draft.request_id })).json().connection;
        const request_id = (await execution('/execution/prepare-request', { operation_name: 'github.current_user' })).json().request_id;
        const denied = await execution('/execution/execute', { request_id, connection_id: apiConnection.id, operation_id: 'github.current_user', expected_record_version: 1, args: {} });
        assert.equal(denied.statusCode, 403);
        assert.equal(denied.json().error, 'synthetic_external_execution_denied');
      }
      const configured = await manage('/management/oauth/client', 'POST', config);
      assert.equal(configured.statusCode, 200); assert(!configured.body.includes(fixture.clientSecret));
      assert.equal((await manage('/management/oauth/client', 'POST', config)).statusCode, 409);
      const payload = { mode: 'create', label: 'Synthetic OAuth route', service_id: provider, credential_type: 'oauth', account_alias: 'synthetic-route', secret: JSON.stringify({ schema: 1, provider, approvedScopes: provider === 'github' ? ['read:user'] : ['email', 'openid'] }), origin: provider === 'github' ? 'https://api.github.com' : 'https://www.googleapis.com', environment: 'local', granted_operations: [provider === 'github' ? 'github.current_user' : 'google.userinfo'] };
      const draft = (await manage('/management/drafts', 'POST', payload)).json();
      const connection = (await manage(`/management/drafts/${draft.draft.draft_id}/confirm`, 'POST', { draft_version: 1, request_id: draft.request_id })).json().connection;
      const target = { connectionId: connection.id, expectedRecordVersion: connection.record_version };
      const authorize = async () => {
        const begin = await manage('/management/oauth/authorize', 'POST', { ...target, offline: true, consent: provider === 'google' });
        assert.equal(begin.statusCode, 200);
        const response = await fetch(begin.json().authorizationUrl, { redirect: 'manual' });
        assert.equal(response.status, 302); const callbackUrl = response.headers.get('location')!; await response.body?.cancel();
        return callbackUrl;
      };
      let callbackUrl = await authorize();
      assert.equal((await manage(`/management/oauth/callback/${provider}`, 'POST', { callbackUrl }, { 'x-csrf-token': 'bad' })).statusCode, 403);
      assert.equal(fixture.counts.exchange, 0);
      const relay = await server.app.inject({ method: 'GET', url: new URL(callbackUrl).pathname + new URL(callbackUrl).search, headers: { host, 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } });
      assert.equal(relay.statusCode, 200); assert(!relay.body.includes(new URL(callbackUrl).searchParams.get('code')!)); assert.equal(fixture.counts.exchange, 0);
      assert.equal((await manage(`/management/oauth/callback/${provider}`, 'POST', { callbackUrl })).statusCode, 200);
      assert.equal((await manage(`/management/oauth/callback/${provider}`, 'POST', { callbackUrl })).statusCode, 409);
      const operation_id = payload.granted_operations[0]!;
      const input = async () => ({ request_id: (await execution('/execution/prepare-request', { operation_name: operation_id })).json().request_id, connection_id: connection.id, operation_id, expected_record_version: 1, args: {} });
      const initial = await input();
      assert.equal((await execution('/execution/execute', initial)).json().operation.state, 'succeeded');
      // Keep the human session alive explicitly; execution must not extend its idle deadline.
      now += 14 * 60_000; await manage('/management/connections');
      for (let i = 0; i < 4; i++) { now += 14 * 60_000; await manage('/management/connections'); }
      const before = fixture.counts.refresh;
      const requests = await Promise.all([input(), input()]);
      const results = await Promise.all(requests.map(request => execution('/execution/execute', request)));
      assert(results.every(result => result.json().operation?.state === 'succeeded'));
      assert.equal(fixture.counts.refresh, before + 1);
      assert.equal((await execution('/execution/execute', initial)).json().operation.state, 'succeeded');
      assert.equal(fixture.counts.refresh, before + 1);
      for (let i = 0; i < 5; i++) { now += 14 * 60_000; await manage('/management/connections'); }
      fixture.nextTokenFault = 'drop_after_rotation';
      assert.equal((await execution('/execution/execute', await input())).statusCode, 409);
      const refreshes = fixture.counts.refresh;
      assert.equal((await execution('/execution/execute', await input())).statusCode, 409);
      assert.equal(fixture.counts.refresh, refreshes);
      let row = server.vault.get(connection.id);
      assert.equal(row.status, 'needs_user_action'); assert.equal(row.material_change_unresolved, true);
      const reconcile = { expected_record_version: row.record_version, expected_status_version: row.status_version, expected_material_version: row.material_version, evidence_note: 'Synthetic provider confirms lost rotating response', abandon_old_material: true };
      assert.equal((await manage(`/management/connections/${row.id}/reconcile-material`, 'POST', reconcile)).statusCode, 200);
      callbackUrl = await authorize();
      assert.equal((await manage(`/management/oauth/callback/${provider}`, 'POST', { callbackUrl })).statusCode, 200);
      assert.equal((await execution('/execution/execute', await input())).json().operation.state, 'succeeded');
      const material = JSON.parse(server.vault.readMaterial({ owner_id: 'local', principal_id: 'admin', client_id: 'management', session_id: 'trusted-fixture' }, connection.id).secret).material;
      const revokeResponse = await fetch(provider === 'github' ? `${fixture.endpoints.revoke}/${fixture.clientId}/grant` : fixture.endpoints.revoke, {
        method: provider === 'github' ? 'DELETE' : 'POST',
        headers: provider === 'github' ? { authorization: `Basic ${Buffer.from(`${fixture.clientId}:${fixture.clientSecret}`).toString('base64')}`, 'content-type': 'application/json' } : { 'content-type': 'application/x-www-form-urlencoded' },
        body: provider === 'github' ? JSON.stringify({ access_token: material.accessToken }) : new URLSearchParams({ token: material.refreshToken ?? material.accessToken }),
      });
      assert(revokeResponse.ok); await revokeResponse.body?.cancel();
      const unauthorized = await execution('/execution/execute', await input());
      assert.equal(unauthorized.json().operation.state, 'outcome_unknown');
      assert.equal(server.vault.get(connection.id).status, 'needs_user_action');
      const identityHits = fixture.counts.identity;
      assert.equal((await execution('/execution/execute', await input())).statusCode, 409);
      assert.equal(fixture.counts.identity, identityHits);
      callbackUrl = await authorize();
      assert.equal((await manage(`/management/oauth/callback/${provider}`, 'POST', { callbackUrl })).statusCode, 200);
      assert.equal((await manage('/management/oauth/revoke', 'POST', target)).statusCode, 200);
      assert.equal(fixture.counts.revoke, 2);
      assert.equal((await execution('/execution/execute', await input())).statusCode, 409);
      callbackUrl = await authorize();
      const oldCookie = cookie;
      await manage('/management/lock', 'POST', {});
      assert.equal((await execution('/execution/connections')).statusCode, 423);
      assert.equal((await manage(`/management/oauth/callback/${provider}`, 'POST', { callbackUrl }, { cookie: oldCookie })).statusCode, 401);
      await manage('/management/unlock', 'POST', { passphrase });
      assert.equal((await manage(`/management/oauth/callback/${provider}`, 'POST', { callbackUrl })).statusCode, 409);
      assert(!JSON.stringify((await manage('/management/audit')).json()).includes(fixture.clientSecret));
      for (const name of fs.readdirSync(directory)) assert(!fs.readFileSync(path.join(directory, name)).includes(Buffer.from(fixture.clientSecret)));
    } finally { await server.app.close(); await fixture.close(); fs.rmSync(root, { recursive: true, force: true }); }
  });
}

test('schema3 upgrade preserves a private original backup and persists encrypted OAuth client config across restart', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'product-migration-'));
  const directory = path.join(root, 'vault');
  await initialize(directory, passphrase);
  const filename = path.join(directory, 'vault.sqlite');
  const old = new Database(filename);
  old.exec('DROP TABLE oauth_clients; PRAGMA user_version=3;');
  old.close();
  const before = fs.readFileSync(filename);
  let vault: Vault | undefined;
  const admin = { owner_id: 'local', principal_id: 'admin', client_id: 'management', session_id: 'migration-session' } as const;
  try {
    vault = new Vault(directory);
    const backup = path.join(directory, 'vault.pre-v3-to-v4.sqlite');
    assert.deepEqual(fs.readFileSync(backup), before);
    assert.equal(fs.statSync(backup).mode & 0o777, 0o600);
    await vault.unlock(passphrase);
    vault.writeOAuthClient(admin, 'github', { clientId: 'synthetic-migration-client', clientSecret: 'synthetic-migration-client-secret', redirectUri: 'http://127.0.0.1:1234/callback' }, 0);
    vault.close(); vault = undefined;
    assert(!fs.readFileSync(filename).includes(Buffer.from('synthetic-migration-client-secret')));
    vault = new Vault(directory); await vault.unlock(passphrase);
    assert.equal(vault.readOAuthClient(admin, 'github')?.clientSecret, 'synthetic-migration-client-secret');
    assert.deepEqual(fs.readFileSync(backup), before);
    const db = new Database(filename, { readonly: true });
    try { assert.equal(db.pragma('user_version', { simple: true }), 4); } finally { db.close(); }
  } finally { vault?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('product startup configuration is private, explicit synthetic-only, and cannot override production endpoints', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'product-config-'));
  fs.chmodSync(root, 0o700);
  const directory = path.join(root, 'vault'); await initialize(directory, passphrase);
  const file = path.join(root, 'config.json');
  const endpoints = { authorize: 'http://127.0.0.1:1/authorize', token: 'http://127.0.0.1:1/token', identity: 'http://127.0.0.1:1/identity', revoke: 'http://127.0.0.1:1/revoke' };
  try {
    fs.writeFileSync(file, JSON.stringify({ mode: 'synthetic', providers: { github: { endpoints }, google: { endpoints } } }), { mode: 0o600 });
    assert.throws(() => readProductConfig(file, directory));
    markSyntheticProduct(directory);
    assert.equal(readProductConfig(file, directory).mode, 'synthetic');
    await assert.rejects(createServer(directory, 0), /synthetic_config_required/);
    await assert.rejects(createServer(directory, 0, { productConfig: { mode: 'production' } }), /synthetic_config_required/);
    fs.writeFileSync(file, JSON.stringify({ mode: 'production' }));
    assert.throws(() => readProductConfig(file, directory), /synthetic_config_required/);
    fs.writeFileSync(file, JSON.stringify({ mode: 'synthetic', providers: { github: { endpoints }, google: { endpoints } } }));
    fs.chmodSync(file, 0o644); assert.throws(() => readProductConfig(file, directory)); fs.chmodSync(file, 0o600);
    fs.writeFileSync(file, JSON.stringify({ mode: 'production', providers: { github: { endpoints } } }));
    assert.throws(() => readProductConfig(file, directory));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
