import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import Database from 'better-sqlite3';
import { initialize, Vault } from '../src/vault.js';
import type { Authority, Metadata, SavePayload } from '../src/contracts.js';
import { createSyntheticOAuthAdapter, OAuthError, type OAuthBinding, type OAuthProvider, type OAuthTokenMaterial } from '../src/oauth.js';
import { createVaultOAuthStore, type OAuthVaultEnvelope } from '../src/oauth-vault.js';
import { startOAuthSimulator } from '../src/oauth-simulator.js';

const passphrase = 'synthetic-oauth-fixture-passphrase';
const auth: Authority = { owner_id: 'local', principal_id: 'admin:oauth-fixture', client_id: 'trusted-oauth-fixture', session_id: 'oauth-session' };
function approved(vault: Vault, provider: OAuthProvider): Metadata {
  const envelope: OAuthVaultEnvelope = { schema: 1, provider, approvedScopes: provider === 'github' ? ['read:user'] : ['email', 'openid'] };
  const payload: SavePayload = {
    mode: 'create', label: 'OAuth synthetic fixture', service_id: provider, credential_type: 'oauth', account_alias: 'fixture-account',
    secret: JSON.stringify(envelope), origin: provider === 'github' ? 'https://api.github.com' : 'https://www.googleapis.com',
    environment: 'local', granted_operations: [provider === 'github' ? 'github.current_user' : 'google.userinfo'],
  };
  const card = vault.createDraft(auth, payload);
  const approval = vault.approveDraft(auth, card.draft_id, card.draft_version);
  return vault.saveApproved(auth, { request_id: vault.prepareRequest(auth, 'save_connection'), draft_id: card.draft_id, draft_version: card.draft_version, approval_token: approval.approval_token, payload });
}
for (const provider of ['github', 'google'] as const) {
  test(`OAuth SQLite ${provider}: trusted completion independently rejects unapproved material grants and missing requested scopes`, async t => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'oauth-scope-fixture-'));
    await initialize(directory, passphrase);
    const vault = new Vault(directory);
    t.after(async () => { vault.close(); await fs.rm(directory, { recursive: true, force: true }); });
    await vault.unlock(passphrase);
    const initial = approved(vault, provider);
    const store = createVaultOAuthStore({ vault, resolveAuthority: () => auth });
    const binding: OAuthBinding = { ownerId: auth.owner_id, principalId: auth.principal_id, sessionId: auth.session_id!, securityEpoch: vault.epoch };
    const connection = (await store.read(binding, initial.id))!;
    const lease = await store.reserve(binding, provider, connection, 'authorize');
    const before = vault.readMaterial(auth, initial.id);
    const material: OAuthTokenMaterial = {
      accessToken: 'synthetic-initial-scope-access-token', refreshToken: 'synthetic-initial-scope-refresh-token', tokenType: 'Bearer',
      grantedScopes: provider === 'github' ? ['read:user'] : ['https://www.googleapis.com/auth/userinfo.email', 'openid'],
    };
    const unapprovedScopes = provider === 'github' ? ['repo'] : ['https://www.googleapis.com/auth/userinfo.profile', 'https://evil.invalid/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.email.extra'];
    for (const extra of unapprovedScopes) {
      for (const scopes of [undefined, connection.scopes]) {
        await assert.rejects(store.complete(binding, lease, {
          status: 'active', scopes, material: { ...material, grantedScopes: [...material.grantedScopes, extra] },
        }), error => error instanceof OAuthError && error.code === 'scope_not_approved' && error.message === 'scope_not_approved');
        assert.deepEqual(vault.readMaterial(auth, initial.id), before);
        assert.notEqual(vault.get(initial.id).status, 'active');
        assert.equal((await store.read(binding, initial.id))!.material, undefined);
      }
    }
    await assert.rejects(store.complete(binding, lease, {
      status: 'active', scopes: connection.scopes, material: { ...material, grantedScopes: provider === 'github' ? [] : ['openid'] },
    }), error => error instanceof OAuthError && error.code === 'insufficient_scope' && error.message === 'insufficient_scope');
    assert.deepEqual(vault.readMaterial(auth, initial.id), before);
    const completed = await store.complete(binding, lease, { status: 'active', scopes: connection.scopes, material });
    assert.equal(completed.status, 'active');
    assert.equal(completed.recordVersion, initial.record_version);
    assert.equal(completed.statusVersion, initial.status_version + 1);
    assert.equal(completed.materialVersion, initial.material_version + 1);
    assert.deepEqual((await store.read(binding, initial.id))!.material, material);
    assert.ok(!JSON.stringify(completed).includes(material.accessToken));
    assert.ok(!JSON.stringify(completed).includes(material.refreshToken!));
    const sqlite = new Database(path.join(directory, 'vault.sqlite'), { readonly: true });
    const audit = JSON.stringify(sqlite.prepare('SELECT * FROM audit_events').all());
    sqlite.close();
    assert.ok(!audit.includes(material.accessToken));
    assert.ok(!audit.includes(material.refreshToken!));
  });
  test(`OAuth SQLite ${provider}: approved record -> authorization -> concurrent refresh CAS -> revoke; encrypted at rest`, async t => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'oauth-vault-fixture-'));
    await initialize(directory, passphrase);
    const vault = new Vault(directory);
    t.after(async () => { vault.close(); await fs.rm(directory, { recursive: true, force: true }); });
    await vault.unlock(passphrase);
    const initial = approved(vault, provider);
    const simulator = await startOAuthSimulator({ provider, googleScopeAliases: true }); t.after(() => simulator.close());
    const binding: OAuthBinding = { ownerId: auth.owner_id, principalId: auth.principal_id, sessionId: auth.session_id!, securityEpoch: vault.epoch };
    let sessionLive = true;
    const store = createVaultOAuthStore({ vault, resolveAuthority: value => {
      if (!sessionLive || value.sessionId !== auth.session_id) throw new Error('session_denied');
      return auth;
    } });
    const adapter = createSyntheticOAuthAdapter({ provider, clientId: simulator.clientId, clientSecret: simulator.clientSecret, redirectUri: simulator.redirectUri, endpoints: simulator.endpoints, store });
    const connection = await store.read(binding, initial.id);
    assert.ok(connection);
    const begin = await adapter.begin({ binding, target: connection, scopes: connection.scopes, offline: true });
    const browser = await fetch(begin.authorizationUrl, { redirect: 'manual' });
    const callbackUrl = browser.headers.get('location')!; await browser.body?.cancel();
    const authorized = await adapter.callback({ binding, callbackUrl });
    assert.equal(authorized.recordVersion, initial.record_version);
    assert.equal(authorized.statusVersion, initial.status_version + 1);
    assert.equal(authorized.materialVersion, initial.material_version + 1);
    const old = (await store.read(binding, initial.id))!.material!;
    const secretBytes = await fs.readFile(path.join(directory, 'vault.sqlite'));
    assert.equal(secretBytes.includes(Buffer.from(old.accessToken)), false);
    assert.equal(secretBytes.includes(Buffer.from(old.refreshToken!)), false);
    const sqlite = new Database(path.join(directory, 'vault.sqlite'), { readonly: true });
    const audit = JSON.stringify(sqlite.prepare('SELECT * FROM audit_events').all());
    sqlite.close();
    assert.ok(!audit.includes(old.accessToken));
    assert.ok(!audit.includes(old.refreshToken!));
    assert.ok(!audit.includes(simulator.clientSecret));
    const request = { binding, connectionId: initial.id, expectedRecordVersion: initial.record_version };
    const results = await Promise.allSettled([adapter.refresh(request), adapter.refresh(request)]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(simulator.counts.refresh, 1);
    const refreshed = vault.get(initial.id);
    assert.equal(refreshed.record_version, initial.record_version);
    assert.equal(refreshed.material_version, initial.material_version + 2);
    assert.equal(refreshed.status_version, initial.status_version + 2);
    sessionLive = false;
    await assert.rejects(adapter.refresh(request), /session_denied/u);
    sessionLive = true;
    const revoked = await adapter.revoke(request);
    assert.equal(revoked.status, 'revoked');
    assert.equal(vault.get(initial.id).status, 'revoked');
    assert.equal((await store.read(binding, initial.id))?.material, undefined);
    assert.ok(!JSON.stringify(revoked).includes('accessToken'));
    vault.lock();
    await assert.rejects(store.read(binding, initial.id), /oauth_authority_denied/u);
    assert.equal(simulator.counts.refresh, 1);
  });
}
test('OAuth SQLite: lost rotating refresh response remains unresolved after restart and blocks retries', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'oauth-unknown-fixture-'));
  await initialize(directory, passphrase);
  let vault = new Vault(directory);
  t.after(async () => { vault.close(); await fs.rm(directory, { recursive: true, force: true }); });
  await vault.unlock(passphrase);
  const record = approved(vault, 'github');
  const simulator = await startOAuthSimulator({ provider: 'github' }); t.after(() => simulator.close());
  const makeStore = () => createVaultOAuthStore({ vault, resolveAuthority: () => auth });
  let store = makeStore();
  let binding: OAuthBinding = { ownerId: 'local', principalId: auth.principal_id, sessionId: auth.session_id!, securityEpoch: vault.epoch };
  const options = { provider: 'github' as const, clientId: simulator.clientId, clientSecret: simulator.clientSecret, redirectUri: simulator.redirectUri, endpoints: simulator.endpoints };
  let adapter = createSyntheticOAuthAdapter({ ...options, store });
  const connection = (await store.read(binding, record.id))!;
  const begin = await adapter.begin({ binding, target: connection, scopes: connection.scopes, offline: true });
  const response = await fetch(begin.authorizationUrl, { redirect: 'manual' });
  const callbackUrl = response.headers.get('location')!; await response.body?.cancel();
  await adapter.callback({ binding, callbackUrl });
  simulator.nextTokenFault = 'drop_after_rotation';
  await assert.rejects(adapter.refresh({ binding, connectionId: record.id, expectedRecordVersion: 1 }), /provider_outcome_unknown/u);
  assert.equal(vault.get(record.id).status, 'needs_user_action');
  vault.close();
  vault = new Vault(directory);
  await vault.unlock(passphrase);
  binding = { ...binding, securityEpoch: vault.epoch };
  store = makeStore(); adapter = createSyntheticOAuthAdapter({ ...options, store });
  await assert.rejects(adapter.refresh({ binding, connectionId: record.id, expectedRecordVersion: 1 }), /connection_unavailable/u);
  await assert.rejects(adapter.revoke({ binding, connectionId: record.id, expectedRecordVersion: 1 }), /material_change_unresolved/u);
  const sqlite = new Database(path.join(directory, 'vault.sqlite'), { readonly: true });
  assert.deepEqual(sqlite.prepare('SELECT state FROM material_leases WHERE connection_id=?').get(record.id), { state: 'outcome_unknown' });
  sqlite.close();
  assert.equal(simulator.counts.refresh, 1);
});
test('OAuth SQLite: lock between lease and completion rejects stale epoch and preserves blocking lease', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'oauth-lock-fixture-'));
  await initialize(directory, passphrase);
  const vault = new Vault(directory); t.after(async () => { vault.close(); await fs.rm(directory, { recursive: true, force: true }); });
  await vault.unlock(passphrase);
  const record = approved(vault, 'google');
  const store = createVaultOAuthStore({ vault, resolveAuthority: () => auth });
  const binding: OAuthBinding = { ownerId: 'local', principalId: auth.principal_id, sessionId: auth.session_id!, securityEpoch: vault.epoch };
  const connection = (await store.read(binding, record.id))!;
  const lease = await store.reserve(binding, 'google', connection, 'authorize');
  vault.lock(); await vault.unlock(passphrase);
  await assert.rejects(store.complete(binding, lease, { status: 'active' }), /oauth_authority_denied/u);
  const freshBinding = { ...binding, securityEpoch: vault.epoch };
  await assert.rejects(store.reserve(freshBinding, 'google', connection, 'authorize'), /material_change_unresolved/u);
  assert.equal(vault.get(record.id).material_version, record.material_version);
});
