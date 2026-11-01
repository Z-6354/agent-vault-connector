import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test, type TestContext } from 'node:test';
import Database from 'better-sqlite3';
import { initialize, Vault } from '../src/vault.js';
import type { Authority, SavePayload } from '../src/contracts.js';
import { createOAuthProduct, createSyntheticOAuthProduct, type OAuthProductOptions } from '../src/oauth-product.js';
import { createProductionOAuthAdapter, OAUTH_PRODUCTION_REGISTRY, type OAuthBinding, type OAuthProvider } from '../src/oauth.js';
import { createVaultOAuthStore } from '../src/oauth-vault.js';
import { startOAuthSimulator, type OAuthSimulatorOptions } from '../src/oauth-simulator.js';
import { UpstreamAuthorizationError } from '../src/network.js';

const passphrase = 'synthetic-oauth-product-passphrase';
const admin: Authority = { owner_id: 'local', principal_id: 'admin', client_id: 'management', session_id: 'product-session' };
const execution: Authority = { ...admin, principal_id: 'execution:local', client_id: 'execution' };
const scopes = (provider: OAuthProvider) => provider === 'github' ? ['read:user'] : ['email', 'openid'];
const operation = (provider: OAuthProvider) => provider === 'github' ? 'github.current_user' : 'google.userinfo';
async function setup(t: TestContext, provider: OAuthProvider, fixtureOptions: Partial<OAuthSimulatorOptions> = {}) {
  let now = 1_800_000_000_000;
  const clock = () => now;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'oauth-product-test-'));
  await initialize(directory, passphrase);
  const vault = new Vault(directory, { clock });
  await vault.unlock(passphrase);
  const simulator = await startOAuthSimulator({ ...fixtureOptions, provider, clock });
  t.after(async () => { await simulator.close(); vault.close(); await fs.rm(directory, { recursive: true, force: true }); });
  let live = true;
  const binding: OAuthBinding = { ownerId: 'local', principalId: 'admin', sessionId: admin.session_id!, securityEpoch: vault.epoch };
  const executionBinding: OAuthBinding = { ...binding, principalId: execution.principal_id };
  const resolveBinding: OAuthProductOptions['resolveBinding'] = value => {
    if (!live || value.sessionId !== admin.session_id || value.ownerId !== 'local' || value.securityEpoch !== vault.epoch) throw new Error('session_expired');
    if (value.principalId === admin.principal_id) return admin;
    if (value.principalId === execution.principal_id) return execution;
    throw new Error('principal_denied');
  };
  const options = { vault, resolveBinding, redirectUri: () => simulator.redirectUri, clock };
  const product = createSyntheticOAuthProduct({ ...options, providers: { [provider]: { endpoints: simulator.endpoints } } });
  const payload: SavePayload = {
    mode: 'create', label: 'Synthetic product OAuth', service_id: provider, credential_type: 'oauth', account_alias: 'synthetic-account',
    secret: JSON.stringify({ schema: 1, provider, approvedScopes: scopes(provider) }),
    origin: provider === 'github' ? 'https://api.github.com' : 'https://www.googleapis.com', environment: 'local', granted_operations: [operation(provider)],
  };
  const card = vault.createDraft(admin, payload);
  const approval = vault.approveDraft(admin, card.draft_id, card.draft_version);
  const record = vault.saveApproved(admin, { request_id: vault.prepareRequest(admin, 'save_connection'), draft_id: card.draft_id, draft_version: card.draft_version, approval_token: approval.approval_token, payload });
  const input = { connectionId: record.id, expectedRecordVersion: record.record_version };
  const executionInput = { ...input, operationId: operation(provider) };
  const configure = (expectedVersion = 0) => product.configureClient(binding, { provider, clientId: simulator.clientId, clientSecret: simulator.clientSecret, expectedVersion });
  const callbackUrl = async (offline = true, consent = false) => {
    const begin = await product.begin(binding, { ...input, offline, consent });
    const response = await fetch(begin.authorizationUrl, { redirect: 'manual' });
    assert.equal(response.status, 302);
    const callbackUrl = response.headers.get('location')!;
    await response.body?.cancel();
    return callbackUrl;
  };
  const authorize = async (offline = true) => product.callback(binding, { provider, callbackUrl: await callbackUrl(offline) });
  const material = () => JSON.parse(vault.readMaterial(admin, record.id).secret) as { material?: { accessToken: string; refreshToken?: string } };
  return { directory, vault, simulator, product, binding, executionBinding, record, input, executionInput, options, configure, callbackUrl, authorize, material,
    advance(ms: number) { now += ms; }, setLive(value: boolean) { live = value; } };
}
for (const provider of ['github', 'google'] as const) {
  test(`OAuth product ${provider}: encrypted config, pending confirmation, real callback, automatic concurrent refresh, fixed profile and revoke`, async t => {
    const f = await setup(t, provider, { googleScopeAliases: true });
    assert.equal(f.record.status, 'needs_user_action');
    const disabled = (await f.product.providers(f.binding)).find(item => item.provider === provider)!;
    assert.equal(disabled.enabled, false);
    assert.equal(disabled.reason, 'client_not_configured');
    await assert.rejects(f.product.begin(f.binding, f.input), /client_not_configured/u);
    const configured = await f.configure();
    assert.equal(configured.version, 1);
    assert.equal('clientSecret' in configured, false);
    assert.equal((await f.product.providers(f.binding)).find(item => item.provider === provider)!.enabled, true);
    const authorized = await f.authorize();
    assert.equal(authorized.status, 'active');
    assert.equal(authorized.recordVersion, f.record.record_version);
    assert.equal(authorized.subject, provider === 'github' ? '1234567' : 'synthetic-google-subject');
    assert.equal(authorized.materialVersion, f.record.material_version + 1);
    assert.ok(!JSON.stringify(authorized).includes('accessToken'));
    const before = f.material().material!;
    await f.product.prepareExecution(f.executionBinding, f.executionInput);
    assert.equal(f.simulator.counts.refresh, 0);
    f.advance(3600_001);
    await Promise.all(Array.from({ length: 6 }, () => f.product.prepareExecution(f.executionBinding, f.executionInput)));
    assert.equal(f.simulator.counts.refresh, 1);
    const after = f.material().material!;
    assert.notEqual(after.accessToken, before.accessToken);
    if (provider === 'github') assert.notEqual(after.refreshToken, before.refreshToken);
    else assert.equal(after.refreshToken, before.refreshToken);
    const profile = await f.vault.withToken(f.record.id, async secret => f.product.requestSyntheticProfile(provider, (JSON.parse(secret) as {material:{accessToken:string}}).material.accessToken, new AbortController().signal));
    assert.equal((profile as {id?: number;sub?: string})[provider === 'github' ? 'id' : 'sub'], provider === 'github' ? 1234567 : 'synthetic-google-subject');
    assert.equal(f.simulator.counts.identity, 2);
    const disk = await fs.readFile(path.join(f.directory, 'vault.sqlite'));
    for (const secret of [f.simulator.clientSecret, before.accessToken, before.refreshToken!, after.accessToken, after.refreshToken!]) assert.equal(disk.includes(Buffer.from(secret)), false);
    const db = new Database(path.join(f.directory, 'vault.sqlite'), { readonly: true });
    const audit = JSON.stringify(db.prepare('SELECT * FROM audit_events').all()); db.close();
    for (const secret of [f.simulator.clientSecret, before.accessToken, after.accessToken]) assert.ok(!audit.includes(secret));
    f.vault.setStatus(admin, f.record.id, 'paused', f.vault.get(f.record.id).status_version);
    await assert.rejects(f.product.prepareExecution(f.executionBinding, f.executionInput), /connection_unavailable/u);
    const revoked = await f.product.revoke(f.binding, f.input);
    assert.equal(revoked.status, 'revoked');
    assert.equal(f.material().material, undefined);
    await assert.rejects(f.product.prepareExecution(f.executionBinding, f.executionInput), /connection_unavailable/u);
    assert.equal(f.simulator.counts.refresh, 1);
    assert.equal(f.simulator.counts.revoke, 1);
  });
  test(`OAuth product ${provider}: management/session/state/target/version protection and config replacement invalidate callback`, async t => {
    const f = await setup(t, provider);
    await f.configure();
    let url = await f.callbackUrl();
    await assert.rejects(f.product.callback(f.executionBinding, { provider, callbackUrl: url }), /oauth_management_required/u);
    await assert.rejects(f.product.callback({ ...f.binding, ownerId: 'other' }, { provider, callbackUrl: url }), /session_expired/u);
    await assert.rejects(f.product.callback({ ...f.binding, sessionId: 'other' }, { provider, callbackUrl: url }), /session_expired/u);
    await assert.rejects(f.product.callback({ ...f.binding, principalId: 'unmapped' }, { provider, callbackUrl: url }), /principal_denied/u);
    await assert.rejects(f.product.begin(f.binding, { ...f.input, expectedRecordVersion: 42 }), /record_version_conflict/u);
    f.setLive(false);
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: url }), /session_expired/u);
    assert.equal(f.simulator.counts.exchange, 0);
    f.setLive(true);
    const beforeReplacement = f.vault.get(f.record.id);
    await f.configure(1);
    const afterReplacement = f.vault.get(f.record.id);
    assert.equal(afterReplacement.status, beforeReplacement.status);
    assert.equal(afterReplacement.status_version, beforeReplacement.status_version + 1);
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: url }), /state_invalid_or_consumed/u);
    url = await f.callbackUrl();
    // A trusted config update outside the cached coordinator is still observed.
    f.vault.writeOAuthClient(admin, provider, { clientId: f.simulator.clientId, clientSecret: f.simulator.clientSecret, redirectUri: f.simulator.redirectUri }, 2);
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: url }), /state_invalid_or_consumed/u);
    url = await f.callbackUrl();
    const paused = f.vault.setStatus(admin, f.record.id, 'paused', f.vault.get(f.record.id).status_version);
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: url }), /connection_unavailable|OAuth material denied|material_version_conflict/u);
    assert.equal(f.simulator.counts.exchange, 0);
    f.vault.setStatus(admin, f.record.id, 'active', paused.status_version);
    url = await f.callbackUrl();
    f.vault.lock();
    await f.vault.unlock(passphrase);
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: url }), /session_expired/u);
    assert.equal(f.simulator.counts.exchange, 0);
  });
  test(`OAuth product ${provider}: denied and expired callback consume state without exchanging, successful state cannot replay`, async t => {
    const f = await setup(t, provider);
    await f.configure();
    f.simulator.nextAuthorizationDenied = true;
    const denial = await f.callbackUrl();
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: denial }), /authorization_denied/u);
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: denial }), /state_invalid_or_consumed/u);
    const expired = await f.callbackUrl();
    f.advance(600_001);
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: expired }), /authorization_expired/u);
    assert.equal(f.simulator.counts.exchange, 0);
    const url = await f.callbackUrl();
    const changed = new URL(url); changed.searchParams.set('state', 'forged');
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: changed.href }), /state_invalid_or_consumed/u);
    await f.product.callback(f.binding, { provider, callbackUrl: url });
    await assert.rejects(f.product.callback(f.binding, { provider, callbackUrl: url }), /state_invalid_or_consumed/u);
    assert.equal(f.simulator.counts.exchange, 1);
  });
  test(`OAuth product ${provider}: client replacement requires fresh consent without reusing old grant material`, async t => {
    const f = await setup(t, provider);
    await f.configure(); await f.authorize();
    const before = f.material().material!;
    const differentFixture = createSyntheticOAuthProduct({ ...f.options, providers: { [provider]: { endpoints: { ...f.simulator.endpoints, identity: `${f.simulator.origin}/different-identity` } } } });
    await assert.rejects(differentFixture.prepareExecution(f.executionBinding, f.executionInput), /connection_unavailable/u);
    assert.equal(f.simulator.counts.identity, 1);
    await f.product.configureClient(f.binding, { provider, clientId: 'replacement-app', clientSecret: 'replacement-secret', expectedVersion: 1 });
    assert.equal(f.vault.get(f.record.id).status, 'needs_user_action');
    assert.equal(f.vault.get(f.record.id).can_execute, false);
    // Local status changes cannot bypass the persisted token/client binding.
    f.vault.setStatus(admin, f.record.id, 'active', f.vault.get(f.record.id).status_version);
    const restarted = createSyntheticOAuthProduct({ ...f.options, providers: { [provider]: { endpoints: f.simulator.endpoints } } });
    await assert.rejects(restarted.prepareExecution(f.executionBinding, f.executionInput), /reauthorization_required|connection_unavailable|oauth_client_changed/u);
    f.advance(3600_001);
    await assert.rejects(restarted.prepareExecution(f.executionBinding, f.executionInput), /reauthorization_required|connection_unavailable|oauth_client_changed/u);
    await assert.rejects(restarted.revoke(f.binding, f.input), /reauthorization_required|connection_unavailable|oauth_client_changed/u);
    assert.equal(f.simulator.counts.refresh, 0);
    assert.equal(f.simulator.counts.revoke, 0);
    assert.deepEqual(f.material().material, before);
    // Even restoring the original client values is a new config generation.
    await f.configure(2);
    await assert.rejects(f.product.prepareExecution(f.executionBinding, f.executionInput), /reauthorization_required|connection_unavailable|oauth_client_changed/u);
    await f.authorize(false);
    assert.equal(f.material().material?.refreshToken, undefined);
    assert.notEqual(f.material().material?.accessToken, before.accessToken);
    await f.product.prepareExecution(f.executionBinding, f.executionInput);
    assert.equal(f.simulator.counts.refresh, 0);
  });
  test(`OAuth product ${provider}: local revoked status still permits explicit remote OAuth revocation`, async t => {
    const f = await setup(t, provider);
    await f.configure(); await f.authorize();
    const token = f.material().material!.accessToken;
    f.vault.setStatus(admin, f.record.id, 'revoked', f.vault.get(f.record.id).status_version);
    assert.ok(f.material().material);
    const result = await f.product.revoke(f.binding, f.input);
    assert.equal(result.status, 'revoked');
    assert.equal(f.simulator.counts.revoke, 1);
    assert.equal(f.material().material, undefined);
    await f.product.revoke(f.binding, f.input);
    assert.equal(f.simulator.counts.revoke, 1);
    await assert.rejects(f.product.requestSyntheticProfile(provider, token, new AbortController().signal), UpstreamAuthorizationError);
  });
  test(`OAuth product ${provider}: lost refresh result persists needs_user_action and cannot retry after coordinator restart`, async t => {
    const f = await setup(t, provider, { rotateGoogleRefresh: true });
    await f.configure(); await f.authorize(); f.advance(3600_001);
    f.simulator.nextTokenFault = 'drop_after_rotation';
    await assert.rejects(f.product.prepareExecution(f.executionBinding, f.executionInput), /provider_outcome_unknown/u);
    assert.equal(f.vault.get(f.record.id).status, 'needs_user_action');
    assert.equal(f.vault.get(f.record.id).material_change_unresolved, true);
    const restarted = createSyntheticOAuthProduct({ ...f.options, providers: { [provider]: { endpoints: f.simulator.endpoints } } });
    await assert.rejects(restarted.prepareExecution(f.executionBinding, f.executionInput), /connection_unavailable|material_change_unresolved/u);
    await assert.rejects(restarted.revoke(f.binding, f.input), /material_change_unresolved/u);
    await assert.rejects(restarted.begin(f.binding, f.input), /material_change_unresolved/u);
    const old = f.material().material;
    await f.configure(1);
    assert.equal(f.vault.get(f.record.id).material_change_unresolved, true);
    assert.deepEqual(f.material().material, old);
    await assert.rejects(f.product.begin(f.binding, f.input), /material_change_unresolved/u);
    await assert.rejects(f.product.prepareExecution(f.executionBinding, f.executionInput), /connection_unavailable|material_change_unresolved/u);
    assert.equal(f.simulator.counts.refresh, 1);
  });
}
test('OAuth product: missing offline refresh requires reauthorization, paused/unauthorized execution cannot trigger refresh', async t => {
  const f = await setup(t, 'google', { issueGoogleRefresh: false });
  await f.configure(); await f.authorize(); f.advance(3600_001);
  await assert.rejects(f.product.prepareExecution(f.executionBinding, { ...f.executionInput, operationId: 'github.current_user' }), /connection_unavailable/u);
  const paused = f.vault.setStatus(admin, f.record.id, 'paused', f.vault.get(f.record.id).status_version);
  await assert.rejects(f.product.prepareExecution(f.executionBinding, f.executionInput), /connection_unavailable/u);
  f.vault.setStatus(admin, f.record.id, 'active', paused.status_version);
  await assert.rejects(f.product.prepareExecution(f.executionBinding, f.executionInput), /refresh_unavailable/u);
  assert.equal(f.vault.get(f.record.id).status, 'needs_user_action');
  assert.equal(f.simulator.counts.refresh, 0);
});
test('OAuth product: production endpoints remain immutable, exact loopback callback is permitted, synthetic mode never falls back to production', async t => {
  const f = await setup(t, 'github');
  const production = createOAuthProduct(f.options);
  const config = await production.configureClient(f.binding, { provider: 'github', clientId: f.simulator.clientId, clientSecret: f.simulator.clientSecret, expectedVersion: 0 });
  assert.equal(config.redirect_uri, f.simulator.redirectUri);
  const begin = await production.begin(f.binding, f.input);
  assert.equal(new URL(begin.authorizationUrl).origin, 'https://github.com');
  assert.equal(new URL(begin.authorizationUrl).searchParams.get('redirect_uri'), f.simulator.redirectUri);
  assert.equal(Object.isFrozen(OAUTH_PRODUCTION_REGISTRY), true);
  assert.equal(Object.isFrozen(OAUTH_PRODUCTION_REGISTRY.github), true);
  assert.throws(() => createOAuthProduct({ ...f.options, providers: {} } as OAuthProductOptions), /unsupported_option/u);
  await assert.rejects(production.configureClient(f.binding, { provider: 'github', clientId: f.simulator.clientId, clientSecret: f.simulator.clientSecret, expectedVersion: 1, endpoints: f.simulator.endpoints } as Parameters<typeof production.configureClient>[1]), /unsupported_option/u);
  await assert.rejects(production.requestSyntheticProfile('github', 'synthetic-token', new AbortController().signal), /synthetic_transport_unavailable/u);
  const missing = (await f.product.providers(f.binding)).find(item => item.provider === 'google')!;
  assert.equal(missing.enabled, false); assert.equal(missing.reason, 'synthetic_provider_not_configured');
  await assert.rejects(f.product.configureClient(f.binding, { provider: 'google', clientId: 'synthetic-google', clientSecret: 'synthetic-secret', expectedVersion: 0 }), /synthetic_provider_not_configured/u);
  const store = createVaultOAuthStore({ vault: f.vault, resolveAuthority: () => admin });
  for (const redirectUri of ['http://localhost:1234/callback', 'http://127.0.0.1/callback', 'http://127.0.0.1:1234/', 'http://127.0.0.1:1234/callback?query=1', 'http://127.0.0.1:1234/callback#fragment']) {
    assert.throws(() => createProductionOAuthAdapter({ provider: 'github', clientId: 'synthetic-client', clientSecret: 'synthetic-secret', redirectUri, store }), /invalid_endpoint/u);
  }
  for (const value of ['https://example.invalid/token', 'http://localhost:1234/token', 'http://127.0.0.1:1234/token?x=1']) {
    assert.throws(() => createSyntheticOAuthProduct({ ...f.options, providers: { github: { endpoints: { ...f.simulator.endpoints, token: value } } } }), /invalid_endpoint/u);
  }
});
