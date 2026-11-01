import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  createOAuthLeaseId, createProductionOAuthAdapter, createSyntheticOAuthAdapter, normalizeOAuthScopes, OAUTH_PRODUCTION_REGISTRY,
  OAuthError, type OAuthAdapter, type OAuthBinding, type OAuthConnection, type OAuthExpectedVersion,
  type OAuthMaterialChange, type OAuthMaterialLease, type OAuthMaterialStore, type OAuthProvider,
} from '../src/oauth.js';
import { startOAuthSimulator, type OAuthSimulator } from '../src/oauth-simulator.js';

const initialBinding: OAuthBinding = { ownerId: 'local', principalId: 'admin:test', sessionId: 'session-test', securityEpoch: 1 };
const providerScopes = (provider: OAuthProvider) => provider === 'github' ? ['read:user'] : ['email', 'openid'];
class Store implements OAuthMaterialStore {
  binding = { ...initialBinding };
  unlocked = true;
  record: OAuthConnection;
  lease?: OAuthMaterialLease;
  constructor(provider: OAuthProvider) {
    this.record = { connectionId: 'approved-connection', provider, recordVersion: 1, statusVersion: 1, materialVersion: 1, status: 'reauthorization_required', scopes: providerScopes(provider) };
  }
  async assertAuthorized(binding: OAuthBinding) {
    if (!this.unlocked || JSON.stringify(binding) !== JSON.stringify(this.binding)) throw new OAuthError('vault_locked_or_binding_invalid');
  }
  async read(binding: OAuthBinding, id: string) {
    await this.assertAuthorized(binding);
    return id === this.record.connectionId ? structuredClone(this.record) : undefined;
  }
  async reserve(binding: OAuthBinding, provider: OAuthProvider, expected: OAuthExpectedVersion, action: OAuthMaterialLease['action']) {
    await this.assertAuthorized(binding);
    if (this.lease) throw new OAuthError('material_change_unresolved');
    if (provider !== this.record.provider || expected.connectionId !== this.record.connectionId || expected.recordVersion !== this.record.recordVersion || expected.statusVersion !== this.record.statusVersion || expected.materialVersion !== this.record.materialVersion) throw new OAuthError('material_version_conflict');
    this.lease = { leaseId: createOAuthLeaseId(), provider, expected: { ...expected }, action };
    return structuredClone(this.lease);
  }
  async complete(binding: OAuthBinding, lease: OAuthMaterialLease, change: OAuthMaterialChange) {
    await this.assertAuthorized(binding);
    if (this.lease?.leaseId !== lease.leaseId || this.record.recordVersion !== lease.expected.recordVersion || this.record.statusVersion !== lease.expected.statusVersion || this.record.materialVersion !== lease.expected.materialVersion) throw new OAuthError('material_version_conflict');
    this.record.status = change.status;
    this.record.statusVersion++;
    if (change.material || change.clearMaterial) this.record.materialVersion++;
    if (change.material) this.record.material = structuredClone(change.material);
    if (change.clearMaterial) delete this.record.material;
    if (change.subject !== undefined) this.record.subject = change.subject;
    if (change.status !== 'outcome_unknown') this.lease = undefined;
    const { material: _material, ...metadata } = this.record;
    return structuredClone(metadata);
  }
}
async function setup(provider: OAuthProvider, simulatorOptions: Parameters<typeof startOAuthSimulator>[0] = { provider }) {
  let now = 1_800_000_000_000;
  const clock = () => now;
  const simulator = await startOAuthSimulator({ ...simulatorOptions, provider, clock });
  const store = new Store(provider);
  const binding = { ...store.binding };
  const options = { provider, clientId: simulator.clientId, clientSecret: simulator.clientSecret, redirectUri: simulator.redirectUri, endpoints: simulator.endpoints, store, clock };
  const adapter = createSyntheticOAuthAdapter(options);
  return { adapter, store, binding, simulator, options, clock, advance: (ms: number) => { now += ms; } };
}
async function callbackUrl(adapter: OAuthAdapter, simulator: OAuthSimulator, store: Store, binding: OAuthBinding, offline = true): Promise<string> {
  const begin = await adapter.begin({ binding, target: store.record, scopes: providerScopes(adapter.provider), offline });
  const response = await fetch(begin.authorizationUrl, { redirect: 'manual' });
  assert.equal(response.status, 302);
  const location = response.headers.get('location');
  assert.ok(location?.startsWith(simulator.redirectUri));
  await response.body?.cancel();
  return location!;
}
async function authorize(fixture: Awaited<ReturnType<typeof setup>>, offline = true) {
  return fixture.adapter.callback({ binding: fixture.binding, callbackUrl: await callbackUrl(fixture.adapter, fixture.simulator, fixture.store, fixture.binding, offline) });
}
for (const provider of ['github', 'google'] as const) {
  test(`OAuth ${provider}: network authorization, verified subject, refresh, revoke and independent versions`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    const result = await authorize(f);
    assert.equal(result.status, 'active');
    assert.equal(result.subject, provider === 'github' ? '1234567' : 'synthetic-google-subject');
    assert.equal(result.recordVersion, 1);
    assert.equal(result.statusVersion, 2);
    assert.equal(result.materialVersion, 2);
    assert.ok(!JSON.stringify(result).includes('accessToken'));
    assert.ok(f.store.record.material?.accessExpiresAt! > f.clock());
    const first = structuredClone(f.store.record.material!);
    const refreshed = await f.adapter.refresh({ binding: f.binding, connectionId: result.connectionId, expectedRecordVersion: 1 });
    assert.equal(refreshed.recordVersion, 1);
    assert.equal(refreshed.statusVersion, 3);
    assert.equal(refreshed.materialVersion, 3);
    assert.notEqual(f.store.record.material?.accessToken, first.accessToken);
    if (provider === 'github') {
      assert.notEqual(f.store.record.material?.refreshToken, first.refreshToken);
      const replay = await fetch(f.simulator.endpoints.token, { method: 'POST', body: new URLSearchParams({ client_id: f.simulator.clientId, client_secret: f.simulator.clientSecret, grant_type: 'refresh_token', refresh_token: first.refreshToken! }) });
      assert.equal(replay.status, 400);
      assert.equal((await replay.json() as { error: string }).error, 'bad_refresh_token');
    } else assert.equal(f.store.record.material?.refreshToken, first.refreshToken);
    assert.deepEqual(f.store.record.material?.grantedScopes, first.grantedScopes);
    const revoked = await f.adapter.revoke({ binding: f.binding, connectionId: result.connectionId, expectedRecordVersion: 1 });
    assert.equal(revoked.status, 'revoked');
    assert.equal(f.store.record.material, undefined);
    await f.adapter.revoke({ binding: f.binding, connectionId: result.connectionId, expectedRecordVersion: 1 });
    await assert.rejects(f.adapter.refresh({ binding: f.binding, connectionId: result.connectionId, expectedRecordVersion: 1 }), /connection_unavailable/u);
    assert.deepEqual(f.simulator.counts, { authorize: 1, exchange: 1, refresh: provider === 'github' ? 2 : 1, identity: 1, revoke: 1, callback: 0 });
  });
  test(`OAuth ${provider}: exact callback and session/owner/principal/epoch state bindings; single use`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    const url = await callbackUrl(f.adapter, f.simulator, f.store, f.binding);
    for (const changed of [
      { ...f.binding, sessionId: 'other' }, { ...f.binding, principalId: 'other' },
      { ...f.binding, ownerId: 'other' }, { ...f.binding, securityEpoch: 2 },
    ]) await assert.rejects(f.adapter.callback({ binding: changed, callbackUrl: url }), /callback_binding_mismatch/u);
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url.replace('/callback?', '/callback/wrong?') }), /callback_mismatch/u);
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url + '&state=duplicate' }), /invalid_callback/u);
    const bogusState = new URL(url); bogusState.searchParams.set('state', 'forged');
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: bogusState.href }), /state_invalid_or_consumed/u);
    assert.equal(f.simulator.counts.exchange, 0);
    await f.adapter.callback({ binding: f.binding, callbackUrl: url });
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), /state_invalid_or_consumed/u);
    assert.equal(f.simulator.counts.exchange, 1);
  });
  test(`OAuth ${provider}: authorization expiry, denial, restart and lock consume no token request`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    let url = await callbackUrl(f.adapter, f.simulator, f.store, f.binding);
    f.advance(600_000);
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), /authorization_expired/u);
    f.simulator.nextAuthorizationDenied = true;
    url = await callbackUrl(f.adapter, f.simulator, f.store, f.binding);
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), /authorization_denied/u);
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), /state_invalid_or_consumed/u);
    url = await callbackUrl(f.adapter, f.simulator, f.store, f.binding);
    const restarted = createSyntheticOAuthAdapter(f.options);
    await assert.rejects(restarted.callback({ binding: f.binding, callbackUrl: url }), /state_invalid_or_consumed/u);
    f.store.unlocked = false;
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), /vault_locked/u);
    f.store.unlocked = true;
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), /state_invalid_or_consumed/u);
    assert.equal(f.simulator.counts.exchange, 0);
  });
  test(`OAuth ${provider}: simulator actually enforces PKCE, redirect, client secret, code expiry and code reuse`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    const verifier = 'a'.repeat(64);
    const auth = new URL(f.simulator.endpoints.authorize);
    for (const [key, value] of Object.entries({ client_id: f.simulator.clientId, redirect_uri: f.simulator.redirectUri, response_type: 'code', scope: providerScopes(provider).join(' '), state: 'synthetic-state', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' })) auth.searchParams.set(key, value);
    const response = await fetch(auth, { redirect: 'manual' });
    const code = new URL(response.headers.get('location')!).searchParams.get('code')!;
    await response.body?.cancel();
    const parameters = { client_id: f.simulator.clientId, client_secret: f.simulator.clientSecret, code, redirect_uri: f.simulator.redirectUri, grant_type: 'authorization_code', code_verifier: verifier };
    const exchange = async (parameters: Record<string, string>) => {
      const res = await fetch(f.simulator.endpoints.token, { method: 'POST', body: new URLSearchParams(parameters) });
      return { status: res.status, data: await res.json() as Record<string, unknown> };
    };
    assert.equal((await exchange({ ...parameters, code_verifier: 'b'.repeat(64) })).status, 400);
    assert.equal((await exchange({ ...parameters, redirect_uri: f.simulator.redirectUri + '/other' })).status, 400);
    assert.equal((await exchange({ ...parameters, client_secret: 'wrong' })).status, 401);
    assert.equal((await exchange(parameters)).status, 200);
    assert.equal((await exchange(parameters)).status, 400);
    const another = await fetch(auth, { redirect: 'manual' });
    const oldCode = new URL(another.headers.get('location')!).searchParams.get('code')!;
    await another.body?.cancel();
    f.advance(600_000);
    assert.equal((await exchange({ ...parameters, code: oldCode })).status, 400);
  });
  test(`OAuth ${provider}: concurrent refresh uses one durable lease and makes one HTTP request`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    await authorize(f);
    const request = { binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 };
    const results = await Promise.allSettled([f.adapter.refresh(request), f.adapter.refresh(request)]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.equal(f.simulator.counts.refresh, 1);
    assert.equal(f.store.record.recordVersion, 1);
    assert.equal(f.store.record.materialVersion, 3);
  });
  test(`OAuth ${provider}: confirmed invalid_grant requires reauthorization and errors omit provider descriptions`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    await authorize(f);
    f.simulator.nextTokenFault = 'invalid_grant';
    const request = { binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 };
    await assert.rejects(f.adapter.refresh(request), error => error instanceof OAuthError && error.code === 'reauthorization_required' && !String(error).includes('must-not-leak'));
    assert.equal(f.store.record.status, 'reauthorization_required');
    await assert.rejects(f.adapter.refresh(request), /connection_unavailable/u);
    assert.equal(f.simulator.counts.refresh, 1);
  });
  test(`OAuth ${provider}: ambiguous rotating refresh is blocked without automatic retry`, async t => {
    const f = await setup(provider, { provider, rotateGoogleRefresh: true });
    t.after(() => f.simulator.close());
    await authorize(f);
    f.simulator.nextTokenFault = 'drop_after_rotation';
    const request = { binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 };
    await assert.rejects(f.adapter.refresh(request), /provider_outcome_unknown/u);
    assert.equal(f.store.record.status, 'outcome_unknown');
    assert.ok(f.store.lease);
    await assert.rejects(f.adapter.refresh(request), /connection_unavailable/u);
    await assert.rejects(f.adapter.revoke(request), /material_change_unresolved/u);
    assert.equal(f.simulator.counts.refresh, 1);
  });
  test(`OAuth ${provider}: pending target CAS, local scope approval and PKCE mutation reject safely`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    await assert.rejects(f.adapter.begin({ binding: f.binding, target: f.store.record, scopes: [...providerScopes(provider), 'extra'] }), /scope_not_approved/u);
    const first = await callbackUrl(f.adapter, f.simulator, f.store, f.binding);
    f.store.record.recordVersion++;
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: first }), /material_version_conflict/u);
    assert.equal(f.simulator.counts.exchange, 0);
    const begin = await f.adapter.begin({ binding: f.binding, target: f.store.record, scopes: providerScopes(provider), offline: true });
    const auth = new URL(begin.authorizationUrl); auth.searchParams.set('code_challenge', 'x'.repeat(43));
    const response = await fetch(auth, { redirect: 'manual' });
    const callback = response.headers.get('location')!; await response.body?.cancel();
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: callback }), /reauthorization_required/u);
    assert.equal(f.store.record.status, 'reauthorization_required');
    assert.equal(f.simulator.counts.exchange, 1);
  });
  test(`OAuth ${provider}: first authorization callback rejects unapproved granted scopes before identity or activation`, async t => {
    const f = await setup(provider, { provider, googleScopeAliases: true });
    t.after(() => f.simulator.close());
    const url = await callbackUrl(f.adapter, f.simulator, f.store, f.binding);
    f.simulator.nextTokenFault = 'scope_expansion';
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), error => error instanceof OAuthError && error.code === 'scope_not_approved' && error.message === 'scope_not_approved');
    assert.notEqual(f.store.record.status, 'active');
    assert.equal(f.store.record.material, undefined);
    assert.equal(f.store.record.materialVersion, 1);
    assert.equal(f.simulator.counts.exchange, 1);
    assert.equal(f.simulator.counts.identity, 0);
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), /state_invalid_or_consumed/u);
    assert.equal(f.simulator.counts.exchange, 1);
  });
  test(`OAuth ${provider}: first authorization callback still requires every requested scope`, async t => {
    const f = await setup(provider);
    t.after(() => f.simulator.close());
    const begin = await f.adapter.begin({ binding: f.binding, target: f.store.record, scopes: providerScopes(provider), offline: true });
    const auth = new URL(begin.authorizationUrl);
    auth.searchParams.set('scope', provider === 'github' ? 'offline_access' : 'openid');
    const response = await fetch(auth, { redirect: 'manual' });
    const url = response.headers.get('location')!; await response.body?.cancel();
    await assert.rejects(f.adapter.callback({ binding: f.binding, callbackUrl: url }), error => error instanceof OAuthError && error.code === 'insufficient_scope' && error.message === 'insufficient_scope');
    assert.equal(f.store.record.status, 'reauthorization_required');
    assert.equal(f.store.record.material, undefined);
    assert.equal(f.simulator.counts.exchange, 1);
    assert.equal(f.simulator.counts.identity, 0);
  });
  test(`OAuth ${provider}: redirect, malformed response and scope expansion block token use`, async t => {
    for (const fault of ['redirect', 'malformed', 'scope_expansion'] as const) {
      const f = await setup(provider);
      t.after(() => f.simulator.close());
      await authorize(f);
      f.simulator.nextTokenFault = fault;
      await assert.rejects(f.adapter.refresh({ binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 }), /provider_outcome_unknown|invalid_provider_response|refresh_scope_changed/u);
      assert.notEqual(f.store.record.status, 'active');
      assert.equal(f.simulator.counts.refresh, 1);
    }
  });
}
test('OAuth GitHub: non-expiring online OAuth App grant has no invented refresh capability', async t => {
  const f = await setup('github'); t.after(() => f.simulator.close());
  await authorize(f, false);
  assert.equal(f.store.record.material?.refreshToken, undefined);
  assert.equal(f.store.record.material?.accessExpiresAt, undefined);
  await assert.rejects(f.adapter.refresh({ binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 }), /refresh_unavailable/u);
  assert.equal(f.simulator.counts.refresh, 0);
});
test('OAuth Google: offline access does not guarantee refresh issuance, and rotated refresh is persisted', async t => {
  const noRefresh = await setup('google', { provider: 'google', issueGoogleRefresh: false }); t.after(() => noRefresh.simulator.close());
  await authorize(noRefresh);
  await assert.rejects(noRefresh.adapter.refresh({ binding: noRefresh.binding, connectionId: noRefresh.store.record.connectionId, expectedRecordVersion: 1 }), /refresh_unavailable/u);
  const f = await setup('google', { provider: 'google', rotateGoogleRefresh: true }); t.after(() => f.simulator.close());
  await authorize(f);
  const old = f.store.record.material?.refreshToken;
  await f.adapter.refresh({ binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 });
  assert.notEqual(f.store.record.material?.refreshToken, old);
});
test('OAuth Google: subsequent authorization omitting refresh token preserves same-subject existing active refresh material', async t => {
  const f = await setup('google'); t.after(() => f.simulator.close());
  await authorize(f);
  const refreshToken = f.store.record.material?.refreshToken;
  assert.ok(refreshToken);
  await authorize(f, false);
  assert.equal(f.store.record.material?.refreshToken, refreshToken);
  assert.equal(f.store.record.recordVersion, 1);
});
test('OAuth GitHub: expired refresh material changes status without provider HTTP dispatch', async t => {
  const f = await setup('github'); t.after(() => f.simulator.close());
  await authorize(f);
  f.advance(180 * 86400_000);
  await assert.rejects(f.adapter.refresh({ binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 }), /reauthorization_required/u);
  assert.equal(f.store.record.status, 'reauthorization_required');
  assert.equal(f.simulator.counts.refresh, 0);
});
test('OAuth Google: official full URI identity scope responses match approved shorthand through network authorization and refresh', async t => {
  const f = await setup('google', { provider: 'google', googleScopeAliases: true }); t.after(() => f.simulator.close());
  f.store.record.scopes = ['openid', 'https://www.googleapis.com/auth/userinfo.email'];
  const result = await authorize(f);
  assert.equal(result.status, 'active');
  assert.deepEqual(f.store.record.material?.grantedScopes, ['email', 'openid']);
  await f.adapter.refresh({ binding: f.binding, connectionId: f.store.record.connectionId, expectedRecordVersion: 1 });
  assert.deepEqual(f.store.record.material?.grantedScopes, ['email', 'openid']);
  assert.deepEqual(normalizeOAuthScopes('google', ['email', 'https://www.googleapis.com/auth/userinfo.email', 'profile', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']), ['email', 'openid', 'profile']);
  assert.deepEqual(normalizeOAuthScopes('google', ['https://evil.invalid/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.email.extra']), ['https://evil.invalid/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.email.extra']);
  assert.deepEqual(normalizeOAuthScopes('github', ['https://www.googleapis.com/auth/userinfo.email']), ['https://www.googleapis.com/auth/userinfo.email']);
});
test('OAuth production registry is immutable HTTPS; production rejects endpoint/transport overrides and synthetic requires literal loopback', () => {
  const store = new Store('github');
  const production = { provider: 'github' as const, clientId: 'synthetic-client', clientSecret: 'synthetic-secret', redirectUri: 'https://manager.example.invalid/callback', store };
  const adapter = createProductionOAuthAdapter(production);
  assert.equal(adapter.synthetic, false);
  assert.ok(Object.isFrozen(OAUTH_PRODUCTION_REGISTRY));
  for (const entry of Object.values(OAUTH_PRODUCTION_REGISTRY)) {
    assert.ok(Object.isFrozen(entry));
    for (const endpoint of Object.values(entry)) assert.equal(new URL(endpoint).protocol, 'https:');
  }
  assert.throws(() => createProductionOAuthAdapter({ ...production, endpoints: {} } as never), /unsupported_option/u);
  assert.throws(() => createProductionOAuthAdapter({ ...production, fetch: globalThis.fetch } as never), /unsupported_option/u);
  assert.throws(() => createProductionOAuthAdapter({ ...production, redirectUri: 'http://127.0.0.1/callback' }), /invalid_endpoint/u);
  const endpoints = { authorize: 'http://127.0.0.1:1234/auth', token: 'http://127.0.0.1:1234/token', identity: 'http://127.0.0.1:1234/id', revoke: 'http://127.0.0.1:1234/revoke' };
  for (const endpoint of ['http://localhost/token', 'http://127.0.0.1.evil.invalid/token', 'https://oauth2.googleapis.com/token', 'http://169.254.169.254/token', 'http://127.0.0.1/token#x', 'http://user@127.0.0.1/token']) {
    assert.throws(() => createSyntheticOAuthAdapter({ ...production, redirectUri: 'http://127.0.0.1:1234/callback', endpoints: { ...endpoints, token: endpoint } }), /invalid_endpoint/u);
  }
  // Constructor assertions above never dispatch production HTTP.
});
