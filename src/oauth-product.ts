import type { Authority, Metadata } from './contracts.js';
import type { Vault } from './vault.js';
import {
  createProductionOAuthAdapter, createSyntheticOAuthAdapter, normalizeOAuthScopes, OAuthError, OAUTH_PRODUCTION_REGISTRY,
  type OAuthAdapter, type OAuthBinding, type OAuthConnection, type OAuthConnectionMetadata,
  type OAuthBeginResult, type OAuthProvider, type SyntheticOAuthOptions,
} from './oauth.js';
import { createVaultOAuthStore, type OAuthClientBinding } from './oauth-vault.js';
import { OAUTH_EXECUTION_POLICY as policy } from './registry.js';
import { UpstreamAuthorizationError } from './network.js';

export interface OAuthClientConfig { clientId: string; clientSecret: string; redirectUri: string; version: number }
export interface OAuthClientMetadata { provider: OAuthProvider; client_id: string; redirect_uri: string; version: number }
/** Trusted encrypted facility. These values must never be returned by a route. */
export interface OAuthClientFacility {
  writeOAuthClient(auth: Authority, provider: OAuthProvider, config: Omit<OAuthClientConfig, 'version'>, expected_version: number): OAuthClientMetadata;
  readOAuthClient(auth: Authority, provider: OAuthProvider): OAuthClientConfig | undefined;
}
type ProductVault = Pick<Vault, 'epoch' | 'requireUnlocked' | 'readMaterial' | 'reserveMaterial' | 'completeMaterial' | 'get'> & OAuthClientFacility;
export interface OAuthProductOptions {
  vault: ProductVault;
  /** Revalidate the live sole administrator session and epoch on EVERY call.
   * Execution contexts keep their execution principal and do not extend idle expiry. */
  resolveBinding(binding: OAuthBinding): Authority | Promise<Authority>;
  /** Exact callback URL computed by the trusted server, never a management body. */
  redirectUri(provider: OAuthProvider): string;
  clock?: () => number;
}
export interface SyntheticOAuthProductOptions extends OAuthProductOptions {
  /** Explicit isolated synthetic factory only. Omitted providers stay disabled. */
  providers: Partial<Record<OAuthProvider, { endpoints: SyntheticOAuthOptions['endpoints'] }>>;
}
export interface OAuthProductProvider {
  provider: OAuthProvider;
  enabled: boolean;
  synthetic: boolean;
  reason?: 'client_not_configured' | 'synthetic_provider_not_configured' | 'redirect_uri_changed';
  scopes: string[];
  operation_id: string;
  redirect_uri: string;
  client_id?: string;
  version?: number;
}
export interface OAuthProductExisting { connectionId: string; expectedRecordVersion: number }
export interface OAuthProductExecution extends OAuthProductExisting { operationId: string }
export interface OAuthProduct {
  readonly synthetic: boolean;
  providers(binding: OAuthBinding): Promise<OAuthProductProvider[]>;
  configureClient(binding: OAuthBinding, input: { provider: OAuthProvider; clientId: string; clientSecret: string; expectedVersion: number }): Promise<OAuthClientMetadata>;
  begin(binding: OAuthBinding, input: OAuthProductExisting & { offline?: boolean; consent?: boolean }): Promise<OAuthBeginResult>;
  callback(binding: OAuthBinding, input: { provider: OAuthProvider; callbackUrl: string }): Promise<OAuthConnectionMetadata>;
  revoke(binding: OAuthBinding, input: OAuthProductExisting): Promise<OAuthConnectionMetadata>;
  /** Called before beginOperation: leases must finish before execution is accepted. */
  prepareExecution(binding: OAuthBinding, input: OAuthProductExecution): Promise<void>;
  invalidatePending(): void;
  /** Trusted registry transport only. Its ordinary output whitelist/redaction still applies. */
  requestSyntheticProfile(provider: OAuthProvider, token: string, signal: AbortSignal): Promise<unknown>;
}
const providers = ['github', 'google'] as const;
function denied(code: string): never { throw new OAuthError(code); }
function provider(value: string): OAuthProvider { if (!providers.includes(value as OAuthProvider)) denied('unsupported_provider'); return value as OAuthProvider; }
function endpoint(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { return denied('invalid_endpoint'); }
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || !url.port || url.username || url.password || url.hash || url.search) denied('invalid_endpoint');
  return url.href;
}
interface CachedAdapter { adapter: OAuthAdapter; version: number; redirectUri: string; epoch: number }
class Product implements OAuthProduct {
  private adapters = new Map<OAuthProvider, CachedAdapter>();
  private refreshing = new Map<string, Promise<void>>();
  constructor(private options: OAuthProductOptions, readonly synthetic: boolean, private syntheticProviders: SyntheticOAuthProductOptions['providers'] = {}) {}
  private now(): number { return (this.options.clock ?? Date.now)(); }
  private async auth(binding: OAuthBinding, management = false): Promise<Authority> {
    const auth = await this.options.resolveBinding(binding);
    if (auth.owner_id !== binding.ownerId || auth.principal_id !== binding.principalId || auth.session_id !== binding.sessionId || binding.securityEpoch !== this.options.vault.epoch) denied('oauth_authority_denied');
    if (management && (auth.principal_id !== 'admin' || auth.client_id !== 'management' || !auth.session_id)) denied('oauth_management_required');
    if (!management && !((auth.principal_id === 'admin' && auth.client_id === 'management') || (auth.principal_id === 'execution:local' && auth.client_id === 'execution'))) denied('oauth_authority_denied');
    this.options.vault.requireUnlocked();
    return auth;
  }
  private config(auth: Authority, name: OAuthProvider): OAuthClientConfig {
    if (this.synthetic && !this.syntheticProviders[name]) denied('synthetic_provider_not_configured');
    const value = this.options.vault.readOAuthClient(auth, name);
    if (!value) denied('client_not_configured');
    if (value.redirectUri !== this.options.redirectUri(name)) denied('redirect_uri_changed');
    return value;
  }
  private clientBinding(name: OAuthProvider, config: OAuthClientConfig): OAuthClientBinding {
    const endpoints = this.synthetic ? this.syntheticProviders[name]!.endpoints : OAUTH_PRODUCTION_REGISTRY[name];
    return { clientId: config.clientId, version: config.version, context: JSON.stringify({ provider: name, mode: this.synthetic ? 'synthetic' : 'production', endpoints: { authorize: endpoints.authorize, token: endpoints.token, identity: endpoints.identity, revoke: endpoints.revoke } }) };
  }
  private clear(name: OAuthProvider): void { this.adapters.get(name)?.adapter.invalidatePending(); this.adapters.delete(name); }
  invalidatePending(): void {
    for (const name of providers) this.clear(name);
    this.refreshing.clear();
  }
  private async adapter(binding: OAuthBinding, name: OAuthProvider): Promise<OAuthAdapter> {
    const auth = await this.auth(binding);
    const config = this.config(auth, name);
    const cached = this.adapters.get(name);
    if (cached && cached.version === config.version && cached.redirectUri === config.redirectUri && cached.epoch === binding.securityEpoch) return cached.adapter;
    this.clear(name);
    const baseStore = createVaultOAuthStore({ vault: this.options.vault, resolveAuthority: async current => {
      const authority = await this.auth(current);
      const latest = this.config(authority, name);
      if (latest.version !== config.version || latest.redirectUri !== config.redirectUri) denied('oauth_client_changed');
      return authority;
    }, clientConfig: this.clientBinding(name, config), clock: this.options.clock });
    const adapterOptions = { provider: name, clientId: config.clientId, clientSecret: config.clientSecret, redirectUri: config.redirectUri, store: baseStore, clock: this.options.clock };
    const adapter = this.synthetic
      ? createSyntheticOAuthAdapter({ ...adapterOptions, endpoints: this.syntheticProviders[name]!.endpoints })
      : createProductionOAuthAdapter(adapterOptions);
    this.adapters.set(name, { adapter, version: config.version, redirectUri: config.redirectUri, epoch: binding.securityEpoch });
    return adapter;
  }
  async providers(binding: OAuthBinding): Promise<OAuthProductProvider[]> {
    const auth = await this.auth(binding, true);
    return providers.map(name => {
      const stored = this.options.vault.readOAuthClient(auth, name);
      const reason = this.synthetic && !this.syntheticProviders[name] ? 'synthetic_provider_not_configured'
        : !stored ? 'client_not_configured' : stored.redirectUri !== this.options.redirectUri(name) ? 'redirect_uri_changed' : undefined;
      return {
        provider: name, enabled: !reason, synthetic: this.synthetic, ...(reason ? { reason } : {}),
        scopes: [...policy[name].scopes], operation_id: policy[name].operationId, redirect_uri: this.options.redirectUri(name),
        ...(stored ? { client_id: stored.clientId, version: stored.version } : {}),
      };
    });
  }
  async configureClient(binding: OAuthBinding, input: { provider: OAuthProvider; clientId: string; clientSecret: string; expectedVersion: number }): Promise<OAuthClientMetadata> {
    const auth = await this.auth(binding, true);
    const name = provider(input.provider);
    if (Object.keys(input).some(key => !['provider', 'clientId', 'clientSecret', 'expectedVersion'].includes(key))) denied('unsupported_option');
    if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 0) denied('invalid_client_version');
    if (this.synthetic && !this.syntheticProviders[name]) denied('synthetic_provider_not_configured');
    const config = { clientId: input.clientId, clientSecret: input.clientSecret, redirectUri: this.options.redirectUri(name) };
    // Validate before persisting, with the same immutable endpoint factory used later.
    const store = createVaultOAuthStore({ vault: this.options.vault, resolveAuthority: current => this.auth(current), clock: this.options.clock });
    const options = { provider: name, ...config, store, clock: this.options.clock };
    if (this.synthetic) createSyntheticOAuthAdapter({ ...options, endpoints: this.syntheticProviders[name]!.endpoints });
    else createProductionOAuthAdapter(options);
    const result = this.options.vault.writeOAuthClient(auth, name, config, input.expectedVersion);
    this.clear(name);
    return result;
  }
  private record(input: OAuthProductExisting, name?: OAuthProvider, allowUnresolved = false): Metadata {
    const row = this.options.vault.get(input.connectionId);
    if (row.credential_type !== 'oauth') denied('oauth_connection_required');
    const actual = provider(row.service_id);
    if (name && actual !== name || row.origin !== policy[actual].origin) denied('oauth_provider_mismatch');
    if (row.record_version !== input.expectedRecordVersion) denied('record_version_conflict');
    if (row.material_change_unresolved && !allowUnresolved) denied('material_change_unresolved');
    return row;
  }
  private async connection(binding: OAuthBinding, row: Metadata): Promise<OAuthConnection> {
    const authority = await this.auth(binding);
    const name = provider(row.service_id);
    const config = this.config(authority, name);
    const store = createVaultOAuthStore({ vault: this.options.vault, resolveAuthority: async current => {
      const auth = await this.auth(current);
      if (this.config(auth, name).version !== config.version) denied('oauth_client_changed');
      return auth;
    }, clientConfig: this.clientBinding(name, config), clock: this.options.clock });
    const value = await store.read(binding, row.id);
    if (!value) denied('connection_not_found');
    const required = policy[value.provider].scopes;
    const approved = normalizeOAuthScopes(value.provider, value.scopes);
    if (approved.length !== required.length || !required.every(scope => approved.includes(scope))) denied('scope_not_approved');
    return value;
  }
  async begin(binding: OAuthBinding, input: OAuthProductExisting & { offline?: boolean; consent?: boolean }): Promise<OAuthBeginResult> {
    await this.auth(binding, true);
    const row = this.record(input);
    if (row.status === 'paused') denied('connection_unavailable');
    const name = provider(row.service_id);
    const adapter = await this.adapter(binding, name);
    const connection = await this.connection(binding, row);
    return adapter.begin({ binding, target: connection, scopes: [...policy[name].scopes], offline: input.offline, consent: input.consent });
  }
  async callback(binding: OAuthBinding, input: { provider: OAuthProvider; callbackUrl: string }): Promise<OAuthConnectionMetadata> {
    await this.auth(binding, true);
    return (await this.adapter(binding, provider(input.provider))).callback({ binding, callbackUrl: input.callbackUrl });
  }
  async revoke(binding: OAuthBinding, input: OAuthProductExisting): Promise<OAuthConnectionMetadata> {
    await this.auth(binding, true);
    const row = this.record(input);
    if (!['active', 'paused', 'needs_user_action', 'expired', 'revoked'].includes(row.status)) denied('connection_unavailable');
    return (await this.adapter(binding, provider(row.service_id))).revoke({ binding, ...input });
  }
  async prepareExecution(binding: OAuthBinding, input: OAuthProductExecution): Promise<void> {
    await this.auth(binding);
    const row = this.record(input, undefined, true);
    const name = provider(row.service_id);
    if (row.owner_id !== binding.ownerId || row.status !== 'active' || input.operationId !== policy[name].operationId || !row.granted_operations.includes(input.operationId)) denied('connection_unavailable');
    const key = `${name}:${row.id}:${row.record_version}:${binding.securityEpoch}`;
    const running = this.refreshing.get(key);
    if (running) { await running; return this.prepareExecution(binding, input); }
    if (row.material_change_unresolved) denied('material_change_unresolved');
    const adapter = await this.adapter(binding, name);
    const value = await this.connection(binding, row);
    if (value.status !== 'active' || !value.material) denied('connection_unavailable');
    const scopes = normalizeOAuthScopes(name, value.material.grantedScopes);
    if (scopes.length !== policy[name].scopes.length || !policy[name].scopes.every(scope => scopes.includes(scope))) denied('scope_not_approved');
    if (value.material.accessExpiresAt !== undefined && value.material.accessExpiresAt <= this.now()) {
      let pending = this.refreshing.get(key);
      if (!pending) {
        pending = (async () => {
          if (!value.material!.refreshToken) {
            const store = createVaultOAuthStore({ vault: this.options.vault, resolveAuthority: current => this.auth(current), clock: this.options.clock });
            const lease = await store.reserve(binding, name, value, 'refresh');
            await store.complete(binding, lease, { status: 'reauthorization_required' });
            denied('refresh_unavailable');
          }
          await adapter.refresh({ binding, connectionId: row.id, expectedRecordVersion: row.record_version });
        })();
        this.refreshing.set(key, pending);
        void pending.finally(() => { if (this.refreshing.get(key) === pending) this.refreshing.delete(key); }).catch(() => {});
      }
      await pending;
      // Each coalesced waiter must independently recheck its own live identity/policy.
      await this.auth(binding);
      const current = this.record(input, name);
      if (current.status !== 'active' || !current.granted_operations.includes(input.operationId)) denied('connection_unavailable');
      const refreshed = await this.connection(binding, current);
      if (!refreshed.material || refreshed.status !== 'active' || refreshed.material.accessExpiresAt !== undefined && refreshed.material.accessExpiresAt <= this.now()) denied('connection_unavailable');
    }
  }
  async requestSyntheticProfile(name: OAuthProvider, token: string, signal: AbortSignal): Promise<unknown> {
    if (!this.synthetic) denied('synthetic_transport_unavailable');
    const registered = this.syntheticProviders[provider(name)];
    if (!registered) denied('synthetic_provider_not_configured');
    const response = await fetch(registered.endpoints.identity, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }, redirect: 'error',
      signal: AbortSignal.any([signal, AbortSignal.timeout(5_000)]),
    });
    if (!response.ok) {
      await response.body?.cancel();
      if (response.status === 401) throw new UpstreamAuthorizationError();
      denied('synthetic_profile_failed');
    }
    if (!response.body) denied('synthetic_profile_failed');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 64 * 1024) { await reader.cancel(); denied('synthetic_profile_failed'); }
      chunks.push(value);
    }
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return denied('synthetic_profile_failed'); }
  }
}
function validateOptions(options: OAuthProductOptions, synthetic: boolean): void {
  if (Object.keys(options).some(key => !['vault', 'resolveBinding', 'redirectUri', 'clock', ...(synthetic ? ['providers'] : [])].includes(key))) denied('unsupported_option');
}
export function createOAuthProduct(options: OAuthProductOptions): OAuthProduct {
  validateOptions(options, false);
  return new Product({ ...options }, false);
}
/** Isolated opt-in factory; production cannot be configured to dispatch to these URLs. */
export function createSyntheticOAuthProduct(options: SyntheticOAuthProductOptions): OAuthProduct {
  validateOptions(options, true);
  const registered: SyntheticOAuthProductOptions['providers'] = {};
  for (const [name, config] of Object.entries(options.providers)) {
    provider(name);
    if (Object.keys(config).join(',') !== 'endpoints' || Object.keys(config.endpoints).sort().join(',') !== 'authorize,identity,revoke,token') denied('invalid_endpoint');
    const endpoints = {
      authorize: endpoint(config.endpoints.authorize), token: endpoint(config.endpoints.token),
      identity: endpoint(config.endpoints.identity), revoke: endpoint(config.endpoints.revoke),
    };
    registered[name as OAuthProvider] = Object.freeze({ endpoints: Object.freeze(endpoints) });
  }
  return new Product({ vault: options.vault, resolveBinding: options.resolveBinding, redirectUri: options.redirectUri, clock: options.clock }, true, Object.freeze(registered));
}
