import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { restrictedOAuthRequest } from './network.js';

/** Trusted management context, supplied by authentication code, never by a model. */
export interface OAuthBinding {
  ownerId: string;
  principalId: string;
  sessionId: string;
  securityEpoch: number;
}
export type OAuthProvider = 'github' | 'google';
export type OAuthStatus = 'active' | 'reauthorization_required' | 'revoked' | 'outcome_unknown' | 'error';
export interface OAuthTokenMaterial {
  accessToken: string;
  refreshToken?: string;
  tokenType: 'Bearer';
  accessExpiresAt?: number;
  refreshExpiresAt?: number;
  grantedScopes: string[];
}
export interface OAuthExpectedVersion {
  connectionId: string;
  recordVersion: number;
  statusVersion: number;
  materialVersion: number;
}
export interface OAuthConnectionMetadata extends OAuthExpectedVersion {
  provider: OAuthProvider;
  subject?: string;
  status: OAuthStatus;
  /** Local approved scope ceiling; authorization and refresh cannot expand it. */
  scopes: string[];
}
/** Secrets must remain inside trusted adapter/store code, never an MCP response. */
export interface OAuthConnection extends OAuthConnectionMetadata { material?: OAuthTokenMaterial }
export type OAuthAction = 'authorize' | 'refresh' | 'revoke';
export interface OAuthMaterialLease {
  leaseId: string;
  expected: OAuthExpectedVersion;
  provider: OAuthProvider;
  action: OAuthAction;
}
export interface OAuthMaterialChange {
  status: OAuthStatus;
  material?: OAuthTokenMaterial;
  subject?: string;
  /** Authorization requests a subset of the pre-approved scope ceiling. */
  scopes?: string[];
  clearMaterial?: boolean;
}
/**
 * Implementations MUST perform authorization, epoch, lock, owner and version checks
 * inside the same transaction as reserve/complete. read is trusted-only and must
 * decrypt only while unlocked. reserve durably excludes any competing refresh,
 * revoke, execution or replacement before an HTTP request is dispatched. A crash
 * leaves a blocking unresolved lease; never release it on a timer or blindly retry.
 * complete requires the exact lease + versions + epoch, stores AEAD ciphertext,
 * and atomically updates independent status/material versions. Neither refresh nor
 * authorize changes recordVersion: provider/scope changes require a separately
 * user-approved record replacement first. Do not persist pending
 * authorization state/verifiers. Logout/lock invalidates pending bindings by epoch.
 * On ambiguous dispatch, preserve the old encrypted material for reconciliation,
 * but deny its use. These methods must never log token or callback payloads.
 */
export interface OAuthMaterialStore {
  assertAuthorized(binding: OAuthBinding): Promise<void>;
  read(binding: OAuthBinding, connectionId: string): Promise<OAuthConnection | undefined>;
  reserve(binding: OAuthBinding, provider: OAuthProvider, expected: OAuthExpectedVersion, action: OAuthAction): Promise<OAuthMaterialLease>;
  complete(binding: OAuthBinding, lease: OAuthMaterialLease, change: OAuthMaterialChange): Promise<OAuthConnectionMetadata>;
}
export class OAuthError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'OAuthError'; }
}
interface Endpoints { authorize: string; token: string; identity: string; revoke: string }
/** No production endpoint options, discovery overrides, arbitrary headers or transport injection. */
export const OAUTH_PRODUCTION_REGISTRY: Readonly<Record<OAuthProvider, Readonly<Endpoints>>> = Object.freeze({
  github: Object.freeze({
    authorize: 'https://github.com/login/oauth/authorize',
    token: 'https://github.com/login/oauth/access_token',
    identity: 'https://api.github.com/user',
    revoke: 'https://api.github.com/applications',
  }),
  google: Object.freeze({
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    token: 'https://oauth2.googleapis.com/token',
    identity: 'https://openidconnect.googleapis.com/v1/userinfo',
    revoke: 'https://oauth2.googleapis.com/revoke',
  }),
});
export interface OAuthOptions {
  provider: OAuthProvider;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  store: OAuthMaterialStore;
  clock?: () => number;
}
export interface OAuthBeginRequest {
  binding: OAuthBinding;
  target: OAuthExpectedVersion;
  scopes: string[];
  /** Google offline access and GitHub OAuth App offline_access. */
  offline?: boolean;
  /** Google consent can recover a missing refresh token; never forced silently. */
  consent?: boolean;
}
export interface OAuthBeginResult { authorizationUrl: string; expiresAt: number }
export interface OAuthExistingRequest { binding: OAuthBinding; connectionId: string; expectedRecordVersion: number }
export interface OAuthAdapter {
  readonly provider: OAuthProvider;
  readonly synthetic: boolean;
  begin(request: OAuthBeginRequest): Promise<OAuthBeginResult>;
  callback(request: { binding: OAuthBinding; callbackUrl: string }): Promise<OAuthConnectionMetadata>;
  refresh(request: OAuthExistingRequest): Promise<OAuthConnectionMetadata>;
  revoke(request: OAuthExistingRequest): Promise<OAuthConnectionMetadata>;
  /** Call at lock/logout as well as enforcing store securityEpoch checks. */
  invalidatePending(): void;
}
const AUTH_TTL_MS = 10 * 60_000;
const HTTP_TIMEOUT_MS = 5_000;
const RESPONSE_LIMIT = 64 * 1024;
interface Pending {
  binding: OAuthBinding;
  target: OAuthExpectedVersion;
  scopes: string[];
  verifier: string;
  expiresAt: number;
}
function fail(code: string): never { throw new OAuthError(code); }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_provider_response');
  return value as Record<string, unknown>;
}
function secret(value: unknown): string {
  if (typeof value !== 'string' || !value.length || value.length > 16_384 || /[\x00-\x20\x7f]/u.test(value)) fail('invalid_provider_response');
  return value;
}
function expiry(value: unknown, now: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > 10 * 365 * 24 * 60 * 60) fail('invalid_provider_response');
  return now + (value as number) * 1000;
}
/** Only Google's two documented identity scope spellings are aliases. No generic URI rewriting. */
export function normalizeOAuthScopes(provider: OAuthProvider, values: readonly string[]): string[] {
  const aliases: Readonly<Record<string, string>> = {
    'https://www.googleapis.com/auth/userinfo.email': 'email',
    'https://www.googleapis.com/auth/userinfo.profile': 'profile',
  };
  return [...new Set(values.map(value => provider === 'google' && Object.hasOwn(aliases, value) ? aliases[value]! : value))].sort();
}
function scopes(value: unknown, provider: OAuthProvider): string[] {
  if (typeof value !== 'string' || value.length > 8192) fail('invalid_provider_response');
  return normalizeOAuthScopes(provider, value.split(provider === 'github' ? /[,\s]+/u : /\s+/u).filter(Boolean));
}
function validateScopes(value: string[]): string[] {
  if (!Array.isArray(value) || !value.length || value.length > 100 || value.some(s => typeof s !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]{1,512}$/u.test(s) || s.includes(','))) fail('invalid_scope');
  return [...new Set(value)].sort();
}
function sameBinding(a: OAuthBinding, b: OAuthBinding): boolean {
  return a.ownerId === b.ownerId && a.principalId === b.principalId && a.sessionId === b.sessionId && a.securityEpoch === b.securityEpoch;
}
function validateBinding(binding: OAuthBinding): void {
  if (!binding || ['ownerId', 'principalId', 'sessionId'].some(k => typeof binding[k as keyof OAuthBinding] !== 'string' || !(binding[k as keyof OAuthBinding] as string).length) || !Number.isSafeInteger(binding.securityEpoch) || binding.securityEpoch < 0) fail('invalid_binding');
}
function validateTarget(target: OAuthExpectedVersion): void {
  if (!target || typeof target.connectionId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(target.connectionId) || [target.recordVersion, target.statusVersion, target.materialVersion].some(v => !Number.isSafeInteger(v) || v < 0)) fail('invalid_target');
}
function parseUrl(value: string): URL { try { return new URL(value); } catch { return fail('invalid_url'); } }
function loopback(url: URL): boolean { return url.hostname === '127.0.0.1' || url.hostname === '[::1]'; }
function checkedUrl(value: string, synthetic: boolean): URL {
  const url = parseUrl(value);
  if (url.username || url.password || url.hash || url.search || (synthetic ? url.protocol !== 'http:' || !loopback(url) : url.protocol !== 'https:')) fail('invalid_endpoint');
  return url;
}
/** Native/local products may register an exact literal-IP loopback callback.
 * Provider endpoints themselves always keep checkedUrl's HTTPS requirement. */
function checkedRedirect(value: string, synthetic: boolean): URL {
  const url = parseUrl(value);
  if (!synthetic && url.protocol === 'http:' && loopback(url) && url.port && url.pathname !== '/' && !url.username && !url.password && !url.hash && !url.search) return url;
  return checkedUrl(value, synthetic);
}
function tokenMaterial(body: Record<string, unknown>, provider: OAuthProvider, now: number, previous?: OAuthTokenMaterial): OAuthTokenMaterial {
  if (typeof body.token_type !== 'string' || body.token_type.toLowerCase() !== 'bearer') fail('invalid_provider_response');
  const material: OAuthTokenMaterial = {
    accessToken: secret(body.access_token),
    tokenType: 'Bearer',
    grantedScopes: body.scope === undefined && previous ? [...previous.grantedScopes] : scopes(body.scope, provider),
    accessExpiresAt: expiry(body.expires_in, now),
  };
  if (body.refresh_token !== undefined) {
    material.refreshToken = secret(body.refresh_token);
    material.refreshExpiresAt = expiry(body.refresh_token_expires_in, now);
  } else if (previous?.refreshToken) {
    // Google usually omits refresh_token on refresh. GitHub rotates its pair.
    if (provider === 'github') fail('invalid_provider_response');
    material.refreshToken = previous.refreshToken;
    material.refreshExpiresAt = previous.refreshExpiresAt;
  }
  if ((provider === 'google' || material.refreshToken) && !material.accessExpiresAt) fail('invalid_provider_response');
  if (provider === 'github' && material.refreshToken && !material.refreshExpiresAt) fail('invalid_provider_response');
  if (previous && provider === 'github' && material.refreshToken === previous.refreshToken) fail('invalid_provider_response');
  return material;
}
async function http(url: string, init: RequestInit, synthetic: boolean, emptySuccess?: number): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    const request = { ...init, redirect: 'error' as const, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) };
    response = await (synthetic ? fetch(url, request) : restrictedOAuthRequest(url, request));
  }
  catch { return fail('provider_outcome_unknown'); }
  if (emptySuccess !== undefined && response.status === emptySuccess) { await response.body?.cancel(); return {}; }
  if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); return fail('provider_outcome_unknown'); }
  let content = '';
  try {
    if (!response.body) fail('invalid_provider_response');
    const reader = response.body!.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let size = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > RESPONSE_LIMIT) { await reader.cancel(); fail('invalid_provider_response'); }
      content += decoder.decode(value, { stream: true });
    }
    content += decoder.decode();
  } catch { return fail('provider_outcome_unknown'); }
  let body: Record<string, unknown>;
  try { body = object(JSON.parse(content)); } catch { return fail('invalid_provider_response'); }
  if (body.error !== undefined || !response.ok) {
    // Neither descriptions nor provider bodies may escape through error messages.
    if (['invalid_grant', 'bad_refresh_token', 'expired_refresh_token', 'bad_verification_code', 'access_denied'].includes(String(body.error))) fail('reauthorization_required');
    if (['invalid_client', 'incorrect_client_credentials', 'redirect_uri_mismatch'].includes(String(body.error))) fail('provider_configuration_error');
    fail(response.status >= 500 || response.status === 429 ? 'provider_outcome_unknown' : 'provider_rejected');
  }
  return body;
}
class Adapter implements OAuthAdapter {
  private pending = new Map<string, Pending>();
  readonly provider: OAuthProvider;
  constructor(private options: OAuthOptions, private endpoints: Readonly<Endpoints>, readonly synthetic: boolean) {
    this.provider = options.provider;
    if (!['github', 'google'].includes(options.provider)) fail('unsupported_provider');
    if (typeof options.clientId !== 'string' || !/^[A-Za-z0-9._-]{1,256}$/u.test(options.clientId)) fail('invalid_client');
    secret(options.clientSecret);
    checkedRedirect(options.redirectUri, synthetic);
  }
  private now(): number { return (this.options.clock ?? Date.now)(); }
  invalidatePending(): void { this.pending.clear(); }
  async begin(request: OAuthBeginRequest): Promise<OAuthBeginResult> {
    validateBinding(request.binding);
    validateTarget(request.target);
    const requested = normalizeOAuthScopes(this.provider, validateScopes(request.scopes));
    if (this.provider === 'google' && !requested.includes('openid')) fail('openid_scope_required');
    if (requested.includes('offline_access')) fail('use_offline_option');
    await this.options.store.assertAuthorized(request.binding);
    const connection = await this.options.store.read(request.binding, request.target.connectionId);
    if (!connection || connection.provider !== this.provider) fail('approved_connection_required');
    if (connection.recordVersion !== request.target.recordVersion || connection.statusVersion !== request.target.statusVersion || connection.materialVersion !== request.target.materialVersion) fail('version_conflict');
    if (requested.some(scope => !normalizeOAuthScopes(this.provider, connection.scopes).includes(scope))) fail('scope_not_approved');
    for (const [state, pending] of this.pending) if (pending.expiresAt <= this.now()) this.pending.delete(state);
    if (this.pending.size >= 1024) fail('too_many_pending_authorizations');
    const state = randomBytes(32).toString('base64url');
    const verifier = randomBytes(64).toString('base64url');
    const expiresAt = this.now() + AUTH_TTL_MS;
    this.pending.set(state, { binding: { ...request.binding }, target: { ...request.target }, scopes: requested, verifier, expiresAt });
    const url = new URL(this.endpoints.authorize);
    url.searchParams.set('client_id', this.options.clientId);
    url.searchParams.set('redirect_uri', this.options.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', [...requested, ...(request.offline && this.provider === 'github' ? ['offline_access'] : [])].join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', createHash('sha256').update(verifier).digest('base64url'));
    url.searchParams.set('code_challenge_method', 'S256');
    if (this.provider === 'google') {
      url.searchParams.set('access_type', request.offline ? 'offline' : 'online');
      // Do not silently combine prior grants or force a consent screen.
      url.searchParams.set('include_granted_scopes', 'false');
      if (request.consent) url.searchParams.set('prompt', 'consent');
    }
    return { authorizationUrl: url.href, expiresAt };
  }
  async callback(request: { binding: OAuthBinding; callbackUrl: string }): Promise<OAuthConnectionMetadata> {
    validateBinding(request.binding);
    const url = parseUrl(request.callbackUrl);
    const redirect = new URL(this.options.redirectUri);
    if (url.origin !== redirect.origin || url.pathname !== redirect.pathname || url.username || url.password || url.hash) fail('callback_mismatch');
    for (const key of ['state', 'code', 'error']) if (url.searchParams.getAll(key).length > 1) fail('invalid_callback');
    const state = url.searchParams.get('state');
    const pending = state ? this.pending.get(state) : undefined;
    if (!pending) fail('state_invalid_or_consumed');
    if (!sameBinding(pending.binding, request.binding)) fail('callback_binding_mismatch');
    this.pending.delete(state!); // All validly bound callbacks, including denials, are single use.
    if (pending.expiresAt <= this.now()) fail('authorization_expired');
    await this.options.store.assertAuthorized(request.binding);
    if (url.searchParams.has('error')) {
      if (url.searchParams.has('code')) fail('invalid_callback');
      fail(url.searchParams.get('error') === 'access_denied' ? 'authorization_denied' : 'authorization_failed');
    }
    const code = url.searchParams.get('code');
    if (!code || code.length > 4096 || /[\x00-\x20\x7f]/u.test(code)) fail('invalid_callback');
    const previous = await this.options.store.read(request.binding, pending.target.connectionId);
    const lease = await this.options.store.reserve(request.binding, this.provider, pending.target, 'authorize');
    let material: OAuthTokenMaterial | undefined;
    try {
      const body = await this.token({ grant_type: 'authorization_code', code, redirect_uri: this.options.redirectUri, code_verifier: pending.verifier });
      material = tokenMaterial(body, this.provider, this.now());
      if (!pending.scopes.every(scope => material!.grantedScopes.includes(scope))) fail('insufficient_scope');
      if (!previous || material.grantedScopes.some(scope => !normalizeOAuthScopes(this.provider, previous.scopes).includes(scope))) fail('scope_not_approved');
      await this.options.store.assertAuthorized(request.binding);
      const subject = await this.identity(material.accessToken);
      if (previous?.subject !== undefined && previous.subject !== subject) fail('oauth_subject_changed');
      if (this.provider === 'google' && !material.refreshToken && previous?.subject === subject && previous.status === 'active' && previous.material?.refreshToken && (previous.material.refreshExpiresAt === undefined || previous.material.refreshExpiresAt > this.now())) {
        material.refreshToken = previous.material.refreshToken;
        material.refreshExpiresAt = previous.material.refreshExpiresAt;
      }
      return await this.options.store.complete(request.binding, lease, { status: 'active', material, subject, scopes: pending.scopes });
    } catch (error) {
      await this.finishFailure(request.binding, lease, error);
      throw error;
    }
  }
  private async token(parameters: Record<string, string>): Promise<Record<string, unknown>> {
    return http(this.endpoints.token, {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.options.clientId, client_secret: this.options.clientSecret, ...parameters }),
    }, this.synthetic);
  }
  private async identity(accessToken: string): Promise<string> {
    const body = await http(this.endpoints.identity, { headers: {
      Authorization: `Bearer ${accessToken}`, Accept: 'application/json',
      ...(this.provider === 'github' ? { 'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'agent-vault-connector' } : {}),
    } }, this.synthetic);
    if (this.provider === 'google') {
      if (typeof body.sub !== 'string' || !/^[A-Za-z0-9_-]{1,255}$/u.test(body.sub)) fail('invalid_provider_identity');
      return body.sub;
    }
    if (typeof body.id === 'number' && Number.isSafeInteger(body.id) && body.id > 0) return String(body.id);
    if (typeof body.id === 'string' && /^[1-9][0-9]{0,19}$/u.test(body.id)) return body.id;
    return fail('invalid_provider_identity');
  }
  private async existing(request: OAuthExistingRequest): Promise<OAuthConnection> {
    validateBinding(request.binding);
    await this.options.store.assertAuthorized(request.binding);
    const value = await this.options.store.read(request.binding, request.connectionId);
    if (!value || value.provider !== this.provider) fail('connection_not_found');
    if (value.recordVersion !== request.expectedRecordVersion) fail('record_version_conflict');
    return value;
  }
  async refresh(request: OAuthExistingRequest): Promise<OAuthConnectionMetadata> {
    const connection = await this.existing(request);
    if (connection.status !== 'active' || !connection.material) fail('connection_unavailable');
    if (!connection.material.refreshToken) fail('refresh_unavailable');
    const lease = await this.options.store.reserve(request.binding, this.provider, connection, 'refresh');
    try {
      if (connection.material.refreshExpiresAt !== undefined && connection.material.refreshExpiresAt <= this.now()) fail('reauthorization_required');
      const body = await this.token({ grant_type: 'refresh_token', refresh_token: connection.material.refreshToken });
      const material = tokenMaterial(body, this.provider, this.now(), connection.material);
      if (material.grantedScopes.some(scope => !normalizeOAuthScopes(this.provider, connection.material!.grantedScopes).includes(scope))) fail('refresh_scope_changed');
      if (!normalizeOAuthScopes(this.provider, connection.scopes).every(scope => material.grantedScopes.includes(scope))) fail('insufficient_scope');
      return await this.options.store.complete(request.binding, lease, { status: 'active', material });
    } catch (error) {
      await this.finishFailure(request.binding, lease, error);
      throw error;
    }
  }
  async revoke(request: OAuthExistingRequest): Promise<OAuthConnectionMetadata> {
    const connection = await this.existing(request);
    // A local policy revocation may retain an upstream grant for explicit cleanup.
    if (connection.status === 'revoked' && !connection.material) return publicMetadata(connection);
    if (!connection.material) fail('connection_unavailable');
    const lease = await this.options.store.reserve(request.binding, this.provider, connection, 'revoke');
    try {
      if (this.provider === 'github') {
        await http(`${this.endpoints.revoke}/${encodeURIComponent(this.options.clientId)}/grant`, {
          method: 'DELETE', headers: {
            Authorization: `Basic ${Buffer.from(`${this.options.clientId}:${this.options.clientSecret}`).toString('base64')}`,
            Accept: 'application/vnd.github+json', 'Content-Type': 'application/json',
            'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'agent-vault-connector',
          }, body: JSON.stringify({ access_token: connection.material.accessToken }),
        }, this.synthetic, 204);
      } else {
        await http(this.endpoints.revoke, {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token: connection.material.refreshToken ?? connection.material.accessToken }),
        }, this.synthetic, 200);
      }
      return await this.options.store.complete(request.binding, lease, { status: 'revoked', clearMaterial: true });
    } catch (error) {
      await this.finishFailure(request.binding, lease, error);
      throw error;
    }
  }
  private async finishFailure(binding: OAuthBinding, lease: OAuthMaterialLease, error: unknown): Promise<void> {
    const code = error instanceof OAuthError ? error.code : 'provider_outcome_unknown';
    const status: OAuthStatus = ['reauthorization_required', 'insufficient_scope'].includes(code)
      ? 'reauthorization_required'
      : code === 'provider_configuration_error' || code === 'provider_rejected' ? 'error' : 'outcome_unknown';
    // A lock/CAS failure here intentionally leaves a durable blocking lease.
    await this.options.store.complete(binding, lease, { status });
  }
}
function publicMetadata(connection: OAuthConnection): OAuthConnectionMetadata {
  const { connectionId, provider, recordVersion, statusVersion, materialVersion, subject, status, scopes } = connection;
  return { connectionId, provider, recordVersion, statusVersion, materialVersion, subject, status, scopes: [...scopes] };
}
export function createProductionOAuthAdapter(options: OAuthOptions): OAuthAdapter {
  // Reject accidental endpoint overrides rather than silently ignoring them.
  const allowed = new Set(['provider', 'clientId', 'clientSecret', 'redirectUri', 'store', 'clock']);
  if (Object.keys(options).some(key => !allowed.has(key))) fail('unsupported_option');
  return new Adapter({ ...options }, OAUTH_PRODUCTION_REGISTRY[options.provider], false);
}
export interface SyntheticOAuthOptions extends OAuthOptions { endpoints: Endpoints }
/** Explicit synthetic-only factory. Every endpoint and callback must be literal IP loopback HTTP. */
export function createSyntheticOAuthAdapter(options: SyntheticOAuthOptions): OAuthAdapter {
  const endpoints = { ...options.endpoints };
  for (const endpoint of Object.values(endpoints)) checkedUrl(endpoint, true);
  if (Object.keys(endpoints).sort().join(',') !== 'authorize,identity,revoke,token') fail('invalid_endpoint');
  const { endpoints: ignored, ...adapterOptions } = options;
  return new Adapter(adapterOptions, Object.freeze(endpoints), true);
}
/** Useful to durable store implementations; a lease identifier is never a bearer grant. */
export function createOAuthLeaseId(): string { return randomUUID(); }
