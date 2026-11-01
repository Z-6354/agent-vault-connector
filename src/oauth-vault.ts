import type { Authority, ConnectionStatus, Metadata } from './contracts.js';
import type { Vault } from './vault.js';
import {
  OAuthError, normalizeOAuthScopes, type OAuthBinding, type OAuthConnection, type OAuthConnectionMetadata,
  type OAuthMaterialStore, type OAuthProvider, type OAuthStatus, type OAuthTokenMaterial,
} from './oauth.js';

export interface OAuthClientBinding {
  clientId: string;
  version: number;
  /** Canonical provider/mode/registered-endpoint identity; never supplied by a request. */
  context: string;
}
export interface OAuthVaultEnvelope {
  schema: 1;
  provider: OAuthProvider;
  approvedScopes: string[];
  subject?: string;
  material?: OAuthTokenMaterial;
  clientConfig?: OAuthClientBinding;
  status?: OAuthStatus;
}
export interface VaultOAuthStoreOptions {
  vault: Pick<Vault, 'epoch' | 'requireUnlocked' | 'readMaterial' | 'reserveMaterial' | 'completeMaterial'>;
  /** Must validate a live authenticated management session, CSRF where applicable,
   * stable principal and current epoch. Never map a client-supplied principal. */
  resolveAuthority(binding: OAuthBinding): Authority | Promise<Authority>;
  /** Product adapters always bind issued material to their encrypted client generation. */
  clientConfig?: OAuthClientBinding;
  clock?: () => number;
}
function denied(code: string): never { throw new OAuthError(code); }
function envelope(secret: string, metadata: Metadata): OAuthVaultEnvelope {
  let value: OAuthVaultEnvelope;
  try { value = JSON.parse(secret) as OAuthVaultEnvelope; } catch { return denied('invalid_oauth_envelope'); }
  if (!value || value.schema !== 1 || !['github', 'google'].includes(value.provider) || value.provider !== metadata.service_id || metadata.credential_type !== 'oauth' || !Array.isArray(value.approvedScopes) || !value.approvedScopes.length || value.approvedScopes.some(s => typeof s !== 'string' || !s.length || /[\s,]/u.test(s))) denied('invalid_oauth_envelope');
  if (value.material && (typeof value.material.accessToken !== 'string' || value.material.tokenType !== 'Bearer' || !Array.isArray(value.material.grantedScopes))) denied('invalid_oauth_envelope');
  if (value.clientConfig !== undefined && (!value.clientConfig || typeof value.clientConfig.clientId !== 'string' || !Number.isSafeInteger(value.clientConfig.version) || value.clientConfig.version < 1 || typeof value.clientConfig.context !== 'string' || !value.clientConfig.context)) denied('invalid_oauth_envelope');
  return value;
}
function status(value: ConnectionStatus, stored?: OAuthStatus): OAuthStatus {
  if (value === 'active') return 'active';
  // Core revoked is local policy; only the encrypted adapter result confirms upstream revocation.
  if (value === 'revoked' && stored === 'revoked') return 'revoked';
  if (stored === 'outcome_unknown') return 'outcome_unknown';
  return 'reauthorization_required';
}
function metadata(row: Metadata, value: OAuthVaultEnvelope): OAuthConnectionMetadata {
  return {
    connectionId: row.id, provider: value.provider, recordVersion: row.record_version,
    statusVersion: row.status_version, materialVersion: row.material_version,
    subject: value.subject, status: status(row.status, value.status), scopes: normalizeOAuthScopes(value.provider, value.approvedScopes),
  };
}
/** Trusted-only bridge: decrypted token material never crosses the management/MCP response boundary. */
export function createVaultOAuthStore(options: VaultOAuthStoreOptions): OAuthMaterialStore {
  const vault = options.vault;
  const clientConfig = options.clientConfig ? { ...options.clientConfig } : undefined;
  const matchesClient = (value: OAuthVaultEnvelope) => !clientConfig || value.clientConfig?.clientId === clientConfig.clientId && value.clientConfig.version === clientConfig.version && value.clientConfig.context === clientConfig.context;
  async function auth(binding: OAuthBinding): Promise<Authority> {
    const authority = await options.resolveAuthority(binding);
    if (authority.owner_id !== binding.ownerId || authority.principal_id !== binding.principalId || authority.session_id !== binding.sessionId || vault.epoch !== binding.securityEpoch) denied('oauth_authority_denied');
    vault.requireUnlocked();
    return authority;
  }
  return {
    async assertAuthorized(binding) { await auth(binding); },
    async read(binding, id): Promise<OAuthConnection | undefined> {
      const authority = await auth(binding);
      const record = vault.readMaterial(authority, id);
      const value = envelope(record.secret, record.metadata);
      const publicValue = metadata(record.metadata, value);
      // Keep old encrypted material for reconciliation, but never carry it into a
      // different client generation (including Google's omitted-refresh response).
      if (value.material && !matchesClient(value)) return { ...publicValue, status: 'reauthorization_required' };
      return { ...publicValue, ...(value.material ? { material: structuredClone(value.material) } : {}) };
    },
    async reserve(binding, provider, expected, action) {
      const authority = await auth(binding);
      const record = vault.readMaterial(authority, expected.connectionId);
      const value = envelope(record.secret, record.metadata);
      if (value.provider !== provider) denied('oauth_provider_mismatch');
      if (action !== 'authorize' && !matchesClient(value)) denied('oauth_client_changed');
      const lease = vault.reserveMaterial(authority, expected.connectionId, {
        record_version: expected.recordVersion, status_version: expected.statusVersion, material_version: expected.materialVersion,
      }, action);
      if (lease.epoch !== binding.securityEpoch) denied('oauth_authority_denied');
      return { leaseId: lease.lease_id, expected: { ...expected }, provider, action };
    },
    async complete(binding, lease, change) {
      const authority = await auth(binding);
      const record = vault.readMaterial(authority, lease.expected.connectionId);
      const value = envelope(record.secret, record.metadata);
      if (value.provider !== lease.provider) denied('oauth_provider_mismatch');
      if (lease.action !== 'authorize' && !matchesClient(value)) denied('oauth_client_changed');
      if (record.metadata.record_version !== lease.expected.recordVersion || record.metadata.status_version !== lease.expected.statusVersion || record.metadata.material_version !== lease.expected.materialVersion) denied('oauth_version_conflict');
      const approvedScopes = normalizeOAuthScopes(value.provider, value.approvedScopes);
      if (change.scopes && normalizeOAuthScopes(value.provider, change.scopes).some(scope => !approvedScopes.includes(scope))) denied('scope_not_approved');
      if (change.material !== undefined) {
        const grantedScopes = normalizeOAuthScopes(value.provider, change.material.grantedScopes);
        if (grantedScopes.some(scope => !approvedScopes.includes(scope))) denied('scope_not_approved');
        if (change.scopes && !normalizeOAuthScopes(value.provider, change.scopes).every(scope => grantedScopes.includes(scope))) denied('insufficient_scope');
      }
      if (change.subject !== undefined && value.subject !== undefined && change.subject !== value.subject) denied('oauth_subject_changed');
      const updated: OAuthVaultEnvelope = { ...value, status: change.status };
      if (change.material !== undefined) {
        updated.material = structuredClone(change.material);
        if (clientConfig) updated.clientConfig = { ...clientConfig };
      }
      if (change.subject !== undefined) updated.subject = change.subject;
      if (change.clearMaterial) delete updated.material;
      const coreStatus: ConnectionStatus = change.status === 'active' || change.status === 'revoked' ? change.status : 'needs_user_action';
      const result = vault.completeMaterial(authority, lease.expected.connectionId, lease.leaseId, {
        secret: JSON.stringify(updated), status: coreStatus,
        last_verified_at: new Date((options.clock ?? Date.now)()).toISOString(),
        expected_epoch: binding.securityEpoch, outcome_unknown: change.status === 'outcome_unknown',
      });
      return metadata(result, updated);
    },
  };
}
