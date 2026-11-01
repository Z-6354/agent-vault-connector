import { z } from 'zod';
import { MOCK_OPERATION, MOCK_ORIGIN, restrictedRequest, UpstreamAuthorizationError, type Destination } from './network.js';
import { VaultError, type Vault } from './vault.js';
import type { Authority, OperationDefinition, OperationInput, OperationResult, SavePayload } from './contracts.js';
import type { OAuthProvider } from './oauth.js';
import { normalizeOAuthScopes } from './oauth.js';

export const executionSchema = z.object({
  request_id: z.string().min(20).max(1024),
  connection_id: z.string().uuid(),
  operation_id: z.string().min(1).max(100),
  expected_record_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  args: z.object({}).strict(),
}).strict();
export const tokenSchema = z.string().min(16).max(512).regex(/^synthetic_[A-Za-z0-9_-]+$/);
export const savePayloadBase = z.object({
  mode: z.enum(['create', 'replace']), label: z.string().trim().min(1).max(80),
  service_id: z.string().min(1).max(100), credential_type: z.enum(['api_key', 'password', 'oauth', 'external_reference', 'delegation']),
  account_alias: z.string().trim().min(1).max(80), secret: z.string().max(65536),
  origin: z.string().url().max(2048), environment: z.literal('local'),
  granted_operations: z.array(z.string().min(1).max(100)).max(20),
  target_record_id: z.string().uuid().optional(), expected_record_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
}).strict();
export const savePayloadSchema = savePayloadBase.superRefine((value, ctx) => {
  if (value.mode === 'create' ? value.target_record_id !== undefined || value.expected_record_version !== undefined : value.target_record_id === undefined || value.expected_record_version === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid create/replace versions' });
  }
  if (new Set(value.granted_operations).size !== value.granted_operations.length) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Duplicate operations' });
});

export const OAUTH_EXECUTION_POLICY = Object.freeze({
  github: Object.freeze({ scopes: Object.freeze(['read:user']), operationId: 'github.current_user', origin: 'https://api.github.com' }),
  google: Object.freeze({ scopes: Object.freeze(['email', 'openid']), operationId: 'google.userinfo', origin: 'https://www.googleapis.com' }),
});
const requiredOAuthScopes = (service: string) => OAUTH_EXECUTION_POLICY[service as OAuthProvider].scopes;
const initialOAuthSchema = z.object({ schema: z.literal(1), provider: z.enum(['github', 'google']), approvedScopes: z.array(z.string()).min(1).max(20) }).strict();
const oauthEnvelopeSchema = initialOAuthSchema.extend({
  subject: z.string().optional(), status: z.enum(['active', 'reauthorization_required', 'revoked', 'outcome_unknown', 'error']).optional(),
  clientConfig: z.object({ clientId: z.string().min(1).max(256), version: z.number().int().positive(), context: z.string().min(1).max(16384) }).strict().optional(),
  material: z.object({ accessToken: z.string().min(1).max(16384).regex(/^[\x21-\x7e]+$/), refreshToken: z.string().optional(), tokenType: z.literal('Bearer'), accessExpiresAt: z.number().finite().optional(), refreshExpiresAt: z.number().finite().optional(), grantedScopes: z.array(z.string()).max(100) }).strict(),
}).strict();
const mockOutput = z.object({
  account: z.object({ id: z.string().max(256), name: z.string().max(1024) }),
  plan: z.string().max(256), notices: z.array(z.object({ message: z.string().max(2048) })).max(10),
});
const githubOutput = z.object({ id: z.number().int(), login: z.string().max(256), name: z.string().max(1024).nullable().optional() });
const googleOutput = z.object({ sub: z.string().max(256), name: z.string().max(1024).optional(), email: z.string().max(1024).optional(), email_verified: z.boolean().optional() });
interface RegisteredOperation extends OperationDefinition { description: string; destination: Readonly<Destination>; output: z.ZodTypeAny }
const registered = (id: string, service_id: string, origin: string, path: string, description: string, output: z.ZodTypeAny, mock = false): RegisteredOperation => Object.freeze({
  id, service_id, origin, semantics: 'read_only' as const, business_target: 'authenticated-account', description,
  destination: Object.freeze({ operationId: id, origin, method: 'GET' as const, path, mock }), output,
});
// Source-controlled production HTTPS destinations. The synthetic loopback exception is a separate entry.
const productionOperations = Object.freeze([
  registered(OAUTH_EXECUTION_POLICY.github.operationId, 'github', OAUTH_EXECUTION_POLICY.github.origin, '/user', 'Read the authenticated GitHub account profile.', githubOutput),
  registered(OAUTH_EXECUTION_POLICY.google.operationId, 'google', OAUTH_EXECUTION_POLICY.google.origin, '/oauth2/v3/userinfo', 'Read the authorized Google user profile.', googleOutput),
]);
const syntheticOperations = Object.freeze([
  registered(MOCK_OPERATION, 'synthetic-mock', MOCK_ORIGIN, '/v1/account/summary', 'Read the fixed local synthetic account summary.', mockOutput, true),
]);
const operations = Object.freeze([...productionOperations, ...syntheticOperations]);
export const operation = syntheticOperations[0]!.destination;
export const operationsMetadata = operations.map(({ id, service_id, origin, semantics, description }) => Object.freeze({ id, service_id, origin, semantics, description }));
export const servicesMetadata = Object.freeze([
  { service_id: 'synthetic-mock', origin: MOCK_ORIGIN, credential_types: ['api_key'], operations: [MOCK_OPERATION], synthetic: true },
  { service_id: 'github', origin: OAUTH_EXECUTION_POLICY.github.origin, credential_types: ['api_key', 'oauth'], operations: [OAUTH_EXECUTION_POLICY.github.operationId], synthetic: false },
  { service_id: 'google', origin: OAUTH_EXECUTION_POLICY.google.origin, credential_types: ['oauth'], operations: [OAUTH_EXECUTION_POLICY.google.operationId], synthetic: false },
  { service_id: 'synthetic-login', origin: 'http://127.0.0.1:43122', credential_types: ['password'], operations: ['browser_fill', 'login_submit'], synthetic: true },
  { service_id: 'external-reference', origin: '', credential_types: ['external_reference'], operations: [], synthetic: false },
]);

export function validateSavePayload(input: unknown): SavePayload {
  const parsed = savePayloadSchema.safeParse(input);
  if (!parsed.success) throw new Error('invalid_draft');
  const value = parsed.data;
  if (value.credential_type === 'external_reference') {
    const origin = new URL(value.origin);
    if (value.service_id !== 'external-reference' || origin.protocol !== 'https:' || origin.origin !== value.origin || origin.username || origin.password || value.secret !== '' || value.granted_operations.length) throw new Error('invalid_external_reference');
    return value;
  }
  const service = servicesMetadata.find(item => item.service_id === value.service_id);
  if (!service || value.origin !== service.origin || !service.credential_types.includes(value.credential_type) || !value.secret || value.granted_operations.some(id => !service.operations.includes(id))) throw new Error('unregistered_service_or_scope');
  if (value.credential_type === 'api_key' && !/^[\x21-\x7e]{1,16384}$/.test(value.secret)) throw new Error('invalid_api_token');
  if (service.synthetic && value.credential_type === 'api_key' && !tokenSchema.safeParse(value.secret).success) throw new Error('synthetic_token_required');
  if (value.credential_type === 'oauth') {
    const approved = initialOAuthSchema.safeParse(JSON.parse(value.secret));
    if (!approved.success || approved.data.provider !== value.service_id || approved.data.approvedScopes.length !== requiredOAuthScopes(value.service_id).length || !requiredOAuthScopes(value.service_id).every(scope => approved.data.approvedScopes.includes(scope))) throw new Error('invalid_oauth_approval');
  }
  return value;
}

export function redactSecrets(value: unknown, secrets: readonly string[]): unknown {
  const redact = (text: string) => {
    for (const secret of secrets) {
      if (!secret) continue;
      for (const variant of [secret, encodeURIComponent(secret), Buffer.from(secret).toString('base64')]) text = text.split(variant).join('[REDACTED]');
    }
    return text;
  };
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(item => redactSecrets(item, secrets));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [redact(key), redactSecrets(item, secrets)]));
  return value;
}

export interface ExecutionOptions {
  prepareOAuth?(auth: Authority, request: OperationInput): Promise<void>;
  /** Installed only by the separate explicit synthetic product factory. */
  requestOAuth?(provider: OAuthProvider, token: string, signal: AbortSignal): Promise<unknown>;
  clock?: () => number;
  syntheticOnly?: boolean;
}
export async function execute(vault: Vault, input: unknown, auth: Authority, options: ExecutionOptions = {}): Promise<OperationResult> {
  const parsed = executionSchema.safeParse(input);
  if (!parsed.success) throw new VaultError(400, 'invalid_operation');
  const request = parsed.data;
  const definition = operations.find(item => item.id === request.operation_id);
  if (!definition) throw new VaultError(400, 'unknown_operation');
  // Replays must not refresh credentials or contact an upstream provider.
  const replay = vault.replayOperation(auth, request);
  if (replay) return replay;
  if (options.syntheticOnly && !definition.destination.mock && (vault.get(request.connection_id).credential_type !== 'oauth' || !options.requestOAuth)) throw new VaultError(403, 'synthetic_external_execution_denied');
  if (vault.get(request.connection_id).credential_type === 'oauth' && options.prepareOAuth) await options.prepareOAuth(auth, request);
  const accepted = vault.beginOperation(auth, request, definition);
  if (accepted.replayed) return accepted.operation;
  let dispatched = false;
  const metadata = vault.get(request.connection_id), epoch = vault.epoch;
  try {
    const output = await vault.withToken(request.connection_id, async (secret, signal) => {
      signal.throwIfAborted();
      let token = secret;
      const secrets = [secret];
      if (metadata.credential_type === 'oauth') {
        const envelope = oauthEnvelopeSchema.parse(JSON.parse(secret));
        const required = requiredOAuthScopes(metadata.service_id);
        const approvedScopes = normalizeOAuthScopes(envelope.provider, envelope.approvedScopes);
        const grantedScopes = normalizeOAuthScopes(envelope.provider, envelope.material.grantedScopes);
        if (envelope.provider !== metadata.service_id || envelope.status !== 'active' || !required.every(scope => approvedScopes.includes(scope) && grantedScopes.includes(scope)) || grantedScopes.some(scope => !approvedScopes.includes(scope)) || envelope.material.accessExpiresAt !== undefined && envelope.material.accessExpiresAt <= (options.clock ?? Date.now)()) throw new Error('oauth_unavailable');
        token = envelope.material.accessToken;
        secrets.push(token, ...(envelope.material.refreshToken ? [envelope.material.refreshToken] : []));
      }
      vault.markDispatching(auth, request);
      dispatched = true;
      const raw = metadata.credential_type === 'oauth' && options.requestOAuth
        ? await options.requestOAuth(metadata.service_id as OAuthProvider, token, signal)
        : await restrictedRequest(definition.destination, token, signal);
      const allowed = definition.output.safeParse(raw);
      if (!allowed.success) throw new Error('upstream_response_denied');
      return redactSecrets(allowed.data, secrets);
    }, request.expected_record_version, request.operation_id);
    return vault.finishOperation(auth, request, 'succeeded', output);
  } catch (error) {
    if (metadata.credential_type === 'oauth' && error instanceof UpstreamAuthorizationError && vault.unlocked && vault.epoch === epoch) {
      vault.requireOAuthReauthorization(auth, request.connection_id, metadata, epoch);
    }
    // Dispatching is persisted before network I/O. Ambiguous failures are never retried.
    return vault.finishOperation(auth, request, dispatched ? 'outcome_unknown' : 'failed_before_dispatch', undefined, dispatched ? 'upstream_outcome_unknown' : 'dispatch_denied');
  }
}
