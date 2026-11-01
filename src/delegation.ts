import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import { z } from 'zod';
import type { Authority } from './contracts.js';

const identifier = z.string().min(1).max(256);
const names = z.array(identifier).min(1).max(64);
const grantSchema = z.object({
  id: identifier, owner_id: z.literal('local'), center_principal_id: identifier,
  upstream_principal_id: identifier, upstream_account: identifier, host_id: identifier,
  authorization_source: identifier, verification_evidence: identifier, audience: identifier,
  resources: names, scopes: names, operations: names, endpoints: names,
  expires_at: z.number().int().positive(), revoked: z.boolean(),
}).strict();
export type DelegationGrant = z.infer<typeof grantSchema>;
export interface DelegationConnection {
  id: string; owner_id: 'local'; credential_type: 'external_reference' | 'delegation';
  delegation_id?: string;
}
export interface DelegatedOperation {
  id: string; audience: string; resource: string; scopes: string[]; endpoint: string;
}
export interface DelegationPolicy {
  operations: string[]; audiences: string[]; resources: string[]; scopes: string[]; endpoints: string[];
}
export interface DelegationCall {
  grant: DelegationGrant; operation: DelegatedOperation;
  center_principal_id: string; requesting_principal_id: string;
}
const verificationSchema = z.object({
  state: z.enum(['active', 'revoked', 'expired', 'unknown']),
  grant: grantSchema, verified_at: z.number().int().nonnegative(),
}).strict();
export type DelegationVerification = z.infer<typeof verificationSchema>;
// Adapters must return only reviewed, operation-specific output. No token or shell interface exists.
const resultSchema = z.object({
  upstream_principal_id: identifier, upstream_account: identifier,
  operation_id: identifier, resource: identifier, outcome: z.literal('succeeded'),
}).strict();
export type DelegatedResult = z.infer<typeof resultSchema>;
export interface TrustedDelegationHost {
  readonly host_id: string;
  verify(call: DelegationCall, signal: AbortSignal): Promise<DelegationVerification>;
  execute(call: DelegationCall, signal: AbortSignal): Promise<DelegatedResult>;
}
export class DelegationError extends Error {
  constructor(readonly code: string) { super(code); }
}
const deny = (code: string): never => { throw new DelegationError(code); };
export function externalReferenceStatus(lastVerifiedAt: number | null = null) {
  return { can_execute: false as const, status: 'unknown' as const, last_verified_at: lastVerifiedAt,
    error: 'external_execution_unsupported', needs_user_action: 'Use the original platform connection.' };
}

/** Trusted core only: connection/grant/operation come from its registry, never a model tool payload.
 * The core owns durable request registration and A3 dispatch/outcome_unknown handling around execute().
 * A successful host verification is not an execution authorization by itself.
 */
export class DelegationExecutor {
  constructor(private readonly options: {
    host: TrustedDelegationHost;
    centerPrincipalId: string;
    policy: (authority: Authority, connectionId: string) => DelegationPolicy;
    security: () => { unlocked: boolean; epoch: number };
    clock?: () => number; timeoutMs?: number;
  }) {}

  async execute(authority: Authority, connection: DelegationConnection, savedGrant: DelegationGrant | undefined,
    operation: DelegatedOperation): Promise<DelegatedResult & { requesting_principal_id: string; center_principal_id: string }> {
    if (connection.credential_type === 'external_reference') deny('external_execution_unsupported');
    const initial = this.options.security();
    if (!initial.unlocked) deny('vault_locked');
    if (!authority.principal_id || !authority.client_id || connection.owner_id !== authority.owner_id) deny('delegation_denied');
    const parsed = grantSchema.safeParse(savedGrant);
    if (!parsed.success) throw new DelegationError('external_execution_unsupported');
    const grant = parsed.data;
    const op = structuredClone(operation);
    const clock = this.options.clock ?? Date.now;
    const guard = () => {
      const security = this.options.security();
      if (!security.unlocked || security.epoch !== initial.epoch) deny('vault_locked');
      if (grant.revoked || grant.expires_at <= clock()) deny('delegation_inactive');
      if (connection.delegation_id !== grant.id || grant.owner_id !== authority.owner_id ||
          grant.host_id !== this.options.host.host_id || grant.center_principal_id !== this.options.centerPrincipalId) deny('delegation_identity_mismatch');
      const policy = this.options.policy(authority, connection.id);
      for (const [value, local, upstream] of [
        [op.id, policy.operations, grant.operations], [op.audience, policy.audiences, [grant.audience]],
        [op.resource, policy.resources, grant.resources], [op.endpoint, policy.endpoints, grant.endpoints],
        ...op.scopes.map(scope => [scope, policy.scopes, grant.scopes] as const),
      ] as const) {
        if (!local.includes(value) || !upstream.includes(value)) deny('delegation_scope_denied');
      }
    };
    guard();
    const call: DelegationCall = { grant, operation: op, center_principal_id: this.options.centerPrincipalId,
      requesting_principal_id: authority.principal_id };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 2_500);
    const invoke = async <T>(callback: () => Promise<T>): Promise<T> => {
      let onAbort: (() => void) | undefined;
      try {
        return await Promise.race([callback(), new Promise<never>((_, reject) => {
          onAbort = () => reject(new DelegationError('delegation_unreachable'));
          controller.signal.addEventListener('abort', onAbort, { once: true });
          if (controller.signal.aborted) onAbort();
        })]);
      } finally { if (onAbort) controller.signal.removeEventListener('abort', onAbort); }
    };
    try {
      const verified = verificationSchema.parse(await invoke(() => this.options.host.verify(structuredClone(call), controller.signal)));
      if (verified.state !== 'active' || verified.verified_at > clock() || clock() - verified.verified_at > 5_000) deny('delegation_inactive');
      // Every bound identity, authorization source and capability must match our saved grant.
      if (JSON.stringify(verified.grant) !== JSON.stringify(grant)) deny('delegation_identity_mismatch');
      guard();
      const result = resultSchema.parse(await invoke(() => this.options.host.execute(structuredClone(call), controller.signal)));
      guard();
      if (result.upstream_principal_id !== grant.upstream_principal_id || result.upstream_account !== grant.upstream_account ||
          result.operation_id !== op.id || result.resource !== op.resource) deny('delegation_identity_mismatch');
      return { ...result, requesting_principal_id: authority.principal_id, center_principal_id: this.options.centerPrincipalId };
    } catch (error) {
      if (error instanceof DelegationError) throw error;
      // Never relay host errors, HTTP bodies, credentials, or exception messages.
      throw new DelegationError('delegation_unreachable');
    } finally { clearTimeout(timer); controller.abort(); }
  }
}

/** Synthetic fixture protocol only; this is not any real platform's delegation API.
 * A dedicated test key authenticates the center and host. No upstream credential is exported.
 * Exact numeric loopback, fixed routes, no redirects, DNS, arbitrary headers, scripts or shell.
 */
export class SyntheticLoopbackDelegationHost implements TrustedDelegationHost {
  private readonly key: Buffer;
  private readonly origin: URL;
  private closed = false;
  constructor(readonly host_id: string, origin: string, fixtureKey: Buffer) {
    this.origin = new URL(origin);
    if (this.origin.protocol !== 'http:' || this.origin.hostname !== '127.0.0.1' ||
        !this.origin.port || this.origin.origin !== origin || fixtureKey.length < 32) throw new DelegationError('invalid_synthetic_host');
    this.key = Buffer.from(fixtureKey);
  }
  close() { this.closed = true; this.key.fill(0); }
  verify(call: DelegationCall, signal: AbortSignal): Promise<DelegationVerification> {
    return this.request('/synthetic/verify', call, signal).then(value => verificationSchema.parse(value));
  }
  execute(call: DelegationCall, signal: AbortSignal): Promise<DelegatedResult> {
    return this.request('/synthetic/execute', call, signal).then(value => resultSchema.parse(value));
  }
  private request(route: string, call: DelegationCall, signal: AbortSignal): Promise<unknown> {
    if (this.closed) return Promise.reject(new DelegationError('delegation_unreachable'));
    const nonce = randomBytes(24).toString('hex');
    const body = JSON.stringify(call);
    const signature = createHmac('sha256', this.key).update(`request\n${route}\n${nonce}\n${body}`).digest('hex');
    return new Promise((resolve, reject) => {
      const request = http.request(new URL(route, this.origin), { method: 'POST', signal,
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body),
          'x-synthetic-nonce': nonce, 'x-synthetic-signature': signature }, maxHeaderSize: 8_192 }, response => {
        let size = 0;
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 16_384) response.destroy(); else chunks.push(chunk); });
        response.on('error', () => reject(new DelegationError('delegation_unreachable')));
        response.on('end', () => {
          try {
            if (response.statusCode !== 200 || response.headers['content-type'] !== 'application/json') deny('delegation_unreachable');
            const text = Buffer.concat(chunks).toString('utf8');
            const expected = createHmac('sha256', this.key).update(`response\n${route}\n${nonce}\n${text}`).digest();
            const received = Buffer.from(String(response.headers['x-synthetic-signature'] ?? ''), 'hex');
            if (received.length !== expected.length || !timingSafeEqual(expected, received)) deny('delegation_identity_mismatch');
            resolve(JSON.parse(text));
          } catch { reject(new DelegationError('delegation_unreachable')); }
        });
      });
      request.on('error', () => reject(new DelegationError('delegation_unreachable')));
      request.end(body);
    });
  }
}
