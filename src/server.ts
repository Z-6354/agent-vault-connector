import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import { z } from 'zod';
import { Vault, VaultError, type VaultOptions } from './vault.js';
import { execute, operationsMetadata, servicesMetadata, savePayloadSchema } from './registry.js';
import type { Authority, DraftCard, Metadata } from './contracts.js';
import { createBrowserProduct } from './browser-product.js';
import { BrowserHostError } from './browser.js';
import { createOAuthProduct, createSyntheticOAuthProduct } from './oauth-product.js';
import { OAuthError, type OAuthBinding, type OAuthProvider } from './oauth.js';
import { assertProductMode, type ProductConfig } from './product-config.js';

interface Session { id: string; csrf: string; expires: number; authenticated: boolean; epoch: number }
interface PendingConfirmation { session_id: string; card: DraftCard; request_id: string; result?: Metadata }
export interface ServerOptions { clock?: () => number; vaultOptions?: VaultOptions; productConfig?: ProductConfig }
const SESSION_MS = 15 * 60_000;
const random = () => randomBytes(32).toString('hex');
const equal = (a: string, b: string) => Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const idSchema = z.string().uuid();
const versionSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const passphraseSchema = z.object({ passphrase: z.string().min(1).max(1024) }).strict();
const emptySchema = z.object({}).strict();
function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new VaultError(400, 'invalid_request');
  return result.data;
}

export async function createServer(directory: string, port: number, options: ServerOptions = {}) {
  assertProductMode(directory, options.productConfig);
  const clock = options.clock ?? Date.now;
  const vault = new Vault(directory, { ...options.vaultOptions, clock: options.vaultOptions?.clock ?? clock });
  const app = Fastify({ logger: false, bodyLimit: 96 * 1024, requestTimeout: 5000, connectionTimeout: 5000, trustProxy: false });
  await app.register(cookie);
  const sessions = new Map<string, Session>();
  const pending = new Map<string, PendingConfirmation>();
  const counters = new Map<string, { count: number; until: number }>();
  let adminId: string | undefined;
  let authenticating = false;
  const origin = () => {
    const address = app.server.address();
    return `http://127.0.0.1:${typeof address === 'object' && address ? address.port : port}`;
  };
  const take = (key: string, max: number, interval: number) => {
    const now = clock();
    let entry = counters.get(key);
    if (!entry || entry.until <= now) { entry = { count: 0, until: now + interval }; counters.set(key, entry); }
    if (++entry.count > max) throw new VaultError(429, 'rate_limited');
  };
  let oauth: ReturnType<typeof createOAuthProduct> | undefined;
  const browser = await createBrowserProduct({ vault, config: options.productConfig?.browser, now: clock });
  const globalLogout = () => { vault.lock(); browser.invalidatePending(); oauth?.invalidatePending(); sessions.clear(); pending.clear(); adminId = undefined; };
  const sweepSessions = () => {
    const active = adminId ? sessions.get(adminId) : undefined;
    if (adminId && (!active || active.expires <= clock() || active.epoch !== vault.epoch)) globalLogout();
    for (const [id, session] of sessions) if (session.expires <= clock() || session.epoch !== vault.epoch) sessions.delete(id);
    for (const [id, draft] of pending) if (draft.card.expires_at <= clock()) pending.delete(id);
  };
  const sessionFor = (request: FastifyRequest) => {
    sweepSessions();
    const session = request.cookies.vault_session ? sessions.get(request.cookies.vault_session) : undefined;
    if (!session) throw new VaultError(401, 'session_required');
    return session;
  };
  const issueSession = (reply: FastifyReply, authenticated: boolean) => {
    sweepSessions();
    if (sessions.size >= 128) throw new VaultError(429, 'too_many_sessions');
    const id = random();
    const session: Session = { id, csrf: random(), expires: clock() + SESSION_MS, authenticated, epoch: vault.epoch };
    sessions.set(id, session);
    if (authenticated) adminId = id;
    // This server binds exact loopback HTTP only. HTTPS deployments must add Secure at their authenticated transport boundary.
    reply.setCookie('vault_session', id, { path: '/', httpOnly: true, sameSite: 'strict', maxAge: SESSION_MS / 1000 });
    return session;
  };
  const authority = (session: Session): Authority => ({ owner_id: 'local', principal_id: 'admin', client_id: 'management', session_id: session.id });
  const management = (request: FastifyRequest, state: 'anonymous' | 'authenticated' | 'unlocked' = 'unlocked') => {
    const session = sessionFor(request);
    if (request.method !== 'GET') {
      const csrf = request.headers['x-csrf-token'];
      if (request.headers.origin !== origin() || typeof csrf !== 'string' || !equal(csrf, session.csrf)) throw new VaultError(403, 'csrf_denied');
      if (!/^application\/json(?:\s*;|$)/i.test(String(request.headers['content-type'] ?? ''))) throw new VaultError(415, 'json_required');
    }
    if (state !== 'anonymous' && (!session.authenticated || adminId !== session.id)) throw new VaultError(401, 'login_required');
    if (state === 'unlocked') vault.requireUnlocked();
    // Execution calls never pass here, so they cannot keep an administrator logged in.
    if (session.authenticated) session.expires = clock() + SESSION_MS;
    return session;
  };
  const executionAuth = (request: FastifyRequest): Authority => {
    if (request.headers.origin || request.headers.cookie) throw new VaultError(403, 'execution_connection_denied');
    const auth = request.headers.authorization;
    if (typeof auth !== 'string' || !/^Bearer [a-f0-9]{64}$/.test(auth) || !vault.executionAuthorized(auth.slice(7))) throw new VaultError(401, 'execution_authorization_required');
    if (!vault.unlocked) throw new VaultError(423, 'vault_locked');
    take('execution', 120, 60_000);
    return { owner_id: 'local', principal_id: 'execution:local', client_id: 'execution' };
  };
  const binding = (auth: Authority): OAuthBinding => {
    sweepSessions();
    const session = adminId ? sessions.get(adminId) : undefined;
    if (!session?.authenticated || !vault.unlocked) throw new VaultError(423, 'vault_locked');
    return { ownerId: auth.owner_id, principalId: auth.principal_id, sessionId: session.id, securityEpoch: vault.epoch };
  };
  const oauthOptions = {
    vault, clock, redirectUri: (provider: OAuthProvider) => `${origin()}/management/oauth/callback/${provider}`,
    resolveBinding: (value: OAuthBinding): Authority => {
      sweepSessions();
      const session = sessions.get(value.sessionId);
      if (!session?.authenticated || adminId !== session.id || session.expires <= clock() || session.epoch !== vault.epoch
        || value.securityEpoch !== vault.epoch || value.ownerId !== 'local' || !['admin', 'execution:local'].includes(value.principalId)) throw new OAuthError('oauth_authority_denied');
      vault.requireUnlocked();
      return { owner_id: 'local', principal_id: value.principalId, client_id: value.principalId === 'admin' ? 'management' : 'execution', session_id: session.id };
    },
  };
  oauth = options.productConfig?.mode === 'synthetic'
    ? createSyntheticOAuthProduct({ ...oauthOptions, providers: options.productConfig.providers })
    : createOAuthProduct(oauthOptions);
  const viewSession = (session: Session) => ({ csrf: session.csrf, authenticated: session.authenticated, unlocked: session.authenticated && vault.unlocked, state: session.authenticated ? (vault.unlocked ? 'S2' : 'S1') : 'S0', security_epoch: vault.epoch });
  const executionPaths = new Set(['/execution/connections', '/execution/operations', '/execution/prepare-request', '/execution/connection-status', '/execution/operation-status', '/execution/execute',
    '/execution/browser/sites', '/execution/browser/session', '/execution/browser/session-status', '/execution/browser/request-approval', '/execution/browser/approval-status', '/execution/browser/fill', '/execution/browser/submit']);
  const callbackPath = (request: FastifyRequest) => /^\/management\/oauth\/callback\/(github|google)(?:\?|$)/.test(request.url);
  app.addHook('onRequest', async (request, reply) => {
    sweepSessions();
    reply.headers({
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
      'cross-origin-resource-policy': 'same-origin', 'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    });
    let hosts = 0;
    for (let i = 0; i < request.raw.rawHeaders.length; i += 2) if (request.raw.rawHeaders[i]?.toLowerCase() === 'host') hosts++;
    if (hosts !== 1 || request.headers.host !== new URL(origin()).host) throw new VaultError(403, 'host_denied');
    if (request.headers.origin !== undefined && request.headers.origin !== origin()) throw new VaultError(403, 'origin_denied');
    const callbackNavigation = callbackPath(request) && request.method === 'GET' && request.headers['sec-fetch-mode'] === 'navigate' && request.headers['sec-fetch-dest'] === 'document';
    if (request.headers['sec-fetch-site'] === 'cross-site' && !callbackNavigation) throw new VaultError(403, 'cross_site_denied');
    if (request.headers.authorization !== undefined && !executionPaths.has(request.url)) throw new VaultError(403, 'execution_credential_cannot_manage');
    take('http', 600, 60_000);
  });
  app.addHook('onSend', async (request, reply, payload) => {
    // Keep the browser cookie on the same idle schedule as the server-side admin session.
    // Rotating transitions already issue a new cookie and must not be overwritten.
    if (request.url.startsWith('/management/') && !reply.hasHeader('set-cookie')) {
      const session = request.cookies.vault_session ? sessions.get(request.cookies.vault_session) : undefined;
      if (session?.authenticated && adminId === session.id && session.epoch === vault.epoch && session.expires > clock()) reply.setCookie('vault_session', session.id, { path: '/', httpOnly: true, sameSite: 'strict', maxAge: Math.max(1, Math.ceil((session.expires - clock()) / 1000)) });
    }
    return payload;
  });
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof VaultError) return reply.code(error.status).send({ error: error.message });
    if (error instanceof BrowserHostError) return reply.code(error.code === 'vault_locked' ? 423 : error.code === 'unsupported' ? 409 : 403).send({ error: error.code });
    if (error instanceof OAuthError) return reply.code(409).send({ error: /^[a-z][a-z0-9_]{0,79}$/.test(error.code) ? error.code : 'oauth_failed' });
    const statusCode = error instanceof Error && 'statusCode' in error ? error.statusCode : undefined;
    const status = typeof statusCode === 'number' && Number.isInteger(statusCode) && statusCode >= 400 && statusCode < 500 ? statusCode : 500;
    return reply.code(status).send({ error: status === 500 ? 'request_failed' : 'invalid_request' });
  });
  app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: 'not_found' }));
  app.get('/', async (_request, reply) => reply.type('text/html; charset=utf-8').send(fs.readFileSync(new URL('../public/index.html', import.meta.url))));
  app.get('/app.js', async (_request, reply) => reply.type('text/javascript; charset=utf-8').send(fs.readFileSync(new URL('../public/app.js', import.meta.url))));
  app.get('/style.css', async (_request, reply) => reply.type('text/css; charset=utf-8').send(fs.readFileSync(new URL('../public/style.css', import.meta.url))));
  app.get('/management/session', async (request, reply) => {
    const existing = request.cookies.vault_session ? sessions.get(request.cookies.vault_session) : undefined;
    const session = existing ?? issueSession(reply, false);
    if (session.authenticated) session.expires = clock() + SESSION_MS;
    return viewSession(session);
  });
  app.post('/management/login', async (request, reply) => {
    management(request, 'anonymous');
    const { passphrase } = parse(passphraseSchema, request.body);
    take('login', 10, 60_000);
    if (authenticating) throw new VaultError(429, 'authentication_busy');
    authenticating = true;
    try {
      await vault.authenticate(passphrase);
      // A successful new login replaces the sole admin session and globally locks an existing unlocked vault.
      globalLogout();
      return viewSession(issueSession(reply, true));
    } finally { authenticating = false; }
  });
  app.post('/management/unlock', async (request, reply) => {
    const session = management(request, 'authenticated');
    const { passphrase } = parse(passphraseSchema, request.body);
    if (vault.unlocked) throw new VaultError(409, 'already_unlocked');
    take('unlock', 10, 60_000);
    await vault.unlock(passphrase);
    if (adminId !== session.id || session.epoch !== vault.epoch || session.expires <= clock()) {
      globalLogout();
      throw new VaultError(401, 'session_changed');
    }
    sessions.clear(); pending.clear(); adminId = undefined;
    return viewSession(issueSession(reply, true));
  });
  app.post('/management/lock', async (request, reply) => {
    management(request, 'authenticated'); parse(emptySchema, request.body);
    globalLogout();
    return viewSession(issueSession(reply, true));
  });
  app.post('/management/logout', async (request, reply) => {
    management(request, 'authenticated'); parse(emptySchema, request.body);
    globalLogout(); reply.clearCookie('vault_session', { path: '/' });
    return { state: 'S0', authenticated: false, unlocked: false };
  });
  app.get('/management/connections', async request => {
    const session = management(request);
    return { connections: vault.list(), operations: operationsMetadata, services: servicesMetadata, browser: { supported: options.productConfig?.browser?.enabled === true } };
  });
  app.post('/management/save-result', async request => {
    const session = management(request);
    const { request_id } = parse(z.object({ request_id: z.string().min(20).max(1024) }).strict(), request.body);
    return { connection: vault.getSaveResult(authority(session), request_id) };
  });
  app.post('/management/drafts', async (request, reply) => {
    const session = management(request);
    const payload = parse(savePayloadSchema, request.body);
    const draft = vault.createDraft(authority(session), payload);
    const request_id = vault.prepareRequest(authority(session), 'save_connection');
    pending.set(draft.draft_id, { session_id: session.id, card: draft, request_id });
    reply.code(201);
    return { draft, request_id };
  });
  app.post<{ Params: { id: string } }>('/management/drafts/:id/confirm', async request => {
    const session = management(request);
    const id = parse(idSchema, request.params.id);
    const body = parse(z.object({ draft_version: versionSchema, request_id: z.string().min(20).max(1024) }).strict(), request.body);
    const confirmation = pending.get(id);
    if (!confirmation || confirmation.session_id !== session.id || confirmation.card.draft_version !== body.draft_version || confirmation.request_id !== body.request_id) throw new VaultError(403, 'confirmation_denied');
    if (confirmation.result) return { connection: confirmation.result };
    const auth = authority(session);
    const payload = vault.draftPayload(auth, id);
    const approval = vault.approveDraft(auth, id, body.draft_version);
    const connection = vault.saveApproved(auth, { request_id: body.request_id, draft_id: id, draft_version: body.draft_version, approval_token: approval.approval_token, payload });
    confirmation.result = connection;
    return { connection };
  });
  app.delete<{ Params: { id: string } }>('/management/drafts/:id', async request => {
    const session = management(request); parse(emptySchema, request.body);
    const id = parse(idSchema, request.params.id);
    const draft = pending.get(id);
    if (!draft || draft.session_id !== session.id) throw new VaultError(404, 'draft_not_found');
    vault.cancelDraft(authority(session), id);
    pending.delete(id);
    return { ok: true };
  });
  app.delete<{ Params: { id: string } }>('/management/connections/:id', async request => {
    const session = management(request);
    const body = parse(z.object({ expected_record_version: versionSchema }).strict(), request.body);
    vault.delete(authority(session), parse(idSchema, request.params.id), body.expected_record_version);
    return { ok: true, local_deleted: true, upstream_revoked: false, retained_comparison: 'up_to_7_days' };
  });
  app.post<{ Params: { id: string } }>('/management/connections/:id/reconcile-material', async request => {
    const session = management(request);
    const body = parse(z.object({ expected_record_version: versionSchema, expected_status_version: versionSchema, expected_material_version: versionSchema, evidence_note: z.string().trim().min(1).max(500), abandon_old_material: z.literal(true) }).strict(), request.body);
    return { connection: vault.reconcileMaterial(authority(session), parse(idSchema, request.params.id), body) };
  });
  app.post<{ Params: { id: string } }>('/management/connections/:id/purge-retained', async request => {
    const session = management(request); parse(emptySchema, request.body);
    const id = parse(idSchema, request.params.id);
    vault.purgeRecordComparisons(authority(session), id);
    for (const [draftId, confirmation] of pending) if (confirmation.result?.id === id) pending.delete(draftId);
    return { ok: true, result: 'comparison_copies_purged', replay: 'result_unavailable', backup_copies: 'not_removed' };
  });
  app.patch<{ Params: { id: string } }>('/management/connections/:id/status', async request => {
    const session = management(request);
    const body = parse(z.object({ status: z.enum(['active', 'paused', 'revoked']), expected_status_version: versionSchema }).strict(), request.body);
    return { connection: vault.setStatus(authority(session), parse(idSchema, request.params.id), body.status, body.expected_status_version) };
  });
  app.get('/management/audit', async request => {
    const session = management(request);
    return { events: vault.listAudit(authority(session), 100) };
  });
  app.get('/management/operations', async request => {
    const session = management(request);
    return { operations: vault.listOperationHistory(authority(session)) };
  });
  app.post('/management/operations/reconcile', async request => {
    const session = management(request);
    const body = parse(z.object({
      request_id: z.string().min(20).max(1024), operation_name: z.string().min(1).max(100), principal_id: z.string().min(1).max(160),
      expected_operation_status_version: versionSchema, resolution: z.enum(['confirmed_succeeded', 'confirmed_failed', 'authorize_new_attempt']),
      evidence_note: z.string().trim().min(1).max(500), accept_duplicate_risk: z.boolean().optional(),
    }).strict(), request.body);
    return { operation: vault.reconcileOperation(authority(session), body) };
  });
  app.get('/management/browser/pending', async request => ({ pending: await browser.management.pending(authority(management(request))) }));
  app.post<{ Params: { id: string } }>('/management/browser/approvals/:id', async request => {
    const auth = authority(management(request)); parse(emptySchema, request.body);
    return { approval: await browser.management.approve(auth, parse(idSchema, request.params.id)) };
  });
  app.get('/management/oauth/providers', async request => ({ providers: await oauth!.providers(binding(authority(management(request)))) }));
  app.post('/management/oauth/client', async request => {
    const auth = binding(authority(management(request)));
    const body = parse(z.object({ provider: z.enum(['github', 'google']), clientId: z.string().min(1).max(256), clientSecret: z.string().min(1).max(16384), expectedVersion: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER - 1) }).strict(), request.body);
    return { client: await oauth!.configureClient(auth, body) };
  });
  app.post('/management/oauth/authorize', async request => {
    const auth = binding(authority(management(request)));
    const body = parse(z.object({ connectionId: idSchema, expectedRecordVersion: versionSchema, offline: z.boolean().optional(), consent: z.boolean().optional() }).strict(), request.body);
    return oauth!.begin(auth, body);
  });
  app.post('/management/oauth/revoke', async request => {
    const auth = binding(authority(management(request)));
    const body = parse(z.object({ connectionId: idSchema, expectedRecordVersion: versionSchema }).strict(), request.body);
    return { connection: await oauth!.revoke(auth, body) };
  });
  // Cross-site navigation loads only a static relay. SameSite=Strict cookies are used
  // by its subsequent same-origin JSON POST, which consumes the bound state + CSRF.
  app.get<{ Params: { provider: string } }>('/management/oauth/callback/:provider', async (request, reply) => {
    parse(z.enum(['github', 'google']), request.params.provider);
    return reply.type('text/html; charset=utf-8').send('<!doctype html><html lang="en"><meta charset="utf-8"><title>OAuth return</title><script defer src="/oauth-callback.js"></script><body><p id="oauth-result" role="status">Completing authorization with your management session…</p><a href="/">Return to management</a></body></html>');
  });
  app.get('/oauth-callback.js', async (_request, reply) => reply.type('text/javascript; charset=utf-8').send(fs.readFileSync(new URL('../public/oauth-callback.js', import.meta.url))));
  app.post<{ Params: { provider: string } }>('/management/oauth/callback/:provider', async request => {
    const auth = binding(authority(management(request)));
    const provider = parse(z.enum(['github', 'google']), request.params.provider);
    const body = parse(z.object({ callbackUrl: z.string().url().max(8192) }).strict(), request.body);
    return { connection: await oauth!.callback(auth, { provider, callbackUrl: body.callbackUrl }) };
  });
  app.get('/execution/browser/sites', async request => browser.execution.sites(executionAuth(request)));
  app.post('/execution/browser/session', async request => browser.execution.openSession(executionAuth(request), request.body as never));
  app.post('/execution/browser/session-status', async request => browser.execution.sessionStatus(executionAuth(request), request.body as never));
  app.post('/execution/browser/request-approval', async request => browser.execution.requestApproval(executionAuth(request), request.body as never));
  app.post('/execution/browser/approval-status', async request => browser.execution.approvalStatus(executionAuth(request), request.body as never));
  app.post('/execution/browser/fill', async request => browser.execution.fill(executionAuth(request), request.body as never));
  app.post('/execution/browser/submit', async request => ({ operation: await browser.execution.submit(executionAuth(request), request.body as never) }));
  app.get('/execution/connections', async request => { executionAuth(request); return { connections: vault.list() }; });
  app.get('/execution/operations', async request => { executionAuth(request); return { operations: operationsMetadata }; });
  app.post('/execution/prepare-request', async request => {
    const auth = executionAuth(request);
    const { operation_name } = parse(z.object({ operation_name: z.string().min(1).max(100) }).strict(), request.body);
    if (!operationsMetadata.some(item => item.id === operation_name) && !['browser_fill', 'login_submit'].includes(operation_name)) throw new VaultError(400, 'unknown_operation');
    return { request_id: vault.prepareRequest(auth, operation_name) };
  });
  app.post('/execution/connection-status', async request => {
    executionAuth(request);
    const { connection_id } = parse(z.object({ connection_id: idSchema }).strict(), request.body);
    return { connection: vault.get(connection_id) };
  });
  app.post('/execution/operation-status', async request => {
    const auth = executionAuth(request);
    const body = parse(z.object({ request_id: z.string().min(20).max(1024), operation_name: z.string().min(1).max(100) }).strict(), request.body);
    return { operation: vault.getOperationStatus(auth, body.request_id, body.operation_name) };
  });
  app.post('/execution/execute', async request => ({ operation: await execute(vault, request.body, executionAuth(request), {
    clock,
    prepareOAuth: async (auth, input) => oauth!.prepareExecution(binding(auth), { connectionId: input.connection_id, expectedRecordVersion: input.expected_record_version, operationId: input.operation_id }),
    ...(options.productConfig?.mode === 'synthetic' ? { syntheticOnly: true, requestOAuth: (provider: OAuthProvider, token: string, signal: AbortSignal) => oauth!.requestSyntheticProfile(provider, token, signal) } : {}),
  }) }));
  const timer = setInterval(sweepSessions, 1000); timer.unref();
  const retentionTimer = setInterval(() => vault.cleanupRetention(), 60_000); retentionTimer.unref();
  app.addHook('onClose', async () => { clearInterval(timer); clearInterval(retentionTimer); oauth?.invalidatePending(); vault.lock(); await browser.close(); sessions.clear(); pending.clear(); vault.close(); });
  try { await app.listen({ host: '127.0.0.1', port }); }
  catch (error) { clearInterval(timer); clearInterval(retentionTimer); await browser.close(); vault.close(); throw error; }
  return { app, vault, origin: origin(), sweepSessions };
}
