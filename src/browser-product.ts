import { randomUUID } from 'node:crypto';
import { chromium } from 'playwright-core';
import { z } from 'zod';
import { BROWSER_APPROVAL_TTL_MS, BrowserHostError, browserVaultCapabilities, createControlledBrowserHost, type BrowserApprovalReference, type BrowserBindingRequest, type BrowserOperation, type BrowserSessionReference, type BrowserSiteRules } from './browser.js';
import type { Authority } from './contracts.js';
import { servicesMetadata } from './registry.js';
import type { Vault } from './vault.js';

/** Trusted startup configuration only. Never parse this from execution or management request bodies. */
export interface BrowserProductConfig { enabled: boolean; executablePath?: string; headless?: boolean }
const configSchema = z.object({ enabled: z.boolean(), executablePath: z.string().min(1).max(2048).optional(), headless: z.boolean().optional() }).strict();
const sessionSchema = z.object({ browser_session_id: z.string().uuid() }).strict();
const pendingSchema = z.object({ pending_id: z.string().uuid() }).strict();
const requestSchema = sessionSchema.extend({ connection_id: z.string().uuid(), expected_record_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), operation: z.enum(['browser_fill', 'login_submit']) }).strict();
const submitSchema = pendingSchema.extend({ browser_session_id: z.string().uuid(), connection_id: z.string().uuid(),
  expected_record_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), request_id: z.string().min(20).max(1024) }).strict();
function parse<T>(schema: z.ZodType<T>, raw: unknown): T {
  const result = schema.safeParse(raw);
  if (!result.success) throw new BrowserHostError('browser_target_invalid');
  return result.data;
}

// The registry remains the source of the allowed service/origin. Selectors and navigation paths
// are host-owned constants. No product route accepts a URL, selector, script, browser or DOM handle.
const service = servicesMetadata.find(item => item.service_id === 'synthetic-login')!;
const site: Readonly<BrowserSiteRules> = Object.freeze({ id: service.service_id, version: 1, origin: service.origin,
  loginPath: '/login', formSelector: '#login', usernameSelector: '#username', passwordSelector: '#password',
  submitPath: '/session', sessionPath: '/account', syntheticLoopback: true });

export interface BrowserPendingCard extends BrowserBindingRequest {
  pending_id: string;
  owner_id: string;
  principal_id: string;
  site_id: string;
  origin: string;
  account_alias: string;
  label: string;
  operation: BrowserOperation;
  expires_at: number;
  state: 'pending' | 'approved' | 'consumed';
}
interface Pending {
  card: BrowserPendingCard;
  auth: Authority;
  epoch: number;
  statusVersion: number;
  approval?: BrowserApprovalReference;
  busy: boolean;
}

/** Server coordination boundary. Server supplies authenticated Authority objects, enforces its
 * session/CSRF middleware, and exposes only execution to MCP. Host control and approvals remain here. */
export async function createBrowserProduct(options: { vault: Vault; config?: BrowserProductConfig; now?: () => number }) {
  const config = options.config === undefined ? undefined : parse(configSchema, options.config);
  if (config?.enabled && (!config.executablePath || !config.executablePath.startsWith('/'))) throw new BrowserHostError('site_rules_invalid');
  const vault = options.vault, now = options.now ?? Date.now;
  const mapped = browserVaultCapabilities(vault, (auth, credential, operation) => {
    const current = vault.get(credential.id);
    return current.owner_id === auth.owner_id && current.can_execute && current.granted_operations.includes(operation);
  });
  const browser = config?.enabled ? await chromium.launch({ executablePath: config.executablePath!, headless: config.headless ?? true,
    chromiumSandbox: true, args: ['--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-first-run'] }) : undefined;
  const host = browser ? createControlledBrowserHost({ browser, rules: [site], ...mapped, now }) : undefined;
  const pending = new Map<string, Pending>();
  let closed = false;
  function available() {
    if (!host || closed || !browser?.isConnected()) throw new BrowserHostError('unsupported');
    return host;
  }
  function unlocked() {
    if (!mapped.capabilities.securityState().unlocked) throw new BrowserHostError('vault_locked');
  }
  function executor(auth: Authority) {
    available(); unlocked();
    if (auth.owner_id !== 'local' || auth.client_id !== 'execution' || auth.principal_id === 'admin' || !/^[a-zA-Z0-9:._-]{1,160}$/.test(auth.principal_id)) throw new BrowserHostError('forbidden');
  }
  function manager(auth: Authority) {
    available(); unlocked();
    if (auth.owner_id !== 'local' || auth.principal_id !== 'admin' || auth.client_id !== 'management' || !auth.session_id) throw new BrowserHostError('forbidden');
  }
  function prune() {
    const security = mapped.capabilities.securityState();
    for (const [id, value] of pending) if (value.epoch !== security.epoch || !security.unlocked || value.card.expires_at <= now()) pending.delete(id);
  }
  function owned(auth: Authority, id: string): Pending {
    executor(auth); prune();
    const value = pending.get(id);
    if (!value || value.auth.owner_id !== auth.owner_id || value.auth.principal_id !== auth.principal_id) throw new BrowserHostError('approval_invalid');
    return value;
  }
  async function validate(value: Pending) {
    const credential = await mapped.capabilities.credential(value.auth, value.card.connection_id);
    if (credential.record_version !== value.card.expected_record_version || credential.status_version !== value.statusVersion) throw new BrowserHostError('record_changed');
    if (!await mapped.capabilities.authorize(value.auth, credential, value.card.operation) || credential.origin !== value.card.origin || credential.status !== 'active') throw new BrowserHostError('forbidden');
    await available().execution.sessionStatus(value.auth, value.card.browser_session_id);
    // Both credential and document inspection may yield; don't let a concurrent lock revive a card.
    if (value.epoch !== vault.epoch || value.card.expires_at <= now() || !pending.has(value.card.pending_id)) throw new BrowserHostError('approval_invalid');
    unlocked();
  }
  const execution = {
    sites(auth: Authority) {
      if (!host || closed || !browser?.isConnected()) return { supported: false as const, reason: 'unsupported' as const, sites: [] };
      executor(auth);
      return { supported: true as const, sites: [{ site_id: site.id, origin: site.origin, rules_version: site.version }] };
    },
    async openSession(auth: Authority, raw: unknown): Promise<BrowserSessionReference> {
      executor(auth);
      const request = parse(z.object({ site_id: z.literal('synthetic-login') }).strict(), raw);
      return available().execution.openSession(auth, request.site_id);
    },
    async sessionStatus(auth: Authority, raw: unknown) {
      executor(auth);
      return available().execution.sessionStatus(auth, parse(sessionSchema, raw).browser_session_id);
    },
    async requestApproval(auth: Authority, raw: unknown): Promise<BrowserPendingCard> {
      executor(auth); prune();
      const epoch = vault.epoch;
      const request = parse(requestSchema, raw);
      const session = await available().execution.sessionStatus(auth, request.browser_session_id);
      const credential = await mapped.capabilities.credential(auth, request.connection_id);
      if (credential.record_version !== request.expected_record_version) throw new BrowserHostError('record_changed');
      if (credential.credential_type !== 'password' || credential.origin !== site.origin || !await mapped.capabilities.authorize(auth, credential, request.operation)) throw new BrowserHostError('forbidden');
      if (session.status === 'session_reused' || (request.operation === 'browser_fill' ? session.status !== 'ready' : session.status !== 'filled')) throw new BrowserHostError('approval_invalid');
      executor(auth); prune();
      if (epoch !== vault.epoch) throw new BrowserHostError('browser_session_invalid');
      if (pending.size >= 32) throw new BrowserHostError('unsupported');
      const metadata = vault.get(credential.id);
      const card: BrowserPendingCard = { pending_id: randomUUID(), browser_session_id: request.browser_session_id, connection_id: credential.id,
        expected_record_version: credential.record_version, owner_id: auth.owner_id, principal_id: auth.principal_id,
        site_id: session.site_id, origin: site.origin, account_alias: credential.account_alias, label: metadata.label,
        operation: request.operation, expires_at: Math.min(session.expires_at, now() + BROWSER_APPROVAL_TTL_MS), state: 'pending' };
      pending.set(card.pending_id, { card, auth: { ...auth }, epoch: vault.epoch, statusVersion: credential.status_version, busy: false });
      return { ...card };
    },
    async approvalStatus(auth: Authority, raw: unknown): Promise<BrowserPendingCard> {
      const value = owned(auth, parse(pendingSchema, raw).pending_id);
      if (value.card.state !== 'consumed') await validate(value);
      return { ...value.card };
    },
    async fill(auth: Authority, raw: unknown) {
      const value = owned(auth, parse(pendingSchema, raw).pending_id);
      if (value.card.operation !== 'browser_fill' || value.card.state !== 'approved' || !value.approval || value.busy) throw new BrowserHostError('approval_invalid');
      value.busy = true;
      // Failures consume the attempted approval too; callers must request a fresh approval.
      value.card.state = 'consumed';
      try { return await available().execution.fill(auth, { browser_session_id: value.card.browser_session_id, connection_id: value.card.connection_id,
        expected_record_version: value.card.expected_record_version, approval_id: value.approval.approval_id }); }
      finally { value.busy = false; }
    },
    async submit(auth: Authority, raw: unknown) {
      executor(auth);
      const request = parse(submitSchema, raw);
      // Reconstruct the exact durable host input before consulting ephemeral approvals. A completed
      // or unknown operation remains queryable after approval expiry, lock/unlock and host restart.
      const replayed = vault.replayOperation(auth, { request_id: request.request_id, connection_id: request.connection_id, operation_id: 'login_submit',
        expected_record_version: request.expected_record_version, args: { browser_session_id: request.browser_session_id, approval_id: request.pending_id } });
      if (replayed) return replayed;
      const value = owned(auth, request.pending_id);
      if (value.card.browser_session_id !== request.browser_session_id || value.card.connection_id !== request.connection_id || value.card.expected_record_version !== request.expected_record_version
        || value.card.operation !== 'login_submit' || value.card.state === 'pending' || !value.approval || value.busy) throw new BrowserHostError('approval_invalid');
      value.busy = true;
      value.card.state = 'consumed';
      try { return await available().execution.submit(auth, { browser_session_id: value.card.browser_session_id, connection_id: value.card.connection_id,
        expected_record_version: value.card.expected_record_version, approval_id: value.approval.approval_id, request_id: request.request_id }); }
      finally { value.busy = false; }
    },
  };
  const management = {
    async pending(auth: Authority): Promise<BrowserPendingCard[]> {
      manager(auth); prune();
      const cards: BrowserPendingCard[] = [];
      for (const [id, value] of pending) {
        if (value.card.owner_id !== auth.owner_id || value.card.state === 'consumed') continue;
        try { await validate(value); cards.push({ ...value.card }); }
        catch { pending.delete(id); }
      }
      manager(auth);
      return cards;
    },
    async approve(auth: Authority, id: string): Promise<BrowserPendingCard> {
      manager(auth); prune();
      const value = pending.get(parse(z.string().uuid(), id));
      if (!value || value.card.owner_id !== auth.owner_id || value.card.state !== 'pending' || value.busy) throw new BrowserHostError('approval_invalid');
      value.busy = true;
      try {
        await validate(value); manager(auth);
        const binding = { browser_session_id: value.card.browser_session_id, connection_id: value.card.connection_id, expected_record_version: value.card.expected_record_version };
        value.approval = await (value.card.operation === 'browser_fill' ? available().control.approveFill(value.auth, binding, id) : available().control.approveSubmit(value.auth, binding, id));
        manager(auth);
        if (!pending.has(id) || value.epoch !== vault.epoch) throw new BrowserHostError('approval_invalid');
        value.card.state = 'approved';
        value.card.expires_at = Math.min(value.card.expires_at, value.approval.expires_at);
        return { ...value.card };
      } finally { value.busy = false; }
    },
  };
  return { execution, management,
    /** Server calls immediately after global lock/logout; host independently enforces the epoch. */
    invalidatePending() { pending.clear(); void host?.control.prune().catch(() => {}); },
    async close() { closed = true; pending.clear(); try { await host?.control.close(); } finally { await browser?.close(); } },
  };
}
export type BrowserProduct = Awaited<ReturnType<typeof createBrowserProduct>>;
