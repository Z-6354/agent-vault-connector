import { randomUUID } from 'node:crypto';
import type { Browser, BrowserContext, CDPSession, Page } from 'playwright-core';
import { z } from 'zod';
import type { Authority, OperationDefinition, OperationInput, OperationResult, OperationState } from './contracts.js';

export const BROWSER_HANDLE_TTL_MS = 5 * 60_000;
export const BROWSER_APPROVAL_TTL_MS = 60_000;
export type BrowserOperation = 'browser_fill' | 'login_submit';
export type BrowserErrorCode = 'unsupported' | 'vault_locked' | 'forbidden' | 'browser_session_invalid' | 'approval_invalid' | 'record_changed' | 'site_rules_invalid' | 'browser_target_invalid';
export class BrowserHostError extends Error {
  constructor(readonly code: BrowserErrorCode) { super(code); this.name = 'BrowserHostError'; }
}

/** Trusted configuration, never tool arguments. Production rules require HTTPS. */
export interface BrowserSiteRules {
  readonly id: string;
  readonly version: number;
  readonly origin: string;
  readonly loginPath: string;
  readonly formSelector: string;
  readonly usernameSelector: string;
  readonly passwordSelector: string;
  readonly submitPath: string;
  /** Optional fixed, read-only page used to check the host-owned session after login. */
  readonly sessionPath?: string;
  readonly frameName?: string;
  readonly syntheticLoopback?: boolean;
}
export interface BrowserCredential {
  readonly id: string;
  readonly owner_id: string;
  readonly service_id: string;
  readonly credential_type: string;
  readonly origin: string;
  readonly record_version: number;
  readonly status_version: number;
  readonly status: string;
  readonly account_alias: string;
}
/** These callbacks execute inside the trusted process. No callback result contains a password. */
export interface BrowserCapabilities {
  securityState(): { unlocked: boolean; epoch: number };
  credential(auth: Authority, connectionId: string): BrowserCredential | Promise<BrowserCredential>;
  authorize(auth: Authority, credential: BrowserCredential, operation: BrowserOperation): boolean | Promise<boolean>;
  withPassword<T>(auth: Authority, connectionId: string, expectedVersion: number, operation: BrowserOperation,
    use: (password: string, signal: AbortSignal) => Promise<T>): Promise<T>;
}
/** Must be durable: begin deduplicates the complete input and blocks unresolved same-target side effects.
 * After restart, dispatching must recover as outcome_unknown. Request tickets come from the core. */
export interface BrowserSubmitJournal {
  begin(auth: Authority, input: OperationInput, definition: OperationDefinition): { replayed: boolean; operation: OperationResult };
  dispatching(auth: Authority, input: OperationInput): void;
  finish(auth: Authority, input: OperationInput, state: OperationState, result?: unknown, error?: string): OperationResult;
}
export interface BrowserBindingRequest {
  browser_session_id: string;
  connection_id: string;
  expected_record_version: number;
}
export interface BrowserExecutionRequest extends BrowserBindingRequest { approval_id: string }
export interface BrowserSubmitRequest extends BrowserExecutionRequest { request_id: string }
export interface BrowserSessionReference { browser_session_id: string; expires_at: number; site_id: string }
export interface BrowserApprovalReference { approval_id: string; expires_at: number; operation: BrowserOperation }

interface FrameInfo { id: string; loaderId: string; url: string; name?: string; parentId?: string }
interface FrameTree { frame: FrameInfo; childFrames?: FrameTree[] }
interface Tab {
  context: BrowserContext; page: Page; cdp: CDPSession;
  contextId: string; tabId: string; revision: number; closed: boolean; submitPermit: { remaining: number };
}
interface Binding {
  hostId: string; adapterId: string; ownerId: string; principalId: string;
  contextId: string; tabId: string; frameId: string; documentId: string;
  topFrameId: string; topDocumentId: string; origin: string; topOrigin: string;
  epoch: number; revision: number; rulesVersion: number;
}
interface Session {
  id: string; expires: number; rule: Readonly<BrowserSiteRules>; binding: Readonly<Binding>;
  tab: Tab; objectId: string; fillUsed: boolean; auth: Authority;
  credentialBinding?: { connectionId: string; version: number; statusVersion: number };
  filled?: { connectionId: string; version: number; statusVersion: number };
  loginSucceeded?: boolean;
}
interface Approval {
  id: string; expires: number; operation: BrowserOperation; sessionId: string;
  connectionId: string; version: number; statusVersion: number; binding: Readonly<Binding>; used: boolean;
}
const bindingSchema = z.object({ browser_session_id: z.string().uuid(), connection_id: z.string().min(1).max(200), expected_record_version: z.number().int().positive() }).strict();
const executionSchema = bindingSchema.extend({ approval_id: z.string().uuid() }).strict();
const submitSchema = executionSchema.extend({ request_id: z.string().min(1).max(1024) }).strict();
function parsed<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) throw new BrowserHostError('browser_target_invalid');
  return result.data;
}
function origin(url: string): string { try { return new URL(url).origin; } catch { return 'null'; } }
function validateRules(rule: BrowserSiteRules): Readonly<BrowserSiteRules> {
  const url = new URL(rule.origin);
  const loopback = rule.syntheticLoopback === true && url.protocol === 'http:' && url.hostname === '127.0.0.1';
  if (url.origin !== rule.origin || url.username || url.password || (url.protocol !== 'https:' && !loopback)
    || !Number.isSafeInteger(rule.version) || rule.version < 1 || !rule.id
    || ![rule.loginPath, rule.submitPath, ...(rule.sessionPath === undefined ? [] : [rule.sessionPath])].every(p => p.startsWith('/') && !p.startsWith('//') && new URL(p, rule.origin).origin === rule.origin && !p.includes('\\') && !p.includes('#') && !p.includes('?'))
    || ![rule.formSelector, rule.usernameSelector, rule.passwordSelector].every(p => p.length > 0 && p.length <= 200)) {
    throw new BrowserHostError('site_rules_invalid');
  }
  return Object.freeze({ ...rule });
}
function frames(tree: FrameTree): FrameTree[] { return [tree, ...(tree.childFrames ?? []).flatMap(frames)]; }

/* This function is serialized into a Chromium isolated world and runs synchronously. The retained
 * document/topDocument references belong to the original documents, not a page-supplied token.
 * No events, Enter, click, selector input, DOM value or page exception is returned to the caller. */
function controlledDOM(this: { document: Document; root: Element | null; topDocument: Document; topRoot: Element | null },
  data: { rules: BrowserSiteRules; operation: 'check' | 'fill' | 'submit'; username?: string; password?: string }): 'ready' | 'filled' | 'submitted' | 'rejected' {
  try {
    const r = data.rules;
    const valid = () => this.document === document && this.root === document.documentElement
      && this.topDocument === window.top!.document && this.topRoot === window.top!.document.documentElement
      && location.origin === r.origin && window.top!.location.origin === r.origin;
    if (!valid()) return 'rejected';
    let w: Window = window;
    while (w !== w.top) {
      if (w.parent.location.origin !== r.origin || !w.frameElement?.isConnected) return 'rejected';
      w = w.parent;
    }
    const one = (selector: string) => { const nodes = document.querySelectorAll(selector); return nodes.length === 1 ? nodes[0] : undefined; };
    const form = one(r.formSelector), username = one(r.usernameSelector), password = one(r.passwordSelector);
    if (!(form instanceof HTMLFormElement) || !(username instanceof HTMLInputElement) || !(password instanceof HTMLInputElement)
      || username.form !== form || password.form !== form || !['text', 'email'].includes(username.type) || password.type !== 'password'
      || ![form, username, password].every(n => n.isConnected && n.getClientRects().length > 0)
      || username.disabled || password.disabled || username.readOnly || password.readOnly
      || form.action !== new URL(r.submitPath, r.origin).href || form.method !== 'post'
      || !['', '_self'].includes(form.target) || form.enctype !== 'application/x-www-form-urlencoded') return 'rejected';
    if (data.operation === 'check') return 'ready';
    if (data.operation === 'fill') {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
      setter.call(username, data.username!);
      setter.call(password, data.password!);
      return valid() ? 'filled' : 'rejected';
    }
    if (!valid()) return 'rejected';
    HTMLFormElement.prototype.submit.call(form);
    return 'submitted';
  } catch { return 'rejected'; }
}

/** Only expose execution to an authenticated agent. Keep approvals/control in the trusted manager.
 * Browser must be a dedicated, nonpersistent Chromium instance with no trace/console forwarding. */
export function createControlledBrowserHost(options: {
  browser: Browser;
  rules: readonly BrowserSiteRules[];
  capabilities: BrowserCapabilities;
  journal: BrowserSubmitJournal;
  now?: () => number;
  submitTimeoutMs?: number;
  maxSessions?: number;
  maxApprovals?: number;
  cleanupIntervalMs?: number;
}) {
  const rules = new Map(options.rules.map(rule => { const r = validateRules(rule); return [r.id, r] as const; }));
  if (rules.size !== options.rules.length) throw new BrowserHostError('site_rules_invalid');
  const capabilities = options.capabilities;
  const now = options.now ?? Date.now;
  const hostId = randomUUID();
  const adapterId = 'controlled-chromium-v1';
  const sessions = new Map<string, Session>();
  const approvals = new Map<string, Approval>();
  const tabs = new Set<Tab>();
  const maxSessions = options.maxSessions ?? 8, maxApprovals = options.maxApprovals ?? 32;
  const cleanupIntervalMs = options.cleanupIntervalMs ?? 1_000;
  if (![maxSessions, maxApprovals, cleanupIntervalMs].every(n => Number.isSafeInteger(n) && n > 0)
    || maxSessions > 32 || maxApprovals > 128 || cleanupIntervalMs > 1_000) throw new BrowserHostError('site_rules_invalid');
  let stopped = false, opening = 0;
  let pruning: Promise<void> | undefined;
  const closing = new Map<Tab, Promise<void>>();
  function clearSessionApprovals(sessionId: string) {
    for (const [id, approved] of approvals) if (approved.sessionId === sessionId) approvals.delete(id);
  }
  function forgetTab(tab: Tab) {
    tab.closed = true; tab.revision++; tab.submitPermit.remaining = 0;
    tabs.delete(tab);
    for (const [id, session] of sessions) if (session.tab === tab) { sessions.delete(id); clearSessionApprovals(id); }
  }
  function disposeTab(tab: Tab): Promise<void> {
    const existing = closing.get(tab);
    if (existing) return existing;
    forgetTab(tab);
    const pending = tab.context.close().catch(() => {}).finally(() => { closing.delete(tab); });
    closing.set(tab, pending);
    return pending;
  }
  function basicPrune(current: { unlocked: boolean; epoch: number }) {
    for (const [id, approved] of approvals) if (approved.used || approved.expires <= now() || !sessions.has(approved.sessionId) || approved.binding.epoch !== current.epoch || !current.unlocked) approvals.delete(id);
    for (const session of sessions.values()) {
      if (session.expires <= now() || session.binding.epoch !== current.epoch || !current.unlocked || session.tab.closed || session.tab.page.isClosed()) void disposeTab(session.tab);
      else if (session.binding.revision !== session.tab.revision) clearSessionApprovals(session.id);
    }
  }
  function state() {
    const current = capabilities.securityState();
    basicPrune(current);
    if (!current.unlocked) throw new BrowserHostError('vault_locked');
    if (stopped || !options.browser.isConnected()) throw new BrowserHostError('unsupported');
    return current;
  }
  async function prune() {
    if (pruning) return pruning;
    pruning = (async () => {
      if (stopped) return;
      let current: { unlocked: boolean; epoch: number };
      try { current = capabilities.securityState(); } catch { current = { unlocked: false, epoch: -1 }; }
      basicPrune(current);
      for (const session of [...sessions.values()]) {
        const binding = session.credentialBinding;
        if (!binding) continue;
        try {
          const credential = await capabilities.credential(session.auth, binding.connectionId);
          if (credential.owner_id !== session.binding.ownerId || credential.record_version !== binding.version || credential.status_version !== binding.statusVersion
            || credential.status !== 'active' || !await capabilities.authorize(session.auth, credential, 'browser_fill')) await disposeTab(session.tab);
        } catch { await disposeTab(session.tab); }
      }
      await Promise.all([...closing.values()]);
    })().finally(() => { pruning = undefined; });
    return pruning;
  }
  const cleanupTimer = setInterval(() => { void prune().catch(() => {}); }, cleanupIntervalMs);
  cleanupTimer.unref();
  const disconnected = () => {
    stopped = true; clearInterval(cleanupTimer); approvals.clear();
    for (const tab of [...tabs]) forgetTab(tab);
    options.browser.off('disconnected', disconnected);
  };
  options.browser.on('disconnected', disconnected);
  function sessionFor(auth: Authority, id: string, retainedContext = false): Session {
    const security = state();
    const session = sessions.get(id);
    if (!session || session.expires <= now() || session.binding.epoch !== security.epoch
      || session.binding.ownerId !== auth.owner_id || session.binding.principalId !== auth.principal_id
      || session.binding.hostId !== hostId || session.tab.closed || session.tab.page.isClosed()
      || session.binding.contextId !== session.tab.contextId || session.binding.tabId !== session.tab.tabId
      || (!retainedContext && session.binding.revision !== session.tab.revision) || rules.get(session.rule.id)?.version !== session.binding.rulesVersion) {
      throw new BrowserHostError('browser_session_invalid');
    }
    return session;
  }
  async function credentialFor(auth: Authority, request: BrowserBindingRequest, operation: BrowserOperation) {
    state();
    const credential = await capabilities.credential(auth, request.connection_id);
    for (const approved of [...approvals.values()]) if (approved.connectionId === request.connection_id
      && (!credential || credential.record_version !== approved.version || credential.status_version !== approved.statusVersion || credential.status !== 'active')) {
      const oldSession = sessions.get(approved.sessionId);
      clearSessionApprovals(approved.sessionId);
      if (oldSession?.filled) void disposeTab(oldSession.tab);
    }
    if (!credential || credential.owner_id !== auth.owner_id || credential.credential_type !== 'password' || credential.status !== 'active'
      || !await capabilities.authorize(auth, credential, operation)) throw new BrowserHostError('forbidden');
    if (credential.record_version !== request.expected_record_version) throw new BrowserHostError('record_changed');
    return credential;
  }
  async function snapshot(tab: Tab, rule: BrowserSiteRules) {
    const { frameTree } = await tab.cdp.send('Page.getFrameTree') as { frameTree: FrameTree };
    const candidates = rule.frameName ? frames(frameTree).filter(t => t.frame.name === rule.frameName) : [frameTree];
    if (candidates.length !== 1) throw new BrowserHostError('browser_target_invalid');
    const target = candidates[0]!.frame;
    if (origin(frameTree.frame.url) !== rule.origin || origin(target.url) !== rule.origin) throw new BrowserHostError('browser_target_invalid');
    return { top: frameTree.frame, target };
  }
  async function run(session: Session, operation: 'check' | 'fill' | 'submit', username?: string, password?: string) {
    const result = await session.tab.cdp.send('Runtime.callFunctionOn', {
      objectId: session.objectId,
      functionDeclaration: controlledDOM.toString(),
      arguments: [{ value: { rules: session.rule, operation, ...(username === undefined ? {} : { username }), ...(password === undefined ? {} : { password }) } }],
      returnByValue: true, awaitPromise: false,
    });
    if (result.exceptionDetails || !['ready', 'filled', 'submitted', 'rejected'].includes(result.result?.value)) throw new BrowserHostError('browser_target_invalid');
    return result.result.value as 'ready' | 'filled' | 'submitted' | 'rejected';
  }
  async function check(auth: Authority, session: Session) {
    sessionFor(auth, session.id);
    const before = session.tab.revision;
    const current = await snapshot(session.tab, session.rule);
    const b = session.binding;
    if (current.top.id !== b.topFrameId || current.top.loaderId !== b.topDocumentId || current.target.id !== b.frameId || current.target.loaderId !== b.documentId
      || await run(session, 'check') !== 'ready' || session.tab.revision !== before) throw new BrowserHostError('browser_session_invalid');
    sessionFor(auth, session.id);
  }
  async function approval(auth: Authority, raw: BrowserBindingRequest, operation: BrowserOperation, correlationId?: string): Promise<BrowserApprovalReference> {
    const request = parsed(bindingSchema, raw);
    const session = sessionFor(auth, request.browser_session_id);
    const credential = await credentialFor(auth, request, operation);
    if (credential.origin !== session.rule.origin || (operation === 'browser_fill' && session.fillUsed)
      || (operation === 'login_submit' && (session.filled?.connectionId !== credential.id || session.filled.version !== credential.record_version || session.filled.statusVersion !== credential.status_version))) throw new BrowserHostError('approval_invalid');
    await check(auth, session);
    if (approvals.size >= maxApprovals) throw new BrowserHostError('unsupported');
    session.credentialBinding = { connectionId: credential.id, version: credential.record_version, statusVersion: credential.status_version };
    // Optional trusted coordinator correlation keeps journal inputs reconstructible after restart.
    const id = correlationId === undefined ? randomUUID() : parsed(z.string().uuid(), correlationId);
    if (approvals.has(id)) throw new BrowserHostError('approval_invalid');
    const expires = Math.min(now() + BROWSER_APPROVAL_TTL_MS, session.expires);
    approvals.set(id, { id, expires, operation, sessionId: session.id, connectionId: credential.id, version: credential.record_version, statusVersion: credential.status_version, binding: session.binding, used: false });
    return { approval_id: id, expires_at: expires, operation };
  }
  function takeApproval(session: Session, request: BrowserExecutionRequest, operation: BrowserOperation) {
    const approved = approvals.get(request.approval_id);
    if (!approved || approved.used || approved.expires <= now() || approved.operation !== operation || approved.sessionId !== session.id
      || approved.connectionId !== request.connection_id || approved.version !== request.expected_record_version || approved.binding !== session.binding) throw new BrowserHostError('approval_invalid');
    approved.used = true;
    approvals.delete(approved.id);
    return approved;
  }
  function approvalStillCurrent(approved: Approval) {
    if (approved.expires <= now() || approved.binding.epoch !== state().epoch) throw new BrowserHostError('approval_invalid');
  }
  const execution = {
    async openSession(auth: Authority, siteId: string): Promise<BrowserSessionReference> {
      const security = state();
      const rule = rules.get(siteId);
      if (!rule || !auth.principal_id || !auth.owner_id) throw new BrowserHostError('unsupported');
      if (sessions.size + opening >= maxSessions) throw new BrowserHostError('unsupported');
      opening++;
      let allocatedContext: BrowserContext | undefined;
      let registered = false;
      try {
      const context = await options.browser.newContext({ serviceWorkers: 'block', acceptDownloads: false });
      allocatedContext = context;
      // Dedicated context: no existing profile/cookies, no storageState, trace, video, screenshot or console forwarding.
      const submitPermit = { remaining: 0 };
      await context.route('**/*', route => {
        const request = route.request();
        if (origin(request.url()) !== rule.origin) return route.abort('blockedbyclient');
        if (request.method() !== 'GET' && request.method() !== 'HEAD') {
          if (request.method() !== 'POST' || request.url() !== new URL(rule.submitPath, rule.origin).href || !request.isNavigationRequest() || submitPermit.remaining !== 1) return route.abort('blockedbyclient');
          submitPermit.remaining = 0;
          // Chromium's network stack may internally retry a reset POST without emitting a second
          // routed Request. Dispatch through the fixed route with explicit zero retries/redirects;
          // fulfill once, or abort with a local failure instead of exposing a reset to Chromium.
          return route.fetch({ maxRetries: 0, maxRedirects: 0, timeout: options.submitTimeoutMs ?? 5_000 })
            .then(async response => {
              if (response.status() >= 300 && response.status() < 400) { await response.dispose(); return route.abort('blockedbyclient'); }
              try { await route.fulfill({ response }); } finally { await response.dispose(); }
            }).catch(() => route.abort('failed').catch(() => {}));
        }
        return route.continue();
      });
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      const tab: Tab = { context, page, cdp, contextId: randomUUID(), tabId: randomUUID(), revision: 0, closed: false, submitPermit };
      tabs.add(tab);
      const invalidate = () => { tab.revision++; for (const session of sessions.values()) if (session.tab === tab) clearSessionApprovals(session.id); };
      for (const event of ['Page.frameNavigated', 'Page.navigatedWithinDocument', 'Page.frameAttached', 'Page.frameDetached', 'Page.frameRequestedNavigation', 'Page.frameStartedLoading'] as const) cdp.on(event, invalidate);
      page.on('close', () => { void disposeTab(tab); });
      context.on('close', () => { forgetTab(tab); });
      try {
        await cdp.send('Page.enable');
        await page.goto(new URL(rule.loginPath, rule.origin).href, { waitUntil: 'load' });
        const revision = tab.revision;
        const current = await snapshot(tab, rule);
        const world = await cdp.send('Page.createIsolatedWorld', { frameId: current.target.id, worldName: `vault-${hostId}`, grantUniveralAccess: false });
        const retained = await cdp.send('Runtime.evaluate', {
          contextId: world.executionContextId,
          expression: '({document, root:document.documentElement, topDocument:window.top.document, topRoot:window.top.document.documentElement})',
          returnByValue: false,
        });
        if (retained.exceptionDetails || !retained.result?.objectId || revision !== tab.revision) throw new BrowserHostError('browser_target_invalid');
        const id = randomUUID();
        const session: Session = {
          id, expires: now() + BROWSER_HANDLE_TTL_MS, rule, tab, objectId: retained.result.objectId, fillUsed: false, auth: { ...auth },
          binding: Object.freeze({ hostId, adapterId, ownerId: auth.owner_id, principalId: auth.principal_id, contextId: tab.contextId, tabId: tab.tabId,
            frameId: current.target.id, documentId: current.target.loaderId, topFrameId: current.top.id, topDocumentId: current.top.loaderId,
            origin: origin(current.target.url), topOrigin: origin(current.top.url), epoch: security.epoch, revision, rulesVersion: rule.version }),
        };
        sessions.set(id, session);
        await check(auth, session);
        registered = true;
        return { browser_session_id: id, expires_at: session.expires, site_id: rule.id };
      } catch {
        await context.close().catch(() => {});
        throw new BrowserHostError('browser_target_invalid');
      }
      } finally { if (!registered) await allocatedContext?.close().catch(() => {}); opening--; }
    },
    /** Safe status only. A successful submit retains its context, but never revives its document
     * authorization. The optional session probe is a source-controlled read-only path, not caller input. */
    async sessionStatus(auth: Authority, id: string): Promise<BrowserSessionReference & { status: 'ready' | 'filled' | 'session_reused'; authenticated?: boolean; http_status?: number }> {
      const session = sessionFor(auth, id, true);
      if (!session.loginSucceeded) {
        await check(auth, session);
        return { browser_session_id: id, site_id: session.rule.id, expires_at: session.expires, status: session.filled ? 'filled' : 'ready' };
      }
      if (!session.rule.sessionPath || !session.credentialBinding) throw new BrowserHostError('unsupported');
      const binding = { browser_session_id: id, connection_id: session.credentialBinding.connectionId, expected_record_version: session.credentialBinding.version };
      const validate = async () => {
        sessionFor(auth, id, true);
        const credential = await credentialFor(auth, binding, 'browser_fill');
        if (credential.origin !== session.rule.origin || credential.status_version !== session.credentialBinding!.statusVersion) throw new BrowserHostError('record_changed');
      };
      await validate();
      const target = new URL(session.rule.sessionPath, session.rule.origin).href;
      let response;
      try { response = await session.tab.page.goto(target, { waitUntil: 'load', timeout: options.submitTimeoutMs ?? 5_000 }); }
      catch { throw new BrowserHostError('browser_target_invalid'); }
      await validate();
      if (!response || response.url() !== target || session.tab.page.url() !== target) throw new BrowserHostError('browser_target_invalid');
      const http_status = response.status();
      return { browser_session_id: id, site_id: session.rule.id, expires_at: session.expires, status: 'session_reused', authenticated: http_status === 200, http_status };
    },
    async fill(auth: Authority, raw: BrowserExecutionRequest): Promise<{ status: 'filled'; submitted: false }> {
      const request = parsed(executionSchema, raw);
      const session = sessionFor(auth, request.browser_session_id);
      const credential = await credentialFor(auth, request, 'browser_fill');
      if (credential.origin !== session.rule.origin || session.fillUsed) throw new BrowserHostError('approval_invalid');
      await check(auth, session);
      const approved = takeApproval(session, request, 'browser_fill');
      if (approved.statusVersion !== credential.status_version) throw new BrowserHostError('approval_invalid');
      session.fillUsed = true;
      try {
        await capabilities.withPassword(auth, credential.id, credential.record_version, 'browser_fill', async (password, signal) => {
          await check(auth, session);
          if (signal.aborted) throw new BrowserHostError('vault_locked');
          const current = await credentialFor(auth, request, 'browser_fill');
          if (approved.statusVersion !== current.status_version) throw new BrowserHostError('approval_invalid');
          sessionFor(auth, session.id);
          approvalStillCurrent(approved);
          // Final document identity check and both native setters execute as one renderer task.
          if (await run(session, 'fill', credential.account_alias, password) !== 'filled') throw new BrowserHostError('browser_target_invalid');
          if (signal.aborted) throw new BrowserHostError('vault_locked');
        });
        session.filled = { connectionId: credential.id, version: credential.record_version, statusVersion: credential.status_version };
        return { status: 'filled', submitted: false };
      } catch (error) {
        if (error instanceof BrowserHostError) throw error;
        throw new BrowserHostError('browser_target_invalid');
      }
    },
    async submit(auth: Authority, raw: BrowserSubmitRequest): Promise<OperationResult> {
      const request = parsed(submitSchema, raw);
      const credential = await credentialFor(auth, request, 'login_submit');
      const rule = sessions.get(request.browser_session_id)?.rule ?? [...rules.values()].find(r => r.origin === credential.origin);
      if (!rule) throw new BrowserHostError('unsupported');
      const input: OperationInput = { request_id: request.request_id, connection_id: request.connection_id, operation_id: 'login_submit', expected_record_version: request.expected_record_version,
        args: { browser_session_id: request.browser_session_id, approval_id: request.approval_id } };
      const begun = options.journal.begin(auth, input, { id: 'login_submit', service_id: credential.service_id, origin: rule.origin, semantics: 'non_idempotent', business_target: new URL(rule.submitPath, rule.origin).href });
      if (begun.replayed) return begun.operation;
      let session: Session;
      let approved: Approval;
      try {
        session = sessionFor(auth, request.browser_session_id);
        if (session.rule !== rule || session.filled?.connectionId !== credential.id || session.filled.version !== credential.record_version || session.filled.statusVersion !== credential.status_version) throw new BrowserHostError('approval_invalid');
        await check(auth, session);
        approved = takeApproval(session, request, 'login_submit');
        if (approved.statusVersion !== credential.status_version) throw new BrowserHostError('approval_invalid');
        // Recheck record/status/policy after asynchronous document inspection.
        const current = await credentialFor(auth, request, 'login_submit');
        if (approved.statusVersion !== current.status_version) throw new BrowserHostError('approval_invalid');
        sessionFor(auth, session.id);
      } catch {
        return options.journal.finish(auth, input, 'failed_before_dispatch', undefined, 'browser_approval_or_target_invalid');
      }
      try { options.journal.dispatching(auth, input); }
      catch { return options.journal.finish(auth, input, 'failed_before_dispatch', undefined, 'browser_dispatch_denied'); }
      // Install the response waiter before dispatch. Never inspect or return body, cookies or headers.
      const response = session.tab.page.waitForResponse(r => r.url() === new URL(rule.submitPath, rule.origin).href
        && r.request().method() === 'POST' && r.request().isNavigationRequest(), { timeout: options.submitTimeoutMs ?? 5_000 })
        .then(r => ({ http_status: r.status() })).catch(() => undefined);
      try {
        // Check once more after durable dispatching, then synchronous renderer identity/action + submit.
        await check(auth, session);
        const current = await credentialFor(auth, request, 'login_submit');
        if (approved.statusVersion !== current.status_version) throw new BrowserHostError('approval_invalid');
        sessionFor(auth, session.id);
        approvalStillCurrent(approved);
        session.tab.submitPermit.remaining = 1;
        const result = await run(session, 'submit');
        if (result === 'rejected') return options.journal.finish(auth, input, 'outcome_unknown', undefined, 'browser_target_invalid_after_dispatching');
        if (result !== 'submitted') throw new BrowserHostError('browser_target_invalid');
        const received = await response;
        if (!received) return options.journal.finish(auth, input, 'outcome_unknown', undefined, 'submit_outcome_unknown');
        // HTTP errors do not prove the site performed no side effect; a login may commit
        // before rendering fails. Keep the target blocked until explicit reconciliation.
        // A response event can precede document commit. Settle the fixed submit navigation before
        // allowing a session-status probe to navigate this same tab and reuse its cookies.
        const targetFrame = session.tab.page.frames().find(frame => rule.frameName ? frame.name() === rule.frameName : frame === session.tab.page.mainFrame());
        if (!targetFrame) throw new BrowserHostError('browser_target_invalid');
        await targetFrame.waitForURL(new URL(rule.submitPath, rule.origin).href, { waitUntil: 'load', timeout: options.submitTimeoutMs ?? 5_000 });
        session.loginSucceeded = received.http_status >= 200 && received.http_status < 300;
        return options.journal.finish(auth, input, session.loginSucceeded ? 'succeeded' : 'outcome_unknown',
          { status: 'submitted', ...received }, received.http_status >= 200 && received.http_status < 300 ? undefined : 'submit_outcome_unknown');
      } catch {
        // Includes disconnect/navigation/CDP error after dispatching. Never retry this operation.
        return options.journal.finish(auth, input, 'outcome_unknown', undefined, 'submit_outcome_unknown');
      } finally {
        session.tab.submitPermit.remaining = 0;
      }
    },
  };
  const control = {
    approveFill: (auth: Authority, request: BrowserBindingRequest, correlationId?: string) => approval(auth, request, 'browser_fill', correlationId),
    approveSubmit: (auth: Authority, request: BrowserBindingRequest, correlationId?: string) => approval(auth, request, 'login_submit', correlationId),
    /** Trusted host owner only. Never expose this Page or any generic browser tool to an agent.
     * Intended for local synthetic harnesses and host lifecycle management, not secret inspection. */
    page(auth: Authority, sessionId: string): Page { return sessionFor(auth, sessionId).tab.page; },
    async prune() { await prune(); },
    async closeSession(auth: Authority, sessionId: string) {
      const session = sessions.get(sessionId);
      if (!session) return; // Idempotent cleanup of a previously pruned reference grants no action.
      if (session.binding.ownerId !== auth.owner_id || session.binding.principalId !== auth.principal_id) throw new BrowserHostError('forbidden');
      await disposeTab(session.tab);
    },
    async close() {
      stopped = true; clearInterval(cleanupTimer); options.browser.off('disconnected', disconnected);
      approvals.clear();
      await Promise.all([...tabs].map(disposeTab));
      await pruning;
      await Promise.all([...closing.values()]);
      sessions.clear(); tabs.clear();
    },
  };
  return { execution, control };
}

/** Structural mapping avoids coupling the host to storage or policy implementation details. */
export interface BrowserVaultBackend {
  readonly epoch: number;
  requireUnlocked(): unknown;
  get(id: string): BrowserCredential | undefined;
  withToken<T>(id: string, use: (password: string, signal: AbortSignal) => Promise<T>, expected_record_version?: number, operation_id?: string): Promise<T>;
  beginOperation(auth: Authority, input: OperationInput, definition: OperationDefinition): { replayed: boolean; operation: OperationResult };
  markDispatching(auth: Authority, input: OperationInput): void;
  finishOperation(auth: Authority, input: OperationInput, state: OperationState, result?: unknown, error?: string): OperationResult;
}
export function browserVaultCapabilities(vault: BrowserVaultBackend, authorize: BrowserCapabilities['authorize']): { capabilities: BrowserCapabilities; journal: BrowserSubmitJournal } {
  return {
    capabilities: {
      securityState: () => { try { vault.requireUnlocked(); return { unlocked: true, epoch: vault.epoch }; } catch { return { unlocked: false, epoch: vault.epoch }; } },
      credential: (auth, id) => { const credential = vault.get(id); if (!credential || credential.owner_id !== auth.owner_id) throw new BrowserHostError('forbidden'); return credential; },
      authorize,
      withPassword: async (auth, id, expectedVersion, operation, use) => {
        const credential = vault.get(id);
        if (!credential || credential.owner_id !== auth.owner_id || !await authorize(auth, credential, operation)) throw new BrowserHostError('forbidden');
        return vault.withToken(id, use, expectedVersion, operation);
      },
    },
    journal: {
      begin: (auth, input, definition) => vault.beginOperation(auth, input, definition),
      dispatching: (auth, input) => vault.markDispatching(auth, input),
      finish: (auth, input, status, result, error) => vault.finishOperation(auth, input, status, result, error),
    },
  };
}
