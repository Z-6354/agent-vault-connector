import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { chromium, type Browser } from 'playwright-core';
import { BROWSER_APPROVAL_TTL_MS, BROWSER_HANDLE_TTL_MS, BrowserHostError, createControlledBrowserHost, type BrowserCapabilities, type BrowserCredential, type BrowserSiteRules, type BrowserSubmitJournal, browserVaultCapabilities } from '../src/browser.js';
import { startSyntheticBrowserDemo } from '../src/browser-demo.js';
import type { Authority, OperationDefinition, OperationInput, OperationResult, OperationState, SavePayload } from '../src/contracts.js';
import { initialize, Vault } from '../src/vault.js';

// Only the local synthetic target sees these values. Never use DOM snapshots, inputValue,
// screenshots, trace, HAR, response bodies or assertion output containing a password.
const syntheticUsername = 'synthetic_browser_user';
const syntheticPassword = `synthetic_browser_${randomUUID()}`;
const auth: Authority = { owner_id: 'local', principal_id: 'browser-agent', client_id: 'synthetic-test' };
let browser: Browser;
before(async () => {
  browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, chromiumSandbox: true, args: ['--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-first-run'] });
});
after(async () => { await browser?.close(); });

/** Test implementation of the durable journal capability; production uses the actual Vault mapper.
 * SQLite contains tickets, authenticated scope, immutable nonsecret payloads and status only. */
class TestJournal implements BrowserSubmitJournal {
  readonly db: Database.Database;
  constructor(file: string) {
    this.db = new Database(file);
    this.db.exec('CREATE TABLE IF NOT EXISTS operations(scope TEXT PRIMARY KEY, payload TEXT NOT NULL, target TEXT NOT NULL, operation TEXT NOT NULL)');
    for (const row of this.db.prepare('SELECT scope, operation FROM operations').all() as { scope: string; operation: string }[]) {
      const operation = JSON.parse(row.operation) as OperationResult;
      if (operation.state === 'dispatching') {
        operation.state = 'outcome_unknown'; operation.operation_status_version++;
        this.db.prepare('UPDATE operations SET operation=? WHERE scope=?').run(JSON.stringify(operation), row.scope);
      }
    }
  }
  private scope(auth: Authority, input: OperationInput) { return JSON.stringify([auth.owner_id, auth.principal_id, input.operation_id, input.request_id]); }
  begin(auth: Authority, input: OperationInput, definition: OperationDefinition) {
    const scope = this.scope(auth, input), payload = JSON.stringify(input);
    const row = this.db.prepare('SELECT payload,operation FROM operations WHERE scope=?').get(scope) as { payload: string; operation: string } | undefined;
    if (row) {
      if (row.payload !== payload) throw new Error('idempotency_conflict');
      return { replayed: true, operation: JSON.parse(row.operation) as OperationResult };
    }
    const target = JSON.stringify([auth.owner_id, input.connection_id, definition.id, definition.business_target]);
    const conflicts = this.db.prepare('SELECT operation FROM operations WHERE target=?').all(target) as { operation: string }[];
    if (conflicts.some(row => ['accepted', 'dispatching', 'outcome_unknown'].includes((JSON.parse(row.operation) as OperationResult).state))) throw new Error('operation_conflict');
    const operation: OperationResult = { request_id: input.request_id, connection_id: input.connection_id, operation_id: input.operation_id, state: 'accepted', operation_status_version: 1 };
    this.db.prepare('INSERT INTO operations VALUES(?,?,?,?)').run(scope, payload, target, JSON.stringify(operation));
    return { replayed: false, operation };
  }
  dispatching(auth: Authority, input: OperationInput) { this.finish(auth, input, 'dispatching'); }
  finish(auth: Authority, input: OperationInput, state: OperationState, result?: unknown, error?: string): OperationResult {
    const scope = this.scope(auth, input);
    const row = this.db.prepare('SELECT operation FROM operations WHERE scope=?').get(scope) as { operation: string };
    const previous = JSON.parse(row.operation) as OperationResult;
    const operation: OperationResult = { ...previous, state, operation_status_version: previous.operation_status_version + 1, ...(result === undefined ? {} : { result }), ...(error === undefined ? {} : { error }) };
    this.db.prepare('UPDATE operations SET operation=? WHERE scope=?').run(JSON.stringify(operation), scope);
    return operation;
  }
  close() { this.db.close(); }
}
async function fixture(config: { rules?: (rules: BrowserSiteRules, framed: BrowserSiteRules) => BrowserSiteRules[]; submitTimeoutMs?: number; maxSessions?: number; maxApprovals?: number; cleanupIntervalMs?: number } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-browser-'));
  const demo = await startSyntheticBrowserDemo({ username: syntheticUsername, password: syntheticPassword });
  let journal = new TestJournal(path.join(directory, 'operations.sqlite'));
  const state = { unlocked: true, epoch: 1, time: Date.now(), allowed: true, reads: 0, dispatchDenied: false, pauseBeforePassword: undefined as undefined | (() => Promise<void>) };
  const credential = { id: 'synthetic-connection', owner_id: 'local', service_id: 'synthetic-login', credential_type: 'password', origin: demo.origin, record_version: 1, status_version: 1, status: 'active', account_alias: syntheticUsername };
  const capabilities: BrowserCapabilities = {
    securityState: () => ({ unlocked: state.unlocked, epoch: state.epoch }),
    credential: () => ({ ...credential }),
    authorize: requestAuth => state.allowed && requestAuth.principal_id === auth.principal_id,
    withPassword: async (_auth, _id, version, _operation, use) => {
      if (state.pauseBeforePassword) await state.pauseBeforePassword();
      if (!state.unlocked) throw new BrowserHostError('vault_locked');
      if (version !== credential.record_version) throw new BrowserHostError('record_changed');
      state.reads++;
      return use(syntheticPassword, new AbortController().signal);
    },
  };
  const rules = config.rules?.(demo.rules, demo.frameRules) ?? [demo.rules];
  const host = createControlledBrowserHost({ browser, rules, capabilities,
    journal: { begin: (...args) => journal.begin(...args), dispatching: (...args) => { if (state.dispatchDenied) throw new Error('synthetic_dispatch_denied'); journal.dispatching(...args); }, finish: (...args) => journal.finish(...args) },
    now: () => state.time, submitTimeoutMs: config.submitTimeoutMs ?? 300, maxSessions: config.maxSessions, maxApprovals: config.maxApprovals, cleanupIntervalMs: config.cleanupIntervalMs,
  });
  async function open(siteId = rules[0]!.id) {
    const session = await host.execution.openSession(auth, siteId);
    const binding = { browser_session_id: session.browser_session_id, connection_id: credential.id, expected_record_version: credential.record_version };
    const approved = await host.control.approveFill(auth, binding);
    return { session, binding, request: { ...binding, approval_id: approved.approval_id }, approved, page: host.control.page(auth, session.browser_session_id) };
  }
  return { demo, state, credential, host, open, capabilities, rules, directory,
    restartJournal() { journal.close(); journal = new TestJournal(path.join(directory, 'operations.sqlite')); },
    async close() { await host.control.close(); journal.close(); await demo.close(); fs.rmSync(directory, { recursive: true, force: true }); },
  };
}
function rejectsCode(promise: Promise<unknown>, ...codes: string[]) { return assert.rejects(promise, e => e instanceof BrowserHostError && codes.includes(e.code)); }

 test('real Chromium fills fixed local form once without submission, no secret output, then separately approved submit creates host-owned session', async () => {
  const f = await fixture();
  try {
    const { binding, request, page } = await f.open();
    const result = await f.host.execution.fill(auth, request);
    assert.deepEqual(result, { status: 'filled', submitted: false });
    assert.equal(f.state.reads, 1); assert.equal(f.demo.stats.submissions, 0);
    assert.equal(JSON.stringify(result).includes(syntheticPassword), false);
    await rejectsCode(f.host.execution.fill(auth, request), 'approval_invalid');
    const unapproved = await f.host.execution.submit(auth, { ...request, request_id: randomUUID() });
    assert.equal(unapproved.state, 'failed_before_dispatch'); assert.equal(f.demo.stats.submissions, 0);
    const approved = await f.host.control.approveSubmit(auth, binding);
    const submit = { ...binding, approval_id: approved.approval_id, request_id: randomUUID() };
    const submitted = await f.host.execution.submit(auth, submit);
    assert.equal(submitted.state, 'succeeded');
    assert.equal(f.demo.stats.submissions, 1); assert.equal(f.demo.stats.authenticated, 1);
    assert.equal(JSON.stringify(submitted).includes(syntheticPassword), false);
    const replay = await f.host.execution.submit(auth, submit);
    assert.deepEqual(replay, submitted); assert.equal(f.demo.stats.submissions, 1);
    f.restartJournal();
    assert.deepEqual(await f.host.execution.submit(auth, submit), submitted);
    assert.equal(f.demo.stats.submissions, 1);
    await rejectsCode(f.host.execution.fill(auth, request), 'browser_session_invalid');
    await page.waitForURL(`${f.demo.origin}/session`, { waitUntil: 'load' });
    const account = await page.goto(`${f.demo.origin}/account`);
    assert.equal(account?.status(), 200); assert.equal(f.demo.stats.sessionVisits, 1);
    await page.context().clearCookies();
    assert.equal((await page.goto(`${f.demo.origin}/account`))?.status(), 401);
  } finally { await f.close(); }
});

test('handle bound to principal, host, context, exact origins and strict request schema; caller identity cannot register a page', async () => {
  const f = await fixture();
  const other = await fixture();
  try {
    const first = await f.open(), second = await f.open();
    await rejectsCode(f.host.execution.fill({ ...auth, principal_id: 'other-principal' }, first.request), 'browser_session_invalid');
    await rejectsCode(other.host.execution.fill(auth, first.request), 'browser_session_invalid');
    await rejectsCode(f.host.execution.fill(auth, { ...first.request, browser_session_id: second.binding.browser_session_id }), 'approval_invalid');
    await rejectsCode(f.host.execution.fill(auth, { ...first.request, origin: f.demo.origin } as never), 'browser_target_invalid');
    await rejectsCode(f.host.execution.fill(auth, { ...first.request, selector: '#password' } as never), 'browser_target_invalid');
    await rejectsCode(f.host.execution.fill(auth, { ...first.request, browser_session_id: randomUUID() }), 'browser_session_invalid');
    f.credential.origin = other.demo.origin;
    await rejectsCode(f.host.execution.fill(auth, first.request), 'approval_invalid');
    assert.equal(f.state.reads, 0); assert.equal(f.demo.stats.submissions, 0);
  } finally { await f.close(); await other.close(); }
});

test('same-origin reload, navigation, fragment navigation and document.open replacement invalidate original document handles', async t => {
  for (const change of ['reload', 'navigate', 'fragment', 'document.open'] as const) await t.test(change, async () => {
    const f = await fixture();
    try {
      const { request, page } = await f.open();
      if (change === 'reload') await page.reload();
      if (change === 'navigate') await page.goto(`${f.demo.origin}/next`);
      if (change === 'fragment') await page.goto(`${f.demo.origin}/login#new`);
      if (change === 'document.open') await page.evaluate(() => { document.open(); document.write('<!doctype html><title>Replacement document</title><form id="login" action="/session" method="post"><input id="username" name="username"><input id="password" name="password" type="password"></form>'); document.close(); });
      await rejectsCode(f.host.execution.fill(auth, request), 'browser_session_invalid', 'browser_target_invalid');
      assert.equal(f.state.reads, 0); assert.equal(f.demo.stats.submissions, 0);
    } finally { await f.close(); }
  });
});

test('same-origin frame reload/replacement/removal and unrelated frame tree changes invalidate handles', async t => {
  for (const change of ['reload-frame', 'replace-frame', 'remove-frame', 'add-frame'] as const) await t.test(change, async () => {
    const f = await fixture({ rules: (_r, frame) => [frame] });
    try {
      const { request, page } = await f.open();
      if (change === 'reload-frame') await page.frames().find(frame => frame.name() === 'login-frame')!.goto(`${f.demo.origin}/next`);
      if (change === 'replace-frame') { await page.locator('iframe').evaluate(node => { const frame = node.cloneNode() as HTMLIFrameElement; node.replaceWith(frame); }); await page.waitForLoadState('load'); }
      if (change === 'remove-frame') await page.locator('iframe').evaluate(node => node.remove());
      if (change === 'add-frame') { await page.evaluate(() => { const frame = document.createElement('iframe'); frame.src = '/frame'; document.body.append(frame); }); await page.waitForTimeout(30); }
      await rejectsCode(f.host.execution.fill(auth, request), 'browser_session_invalid', 'browser_target_invalid');
      assert.equal(f.state.reads, 0);
    } finally { await f.close(); }
  });
});

test('approved same-origin frame fills successfully without submit; cross-origin frame refused despite caller matching top origin', async () => {
  const f = await fixture({ rules: (_r, frame) => [frame] });
  try {
    const current = await f.open();
    assert.equal((await f.host.execution.fill(auth, current.request)).status, 'filled');
    assert.equal(f.demo.stats.submissions, 0);
    const other = await f.open();
    await other.page.locator('iframe').evaluate(node => { (node as HTMLIFrameElement).src = 'http://127.0.0.1:9/frame'; });
    await rejectsCode(f.host.execution.fill(auth, other.request), 'browser_session_invalid', 'browser_target_invalid');
    assert.equal(f.state.reads, 1);
  } finally { await f.close(); }
});

test('fixed action, target, field associations, duplicate selectors and main-world prototype tampering cannot bypass trusted rules', async t => {
  for (const change of ['action', 'target', 'duplicate', 'field-type', 'prototype'] as const) await t.test(change, async () => {
    const f = await fixture();
    try {
      const { page, request } = await f.open();
      if (change === 'action') await page.locator('form').evaluate(node => { (node as HTMLFormElement).action = 'http://127.0.0.1:9/session'; });
      if (change === 'target') await page.locator('form').evaluate(node => { (node as HTMLFormElement).target = '_blank'; });
      if (change === 'duplicate') await page.locator('#password').evaluate(node => node.after(node.cloneNode()));
      if (change === 'field-type') await page.locator('#password').evaluate(node => { (node as HTMLInputElement).type = 'text'; });
      if (change === 'prototype') await page.evaluate(() => { Object.defineProperty(HTMLInputElement.prototype, 'value', { set() { throw new Error('main_world_poison'); } }); HTMLFormElement.prototype.submit = () => { throw new Error('main_world_poison'); }; });
      if (change === 'prototype') assert.deepEqual(await f.host.execution.fill(auth, request), { status: 'filled', submitted: false });
      else { await rejectsCode(f.host.execution.fill(auth, request), 'browser_session_invalid', 'browser_target_invalid'); assert.equal(f.state.reads, 0); }
      assert.equal(f.demo.stats.submissions, 0);
    } finally { await f.close(); }
  });
});

test('five-minute handle TTL, sixty-second approval TTL, record version/status/policy, lock/epoch and closed contexts reject without secret dispatch', async t => {
  for (const change of ['handle-ttl', 'approval-ttl', 'record', 'status', 'status-roundtrip', 'policy', 'lock', 'epoch', 'context-close'] as const) await t.test(change, async () => {
    const f = await fixture();
    try {
      const { request, page } = await f.open();
      if (change === 'handle-ttl') f.state.time += BROWSER_HANDLE_TTL_MS;
      if (change === 'approval-ttl') f.state.time += BROWSER_APPROVAL_TTL_MS;
      if (change === 'record') f.credential.record_version++;
      if (change === 'status') f.credential.status = 'revoked';
      if (change === 'status-roundtrip') f.credential.status_version += 2; // paused/revoked then active cannot resurrect an old approval
      if (change === 'policy') f.state.allowed = false;
      if (change === 'lock') f.state.unlocked = false;
      if (change === 'epoch') f.state.epoch++;
      if (change === 'context-close') await page.context().close();
      await rejectsCode(f.host.execution.fill(auth, request), 'browser_session_invalid', 'approval_invalid', 'record_changed', 'forbidden', 'vault_locked');
      assert.equal(f.state.reads, 0); assert.equal(f.demo.stats.submissions, 0);
    } finally { await f.close(); }
  });
});

test('same-origin navigation between approval/dispatch and actual secret callback refuses original handle; cannot refill after ambiguous write', async () => {
  const f = await fixture();
  try {
    const { page, request } = await f.open();
    f.state.pauseBeforePassword = async () => { await page.reload(); };
    await rejectsCode(f.host.execution.fill(auth, request), 'browser_session_invalid', 'browser_target_invalid');
    assert.equal(f.demo.stats.submissions, 0);
    await rejectsCode(f.host.execution.fill(auth, request), 'browser_session_invalid');
  } finally { await f.close(); }
});

test('submit approval is distinct, single-use, expires, and binds record plus document plus same-origin action', async t => {
  for (const change of ['expires', 'record', 'reload', 'action', 'replay-new-ticket'] as const) await t.test(change, async () => {
    const f = await fixture();
    try {
      const { binding, request, page } = await f.open();
      await f.host.execution.fill(auth, request);
      const approved = await f.host.control.approveSubmit(auth, binding);
      const submit = { ...binding, approval_id: approved.approval_id, request_id: randomUUID() };
      if (change === 'expires') f.state.time += BROWSER_APPROVAL_TTL_MS;
      if (change === 'record') f.credential.record_version++;
      if (change === 'reload') await page.reload();
      if (change === 'action') await page.locator('form').evaluate(node => { (node as HTMLFormElement).action = '/other'; });
      if (change === 'record') await rejectsCode(f.host.execution.submit(auth, submit), 'record_changed');
      else {
        const result = await f.host.execution.submit(auth, submit);
        assert.equal(result.state, change === 'replay-new-ticket' ? 'succeeded' : 'failed_before_dispatch');
        if (change === 'replay-new-ticket') {
          const replay = await f.host.execution.submit(auth, { ...submit, request_id: randomUUID() });
          assert.equal(replay.state, 'failed_before_dispatch');
        }
      }
      assert.equal(f.demo.stats.submissions, change === 'replay-new-ticket' ? 1 : 0);
    } finally { await f.close(); }
  });
});

test('upstream accepted then disconnected returns outcome_unknown; same ticket replay and new ticket after journal restart never resend', async () => {
  const f = await fixture({ submitTimeoutMs: 150 });
  try {
    const { binding, request } = await f.open();
    await f.host.execution.fill(auth, request);
    const approved = await f.host.control.approveSubmit(auth, binding);
    const submit = { ...binding, approval_id: approved.approval_id, request_id: randomUUID() };
    f.demo.setSubmitBehavior('disconnect');
    const result = await f.host.execution.submit(auth, submit);
    assert.equal(result.state, 'outcome_unknown');
    assert.equal(f.demo.stats.submissions, 1); assert.equal(f.demo.stats.authenticated, 1);
    assert.deepEqual(await f.host.execution.submit(auth, submit), result);
    f.restartJournal();
    assert.deepEqual(await f.host.execution.submit(auth, submit), result);
    await assert.rejects(f.host.execution.submit(auth, { ...submit, request_id: randomUUID() }), /operation_conflict/);
    assert.equal(f.demo.stats.submissions, 1);
    const db = fs.readFileSync(path.join(f.directory, 'operations.sqlite'));
    assert.equal(db.includes(Buffer.from(syntheticPassword)), false);
    assert.equal(JSON.stringify(result).includes(syntheticPassword), false);
  } finally { await f.close(); }
});

test('committed login followed by HTTP 500 remains outcome_unknown and blocks replay/new-ticket dispatch', async () => {
  const f = await fixture();
  try {
    const { binding, request, page } = await f.open();
    await f.host.execution.fill(auth, request);
    const approved = await f.host.control.approveSubmit(auth, binding);
    const submit = { ...binding, approval_id: approved.approval_id, request_id: randomUUID() };
    f.demo.setSubmitBehavior('commit_then_500');
    const result = await f.host.execution.submit(auth, submit);
    assert.equal(result.state, 'outcome_unknown');
    assert.deepEqual(result.result, { status: 'submitted', http_status: 500 });
    assert.equal(f.demo.stats.submissions, 1); assert.equal(f.demo.stats.authenticated, 1);
    assert.deepEqual(await f.host.execution.submit(auth, submit), result);
    f.restartJournal();
    assert.deepEqual(await f.host.execution.submit(auth, submit), result);
    await assert.rejects(f.host.execution.submit(auth, { ...submit, request_id: randomUUID() }), /operation_conflict/);
    assert.equal(f.demo.stats.submissions, 1);
    await page.waitForURL(`${f.demo.origin}/session`, { waitUntil: 'load' });
    assert.equal((await page.goto(`${f.demo.origin}/account`))?.status(), 200);
    assert.equal(f.demo.stats.sessionVisits, 1);
    assert.equal(JSON.stringify(result).includes(syntheticPassword), false);
  } finally { await f.close(); }
});

test('approval single-use remains atomic under concurrent fills; TTL and policy are checked again before the final write', async t => {
  await t.test('concurrent fill', async () => {
    const f = await fixture();
    try {
      const { request } = await f.open();
      const attempts = await Promise.allSettled([f.host.execution.fill(auth, request), f.host.execution.fill(auth, request)]);
      assert.equal(attempts.filter(attempt => attempt.status === 'fulfilled').length, 1);
      assert.equal(f.state.reads, 1); assert.equal(f.demo.stats.submissions, 0);
    } finally { await f.close(); }
  });
  for (const change of ['approval-ttl', 'policy', 'epoch'] as const) await t.test(change, async () => {
    const f = await fixture();
    try {
      const { request } = await f.open();
      f.state.pauseBeforePassword = async () => {
        if (change === 'approval-ttl') f.state.time += BROWSER_APPROVAL_TTL_MS;
        if (change === 'policy') f.state.allowed = false;
        if (change === 'epoch') f.state.epoch++;
      };
      await rejectsCode(f.host.execution.fill(auth, request), 'approval_invalid', 'forbidden', 'browser_session_invalid');
      assert.equal(f.demo.stats.submissions, 0);
    } finally { await f.close(); }
  });
});

test('actual encrypted Vault SQLite journal + signed tickets + browser mapper persist unknown submit across full Vault and host restart', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-browser-core-'));
  const demo = await startSyntheticBrowserDemo({ username: syntheticUsername, password: syntheticPassword, port: 43122 });
  const passphrase = 'synthetic browser core passphrase';
  let vault: Vault | undefined;
  let host: ReturnType<typeof createControlledBrowserHost> | undefined;
  try {
    await initialize(directory, passphrase);
    vault = new Vault(directory); await vault.unlock(passphrase);
    const manager: Authority = { ...auth, principal_id: 'trusted-browser-manager', client_id: 'trusted-browser-manager', session_id: 'synthetic-admin-session' };
    const payload: SavePayload = { mode: 'create', label: 'Synthetic browser login', service_id: 'synthetic-login', credential_type: 'password', account_alias: syntheticUsername, secret: syntheticPassword,
      origin: demo.origin, environment: 'local', granted_operations: ['browser_fill', 'login_submit'] };
    const draft = vault.createDraft(manager, payload);
    const approved = vault.approveDraft(manager, draft.draft_id, draft.draft_version);
    const credential = vault.saveApproved(manager, { request_id: vault.prepareRequest(manager, 'save_connection'), draft_id: draft.draft_id, draft_version: draft.draft_version, approval_token: approved.approval_token, payload });
    const makeHost = () => {
      const currentVault = vault!;
      return createControlledBrowserHost({ browser, rules: [demo.rules], submitTimeoutMs: 150,
        ...browserVaultCapabilities(currentVault, (requestAuth, metadata, operation) => requestAuth.principal_id === auth.principal_id && currentVault.get(metadata.id).granted_operations.includes(operation)) });
    };
    host = makeHost();
    const session = await host.execution.openSession(auth, demo.rules.id);
    const binding = { browser_session_id: session.browser_session_id, connection_id: credential.id, expected_record_version: credential.record_version };
    const fill = await host.control.approveFill(auth, binding);
    await host.execution.fill(auth, { ...binding, approval_id: fill.approval_id });
    assert.equal(demo.stats.submissions, 0);
    const approval = await host.control.approveSubmit(auth, binding);
    const request = { ...binding, approval_id: approval.approval_id, request_id: vault.prepareRequest(auth, 'login_submit') };
    demo.setSubmitBehavior('disconnect');
    const unknown = await host.execution.submit(auth, request);
    assert.equal(unknown.state, 'outcome_unknown'); assert.equal(demo.stats.authenticated, 1);
    assert.equal(vault.getOperationStatus(auth, request.request_id, 'login_submit').state, 'outcome_unknown');
    await host.control.close(); host = undefined;
    vault.close(); vault = new Vault(directory); await vault.unlock(passphrase);
    host = makeHost();
    assert.deepEqual(await host.execution.submit(auth, request), unknown);
    await assert.rejects(host.execution.submit(auth, { ...request, request_id: vault.prepareRequest(auth, 'login_submit') }), /operation_reconciliation_required/);
    await assert.rejects(host.execution.submit(auth, { ...request, approval_id: randomUUID() }), /idempotency_conflict/);
    await assert.rejects(host.execution.submit(auth, { ...request, request_id: randomUUID() }), /request_invalid/);
    assert.equal(demo.stats.submissions, 1);
    const newSession = await host.execution.openSession(auth, demo.rules.id);
    const newBinding = { ...binding, browser_session_id: newSession.browser_session_id };
    const newApproval = await host.control.approveFill(auth, newBinding);
    vault.lock();
    await rejectsCode(host.execution.fill(auth, { ...newBinding, approval_id: newApproval.approval_id }), 'vault_locked');
    await vault.unlock(passphrase);
    await rejectsCode(host.execution.fill(auth, { ...newBinding, approval_id: newApproval.approval_id }), 'browser_session_invalid');
    const databaseBytes = fs.readFileSync(path.join(directory, 'vault.sqlite'));
    assert.equal(databaseBytes.includes(Buffer.from(syntheticPassword)), false);
    assert.equal(JSON.stringify(unknown).includes(syntheticPassword), false);
  } finally { await host?.control.close(); vault?.close(); await demo.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test('real same-origin framed submit uses the session-bound second rule and dispatch denial terminates accepted without network', async () => {
  const f = await fixture({ rules: (rule, frame) => [rule, frame] });
  try {
    const current = await f.open(f.rules[1]!.id);
    await f.host.execution.fill(auth, current.request);
    const approved = await f.host.control.approveSubmit(auth, current.binding);
    const request = { ...current.binding, approval_id: approved.approval_id, request_id: randomUUID() };
    f.state.dispatchDenied = true;
    const denied = await f.host.execution.submit(auth, request);
    assert.equal(denied.state, 'failed_before_dispatch'); assert.equal(f.demo.stats.submissions, 0);
    assert.deepEqual(await f.host.execution.submit(auth, request), denied);
    f.state.dispatchDenied = false;
    const next = await f.host.control.approveSubmit(auth, current.binding);
    const success = await f.host.execution.submit(auth, { ...current.binding, approval_id: next.approval_id, request_id: randomUUID() });
    assert.equal(success.state, 'succeeded'); assert.equal(f.demo.stats.authenticated, 1);
  } finally { await f.close(); }
});

test('idle pruning closes expired password contexts and epoch/record changes; stale owner close grants no browser action', async t => {
  for (const change of ['expired', 'epoch', 'record', 'status', 'policy', 'stale-close'] as const) await t.test(change, async () => {
    const f = await fixture({ cleanupIntervalMs: 20 });
    try {
      const current = await f.open();
      await f.host.execution.fill(auth, current.request);
      const closed = current.page.waitForEvent('close', { timeout: 2_000 });
      if (change === 'expired' || change === 'stale-close') f.state.time += BROWSER_HANDLE_TTL_MS;
      if (change === 'epoch') f.state.epoch++;
      if (change === 'record') f.credential.record_version++;
      if (change === 'status') f.credential.status_version++;
      if (change === 'policy') f.state.allowed = false;
      if (change === 'stale-close') await f.host.control.closeSession(auth, current.binding.browser_session_id);
      await closed;
      assert.equal(current.page.isClosed(), true);
      await f.host.control.closeSession(auth, current.binding.browser_session_id);
      await rejectsCode(f.host.execution.fill(auth, current.request), 'browser_session_invalid');
    } finally { await f.close(); }
  });
});

test('host session and approval caps bound allocation; expired approvals free capacity and closed hosts detach shared-browser listeners', async () => {
  const baselineContexts = browser.contexts().length;
  const listenerCount = () => (browser as unknown as { listenerCount(event: string): number }).listenerCount('disconnected');
  const baselineListeners = listenerCount();
  const f = await fixture({ maxSessions: 2, maxApprovals: 2 });
  try {
    const first = await f.open(), second = await f.open();
    assert.equal(browser.contexts().length, baselineContexts + 2);
    await rejectsCode(f.host.execution.openSession(auth, f.rules[0]!.id), 'unsupported');
    await rejectsCode(f.host.control.approveFill(auth, first.binding), 'unsupported');
    await assert.rejects(f.host.control.closeSession({ ...auth, principal_id: 'other' }, first.binding.browser_session_id), /forbidden/);
    assert.equal(first.page.isClosed(), false);
    f.state.time += BROWSER_APPROVAL_TTL_MS;
    await f.host.control.prune();
    await f.host.control.approveFill(auth, first.binding);
    await f.host.control.closeSession(auth, second.binding.browser_session_id);
    const next = await f.open();
    assert.equal(next.page.isClosed(), false);
  } finally { await f.close(); }
  assert.equal(browser.contexts().length, baselineContexts);
  assert.equal(listenerCount(), baselineListeners);
  for (let iteration = 0; iteration < 3; iteration++) { const temporary = await fixture(); await temporary.close(); }
  assert.equal(listenerCount(), baselineListeners);
});

test('unsupported host/rules never downgrade to caller URLs; trusted static rules copied immutably', async () => {
  const f = await fixture();
  try {
    assert.throws(() => createControlledBrowserHost({ browser, capabilities: f.capabilities, journal: {} as BrowserSubmitJournal, rules: [{ ...f.rules[0]!, origin: 'http://example.test', syntheticLoopback: false }] }), BrowserHostError);
    await rejectsCode(f.host.execution.openSession(auth, 'caller-defined-site'), 'unsupported');
    const current = await f.open();
    (f.rules[0]! as { passwordSelector: string }).passwordSelector = '#caller-mutated';
    assert.equal((await f.host.execution.fill(auth, current.request)).status, 'filled');
  } finally { await f.close(); }
});
