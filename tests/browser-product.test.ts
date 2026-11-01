import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { chromium } from 'playwright-core';
import { createBrowserProduct, type BrowserProduct } from '../src/browser-product.js';
import { BROWSER_APPROVAL_TTL_MS, BROWSER_HANDLE_TTL_MS, BrowserHostError, browserVaultCapabilities, createControlledBrowserHost } from '../src/browser.js';
import { startSyntheticBrowserDemo } from '../src/browser-demo.js';
import { initialize, Vault } from '../src/vault.js';
import { createServer } from '../src/server.js';
import type { Authority, SavePayload } from '../src/contracts.js';

const manager: Authority = { owner_id: 'local', principal_id: 'admin', client_id: 'management', session_id: 'synthetic-admin-session' };
const execution: Authority = { owner_id: 'local', principal_id: 'execution:local', client_id: 'execution' };
const other: Authority = { ...execution, principal_id: 'execution:other' };
const config = { enabled: true, executablePath: '/usr/bin/chromium', headless: true };
const passphrase = 'synthetic product test passphrase';
async function fixture(enabled = true) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'browser-product-'));
  let vault: Vault | undefined, product: BrowserProduct | undefined;
  const username = 'synthetic_product_account', password = `synthetic_${randomUUID()}`;
  const demo = await startSyntheticBrowserDemo({ username, password, port: 43122 });
  const clock = { time: Date.now() };
  try {
    await initialize(directory, passphrase);
    vault = new Vault(directory, { clock: () => clock.time });
    await vault.unlock(passphrase);
    const payload: SavePayload = { mode: 'create', label: 'Synthetic product account', service_id: 'synthetic-login', credential_type: 'password', account_alias: username,
      origin: demo.origin, environment: 'local', secret: password, granted_operations: ['browser_fill', 'login_submit'] };
    const draft = vault.createDraft(manager, payload), approval = vault.approveDraft(manager, draft.draft_id, draft.draft_version);
    const credential = vault.saveApproved(manager, { request_id: vault.prepareRequest(manager, 'save_connection'), draft_id: draft.draft_id,
      draft_version: draft.draft_version, approval_token: approval.approval_token, payload });
    product = await createBrowserProduct({ vault, config: enabled ? config : undefined, now: () => clock.time });
    const currentVault = vault, currentProduct = product;
    return { vault: currentVault, product: currentProduct, credential, password, demo, clock,
      async request(operation: 'browser_fill' | 'login_submit', browser_session_id?: string) {
        const session = browser_session_id ? { browser_session_id } : await currentProduct.execution.openSession(execution, { site_id: 'synthetic-login' });
        return currentProduct.execution.requestApproval(execution, { browser_session_id: session.browser_session_id, connection_id: credential.id, expected_record_version: credential.record_version, operation });
      },
      async close() { await currentProduct.close(); currentVault.close(); await demo.close(); fs.rmSync(directory, { recursive: true, force: true }); },
    };
  } catch (error) { await product?.close(); vault?.close(); await demo.close(); fs.rmSync(directory, { recursive: true, force: true }); throw error; }
}
function rejected(promise: Promise<unknown>, ...codes: string[]) { return assert.rejects(promise, e => e instanceof BrowserHostError && codes.includes(e.code)); }

test('unconfigured browser product reports unsupported and never creates a fake session', async () => {
  const f = await fixture(false);
  try {
    assert.deepEqual(f.product.execution.sites(execution), { supported: false, reason: 'unsupported', sites: [] });
    await rejected(f.product.execution.openSession(execution, { site_id: 'synthetic-login' }), 'unsupported');
    await rejected(f.product.management.pending(manager), 'unsupported');
    await assert.rejects(createBrowserProduct({ vault: f.vault, config: { enabled: true } }), /site_rules_invalid/);
    await assert.rejects(createBrowserProduct({ vault: f.vault, config: { ...config, executablePath: 'chromium' } }), /site_rules_invalid/);
  } finally { await f.close(); }
});

test('real product vault and Chromium coordinate manager-only fill and separate submit; fixed status reuses the retained context', async () => {
  const f = await fixture();
  try {
    assert.equal(f.product.execution.sites(execution).supported, true);
    const pending = await f.request('browser_fill');
    assert.deepEqual(await f.product.management.pending(manager), [pending]);
    assert.equal(pending.principal_id, execution.principal_id);
    assert.equal(pending.origin, f.demo.origin);
    assert.equal(pending.operation, 'browser_fill');
    assert.equal(pending.expected_record_version, f.credential.record_version);
    assert.equal(JSON.stringify(pending).includes(f.password), false);
    assert.equal('approval_id' in pending, false);
    await rejected(f.product.management.approve(execution, pending.pending_id), 'forbidden');
    await rejected(f.product.management.approve({ ...manager, session_id: undefined }, pending.pending_id), 'forbidden');
    await rejected(f.product.execution.fill(execution, { pending_id: pending.pending_id }), 'approval_invalid');
    await rejected(f.product.execution.approvalStatus(other, { pending_id: pending.pending_id }), 'approval_invalid');
    await rejected(f.product.execution.sessionStatus(other, { browser_session_id: pending.browser_session_id }), 'browser_session_invalid');
    await rejected(f.product.execution.submit(execution, { pending_id: pending.pending_id, browser_session_id: pending.browser_session_id, connection_id: pending.connection_id, expected_record_version: pending.expected_record_version, request_id: f.vault.prepareRequest(execution, 'login_submit') }), 'approval_invalid');
    const approved = await f.product.management.approve(manager, pending.pending_id);
    assert.equal(approved.state, 'approved');
    assert.equal((await f.product.execution.approvalStatus(execution, { pending_id: pending.pending_id })).state, 'approved');
    assert.deepEqual(await f.product.execution.fill(execution, { pending_id: pending.pending_id }), { status: 'filled', submitted: false });
    assert.equal(f.demo.stats.submissions, 0);
    await rejected(f.product.execution.fill(execution, { pending_id: pending.pending_id }), 'approval_invalid');
    assert.equal((await f.product.execution.sessionStatus(execution, { browser_session_id: pending.browser_session_id })).status, 'filled');
    const submit = await f.request('login_submit', pending.browser_session_id);
    const request_id = f.vault.prepareRequest(execution, 'login_submit');
    await rejected(f.product.execution.submit(execution, { pending_id: submit.pending_id, browser_session_id: submit.browser_session_id, connection_id: submit.connection_id, expected_record_version: submit.expected_record_version, request_id }), 'approval_invalid');
    await f.product.management.approve(manager, submit.pending_id);
    const result = await f.product.execution.submit(execution, { pending_id: submit.pending_id, browser_session_id: submit.browser_session_id, connection_id: submit.connection_id, expected_record_version: submit.expected_record_version, request_id });
    assert.equal(result.state, 'succeeded');
    assert.equal(f.demo.stats.authenticated, 1);
    assert.deepEqual(await f.product.execution.submit(execution, { pending_id: submit.pending_id, browser_session_id: submit.browser_session_id, connection_id: submit.connection_id, expected_record_version: submit.expected_record_version, request_id }), result);
    assert.equal(f.demo.stats.submissions, 1);
    const status = await f.product.execution.sessionStatus(execution, { browser_session_id: pending.browser_session_id });
    assert.equal(status.status, 'session_reused'); assert.equal(status.authenticated, true); assert.equal(status.http_status, 200);
    assert.equal(f.demo.stats.sessionVisits, 1);
    assert.equal(status.expires_at, (await f.product.execution.sessionStatus(execution, { browser_session_id: pending.browser_session_id })).expires_at);
    assert.equal(JSON.stringify({ result, status }).includes(f.password), false);
    f.clock.time += BROWSER_APPROVAL_TTL_MS;
    assert.deepEqual(await f.product.execution.submit(execution, { pending_id: submit.pending_id, browser_session_id: submit.browser_session_id,
      connection_id: submit.connection_id, expected_record_version: submit.expected_record_version, request_id }), result);
    await assert.rejects(f.product.execution.submit(execution, { pending_id: submit.pending_id, browser_session_id: randomUUID(), connection_id: submit.connection_id,
      expected_record_version: submit.expected_record_version, request_id }), /idempotency_conflict/);
    await rejected(f.product.execution.requestApproval(execution, { browser_session_id: pending.browser_session_id, connection_id: f.credential.id, expected_record_version: 1, operation: 'browser_fill' }), 'approval_invalid');
    f.vault.setStatus(manager, f.credential.id, 'paused', f.credential.status_version);
    await rejected(f.product.execution.sessionStatus(execution, { browser_session_id: pending.browser_session_id }), 'forbidden', 'browser_session_invalid');
  } finally { await f.close(); }
});

test('product requests reject arbitrary targets, impersonation and executable input', async () => {
  const f = await fixture();
  try {
    await rejected(f.product.execution.openSession(manager, { site_id: 'synthetic-login' }), 'forbidden');
    await rejected(f.product.execution.openSession(execution, { site_id: 'synthetic-login', url: 'http://127.0.0.1:1/' }), 'browser_target_invalid');
    const pending = await f.request('browser_fill');
    for (const extra of [{ selector: '#password' }, { script: 'document.cookie' }, { principal_id: 'admin' }, { approval_id: randomUUID() }]) {
      await rejected(f.product.execution.fill(execution, { pending_id: pending.pending_id, ...extra }), 'browser_target_invalid');
    }
    await rejected(f.product.execution.sessionStatus(execution, { browser_session_id: pending.browser_session_id, path: '/arbitrary' }), 'browser_target_invalid');
    await rejected(f.product.execution.requestApproval(execution, { browser_session_id: pending.browser_session_id, connection_id: f.credential.id, expected_record_version: 1, operation: 'browser_fill', principal_id: 'admin' }), 'browser_target_invalid');
  } finally { await f.close(); }
});

test('pending cards bind original record status, handle TTL, approval TTL and epoch', async t => {
  const f = await fixture();
  try {
    await t.test('status changes invalidate pending cards before management can approve', async () => {
      const pending = await f.request('browser_fill');
      let metadata = f.vault.setStatus(manager, f.credential.id, 'paused', f.credential.status_version);
      f.vault.setStatus(manager, f.credential.id, 'active', metadata.status_version);
      await rejected(f.product.management.approve(manager, pending.pending_id), 'record_changed');
      assert.deepEqual(await f.product.management.pending(manager), []);
    });
    await t.test('approval expires without renewing the document handle', async () => {
      const pending = await f.request('browser_fill');
      await f.product.management.approve(manager, pending.pending_id);
      f.clock.time += BROWSER_APPROVAL_TTL_MS;
      await rejected(f.product.execution.fill(execution, { pending_id: pending.pending_id }), 'approval_invalid');
    });
    await t.test('five-minute handle expires exactly', async () => {
      const session = await f.product.execution.openSession(execution, { site_id: 'synthetic-login' });
      f.clock.time += BROWSER_HANDLE_TTL_MS;
      await rejected(f.product.execution.sessionStatus(execution, { browser_session_id: session.browser_session_id }), 'browser_session_invalid');
    });
    await t.test('lock and re-unlock invalidate old approvals and retained contexts', async () => {
      const pending = await f.request('browser_fill');
      await f.product.management.approve(manager, pending.pending_id);
      f.vault.lock();
      await rejected(f.product.execution.fill(execution, { pending_id: pending.pending_id }), 'vault_locked');
      await f.vault.unlock(passphrase);
      await rejected(f.product.execution.fill(execution, { pending_id: pending.pending_id }), 'approval_invalid');
      await rejected(f.product.execution.sessionStatus(execution, { browser_session_id: pending.browser_session_id }), 'browser_session_invalid');
    });
  } finally { await f.close(); }
});

test('submit unknown result remains replayable after full product and vault restart without another dispatch', async () => {
  const f = await fixture();
  let restarted: BrowserProduct | undefined, restartedVault: Vault | undefined;
  try {
    const fill = await f.request('browser_fill');
    await f.product.management.approve(manager, fill.pending_id);
    await f.product.execution.fill(execution, { pending_id: fill.pending_id });
    const submit = await f.request('login_submit', fill.browser_session_id);
    await f.product.management.approve(manager, submit.pending_id);
    f.demo.setSubmitBehavior('commit_then_500');
    const request = { pending_id: submit.pending_id, browser_session_id: submit.browser_session_id, connection_id: submit.connection_id,
      expected_record_version: submit.expected_record_version, request_id: f.vault.prepareRequest(execution, 'login_submit') };
    const result = await f.product.execution.submit(execution, request);
    assert.equal(result.state, 'outcome_unknown'); assert.equal(f.demo.stats.submissions, 1);
    await f.product.close();
    f.vault.close();
    restartedVault = new Vault(f.vault.directory, { clock: () => f.clock.time });
    await restartedVault.unlock(passphrase);
    restarted = await createBrowserProduct({ vault: restartedVault, config, now: () => f.clock.time });
    assert.deepEqual(await restarted.execution.submit(execution, request), result);
    assert.equal(f.demo.stats.submissions, 1);
    await assert.rejects(restarted.execution.submit(other, request), /request_scope_denied/);
    await rejected(restarted.execution.sessionStatus(execution, { browser_session_id: submit.browser_session_id }), 'browser_session_invalid');
    const newSession = await restarted.execution.openSession(execution, { site_id: 'synthetic-login' });
    const newFill = await restarted.execution.requestApproval(execution, { browser_session_id: newSession.browser_session_id, connection_id: submit.connection_id,
      expected_record_version: submit.expected_record_version, operation: 'browser_fill' });
    await restarted.management.approve(manager, newFill.pending_id); await restarted.execution.fill(execution, { pending_id: newFill.pending_id });
    const newSubmit = await restarted.execution.requestApproval(execution, { browser_session_id: newSession.browser_session_id, connection_id: submit.connection_id,
      expected_record_version: submit.expected_record_version, operation: 'login_submit' });
    await restarted.management.approve(manager, newSubmit.pending_id);
    await assert.rejects(restarted.execution.submit(execution, { pending_id: newSubmit.pending_id, browser_session_id: newSubmit.browser_session_id, connection_id: newSubmit.connection_id,
      expected_record_version: newSubmit.expected_record_version, request_id: restartedVault.prepareRequest(execution, 'login_submit') }), /operation_reconciliation_required/);
    assert.equal(f.demo.stats.submissions, 1);
  } finally {
    await restarted?.close();
    if (restartedVault) { restartedVault.close(); await f.demo.close(); fs.rmSync(f.vault.directory, { recursive: true, force: true }); }
    else await f.close();
  }
});

test('actual server browser routes bind execution credentials, manager CSRF, separate approvals and lock invalidation', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'browser-product-routes-'));
  const password = `synthetic_${randomUUID()}`, username = 'synthetic_http_account';
  const demo = await startSyntheticBrowserDemo({ username, password, port: 43122 });
  await initialize(directory, passphrase);
  const server = await createServer(directory, 0, { productConfig: { mode: 'production', browser: config } });
  const origin = server.origin, host = new URL(origin).host;
  let cookie = '', csrf = '';
  const bearer = { authorization: `Bearer ${fs.readFileSync(path.join(directory, 'execution.key'), 'utf8').trim()}` };
  const manage = async (url: string, body?: unknown, extra: Record<string, string> = {}) => {
    const response = await server.app.inject({ method: body === undefined ? 'GET' : 'POST', url,
      headers: { host, ...(cookie ? { cookie } : {}), ...(body === undefined ? {} : { origin, 'x-csrf-token': csrf, 'content-type': 'application/json' }), ...extra },
      ...(body === undefined ? {} : { payload: body as any }) });
    const set = response.headers['set-cookie']; if (set) cookie = (Array.isArray(set) ? set[0]! : set).split(';')[0]!;
    if (response.json().csrf) csrf = response.json().csrf;
    return response;
  };
  const execute = (url: string, body?: unknown, extra: Record<string, string> = {}) => server.app.inject({ method: body === undefined ? 'GET' : 'POST', url,
    headers: { host, ...bearer, ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...extra }, ...(body === undefined ? {} : { payload: body as any }) });
  try {
    await manage('/management/session'); await manage('/management/login', { passphrase }); await manage('/management/unlock', { passphrase });
    const proposed = await manage('/management/drafts', { mode: 'create', label: 'HTTP synthetic login', service_id: 'synthetic-login', credential_type: 'password',
      account_alias: username, secret: password, origin: demo.origin, environment: 'local', granted_operations: ['browser_fill', 'login_submit'] });
    assert.equal(proposed.statusCode, 201);
    const draft = proposed.json();
    const confirmed = await manage(`/management/drafts/${draft.draft.draft_id}/confirm`, { draft_version: draft.draft.draft_version, request_id: draft.request_id });
    assert.equal(confirmed.statusCode, 200); const credential = confirmed.json().connection;
    assert.equal((await manage('/execution/browser/session', { site_id: 'synthetic-login' })).statusCode, 403);
    assert.equal((await execute('/management/browser/pending')).statusCode, 403);
    assert.equal((await execute('/execution/browser/sites', undefined, { cookie })).statusCode, 403);
    const opened = await execute('/execution/browser/session', { site_id: 'synthetic-login' });
    assert.equal(opened.statusCode, 200); const session = opened.json();
    const binding = { browser_session_id: session.browser_session_id, connection_id: credential.id, expected_record_version: credential.record_version };
    const proposedFill = await execute('/execution/browser/request-approval', { ...binding, operation: 'browser_fill' });
    assert.equal(proposedFill.statusCode, 200); const fill = proposedFill.json();
    const listed = await manage('/management/browser/pending');
    assert.equal(listed.json().pending[0].principal_id, 'execution:local'); assert.equal(listed.json().pending[0].origin, demo.origin);
    assert.equal(listed.json().pending[0].connection_id, credential.id); assert.equal(listed.body.includes(password), false);
    assert.equal((await execute('/execution/browser/fill', { pending_id: fill.pending_id })).statusCode, 403);
    assert.equal((await manage(`/management/browser/approvals/${fill.pending_id}`, {}, { 'x-csrf-token': 'wrong' })).statusCode, 403);
    assert.equal((await execute(`/management/browser/approvals/${fill.pending_id}`, {})).statusCode, 403);
    assert.equal((await manage(`/management/browser/approvals/${fill.pending_id}`, {})).statusCode, 200);
    assert.equal((await execute('/execution/browser/fill', { pending_id: fill.pending_id })).statusCode, 200); assert.equal(demo.stats.submissions, 0);
    const proposedSubmit = await execute('/execution/browser/request-approval', { ...binding, operation: 'login_submit' });
    assert.equal(proposedSubmit.statusCode, 200); const submit = proposedSubmit.json();
    const ticket = await execute('/execution/prepare-request', { operation_name: 'login_submit' });
    const submitRequest = { ...binding, pending_id: submit.pending_id, request_id: ticket.json().request_id };
    assert.equal((await execute('/execution/browser/submit', submitRequest)).statusCode, 403);
    assert.equal((await manage(`/management/browser/approvals/${submit.pending_id}`, {})).statusCode, 200);
    const submitted = await execute('/execution/browser/submit', submitRequest);
    assert.equal(submitted.statusCode, 200); assert.equal(submitted.json().operation.state, 'succeeded'); assert.equal(demo.stats.submissions, 1);
    const status = await execute('/execution/browser/session-status', { browser_session_id: session.browser_session_id });
    assert.equal(status.statusCode, 200); assert.equal(status.json().authenticated, true); assert.equal(demo.stats.sessionVisits, 1);
    assert.equal(status.body.includes(password), false);
    await manage('/management/lock', {});
    const lockedApproval = await execute('/execution/browser/approval-status', { pending_id: submit.pending_id });
    assert.equal(lockedApproval.statusCode, 423); assert.deepEqual(lockedApproval.json(), { error: 'vault_locked' });
    assert.equal((await execute('/execution/browser/session-status', { browser_session_id: session.browser_session_id })).statusCode, 423);
    await manage('/management/unlock', { passphrase });
    assert.equal((await execute('/execution/browser/approval-status', { pending_id: submit.pending_id })).statusCode, 403);
    assert.equal((await execute('/execution/browser/session-status', { browser_session_id: session.browser_session_id })).statusCode, 403);
    assert.equal((await execute('/execution/browser/submit', submitRequest)).json().operation.state, 'succeeded');
    assert.equal(demo.stats.submissions, 1);
  } finally { await server.app.close(); await demo.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test('safe host status rejects a same-origin replacement document and its prior approval', async () => {
  const f = await fixture(false);
  const browser = await chromium.launch({ executablePath: config.executablePath, headless: true, chromiumSandbox: true });
  const host = createControlledBrowserHost({ browser, rules: [{ ...f.demo.rules, sessionPath: '/account' }], ...browserVaultCapabilities(f.vault, (_auth, credential, operation) => f.vault.get(credential.id).granted_operations.includes(operation)) });
  try {
    const session = await host.execution.openSession(execution, f.demo.rules.id);
    const binding = { browser_session_id: session.browser_session_id, connection_id: f.credential.id, expected_record_version: 1 };
    const approval = await host.control.approveFill(execution, binding);
    await host.control.page(execution, session.browser_session_id).goto(`${f.demo.origin}/next`);
    await rejected(host.execution.sessionStatus(execution, session.browser_session_id), 'browser_session_invalid');
    await rejected(host.execution.fill(execution, { ...binding, approval_id: approval.approval_id }), 'browser_session_invalid');
    assert.equal(f.demo.stats.submissions, 0);
  } finally { await host.control.close(); await browser.close(); await f.close(); }
});
