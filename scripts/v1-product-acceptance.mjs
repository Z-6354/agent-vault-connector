// Run only after the focused product tests and build are stable.
// All management changes use Chromium; all execution uses the actual CLI stdio bridge.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright-core';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { startSyntheticBrowserDemo } from '../dist/src/browser-demo.js';
import { startOAuthSimulator } from '../dist/src/oauth-simulator.js';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const evidence = path.join(project, 'docs', 'evidence');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-'));
fs.chmodSync(root, 0o700);
const directory = path.join(root, 'vault');
const cli = path.join(project, 'dist', 'src', 'cli.js');
const privateConfig = path.join(root, 'product.json');
const passphrase = 'synthetic product acceptance passphrase 2026';
const username = 'synthetic_product_acceptance_user';
const password = 'synthetic_product_acceptance_password';
const tokenLifetimeSeconds = 5;
const isolatedEnv = {
  PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
  HOME: root, TMPDIR: root, XDG_CONFIG_HOME: path.join(root, 'config'),
  XDG_CACHE_HOME: path.join(root, 'cache'), XDG_DATA_HOME: path.join(root, 'data'),
  NODE_ENV: 'test', HEADLESS: '1',
};
const started = new Date().toISOString();
const checks = [];
const oauthEvidence = {};
let stage = 'setup';
let app, browser, client, transport, demo;
const fixtures = [];
let diagnostics = '';
let protocol = '';
let pageErrors = 0;
let unexpectedNetwork = 0;
let page;

function check(condition, code) {
  if (!condition) throw new Error(code);
}
function safeText(value) {
  const text = String(value);
  check(diagnostics.length + text.length <= 1024 * 1024, 'diagnostic_limit');
  diagnostics += text;
}
async function freePort() {
  const socket = net.createServer();
  await new Promise((resolve, reject) => { socket.once('error', reject); socket.listen(0, '127.0.0.1', resolve); });
  const port = socket.address().port;
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  return port;
}
async function waitForServer(origin) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    check(app.exitCode === null && app.signalCode === null, 'server_exited');
    try {
      const response = await fetch(origin, { redirect: 'error', signal: AbortSignal.timeout(500) });
      await response.body?.cancel();
      if (response.ok) return;
    } catch { /* Wait only for the isolated CLI's listening socket. */ }
    await delay(50);
  }
  throw new Error('server_start_timeout');
}
async function initializeThroughPty() {
  // The parent feeds the synthetic passphrase over a private pipe, never argv or env.
  const python = String.raw`
import errno, json, os, pty, select, signal, sys, time
settings = json.loads(sys.stdin.read())
secret = settings['passphrase']
pid, fd = pty.fork()
if pid == 0:
    os.chdir(settings['project'])
    os.execv(settings['node'], [settings['node'], settings['cli'], 'init', '--data-dir', settings['directory'], '--synthetic', 'true'])
output = b''
stage = 0
status = None
try:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                part = os.read(fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not part:
                break
            output += part
            if len(output) > 65536:
                raise RuntimeError('pty_output_limit')
            if stage == 0 and b'New passphrase' in output:
                os.write(fd, (secret + '\r').encode())
                stage = 1
            if stage == 1 and b'Confirm passphrase' in output:
                os.write(fd, (secret + '\r').encode())
                stage = 2
        child, child_status = os.waitpid(pid, os.WNOHANG)
        if child:
            status = child_status
            break
    else:
        raise RuntimeError('pty_timeout')
    if status is None:
        _, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status) != 0 or stage != 2 or secret.encode() in output or b'Vault initialized' not in output:
        raise RuntimeError('pty_init_failed')
    print('pty_init_passed')
except BaseException:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    sys.exit(1)
finally:
    os.close(fd)
`;
  const child = spawn('/usr/bin/python3', ['-c', python], { cwd: root, env: isolatedEnv, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', chunk => { output += String(chunk); });
  child.stderr.on('data', safeText);
  const exited = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  child.stdin.end(JSON.stringify({ passphrase, project, directory, node: process.execPath, cli }));
  const code = await exited;
  check(code === 0 && output.trim() === 'pty_init_passed', 'actual_cli_pty_init_failed');
}
async function call(name, args = {}, allowError = false) {
  const result = await client.callTool({ name, arguments: args });
  const serialized = JSON.stringify(result);
  check(protocol.length + serialized.length <= 2 * 1024 * 1024, 'protocol_limit');
  protocol += serialized;
  check(Array.isArray(result.content) && result.content.length === 1 && result.content[0].type === 'text', 'unexpected_mcp_result');
  let data;
  try { data = JSON.parse(result.content[0].text); } catch { throw new Error('invalid_mcp_json'); }
  if (!allowError) check(!result.isError, 'mcp_tool_denied');
  return { denied: result.isError === true, data };
}
async function ticket(operation_name) {
  return (await call('prepare_request', { operation_name })).data.request_id;
}
async function connections() {
  return (await call('list_connections')).data.connections;
}
async function findConnection(label) {
  const connection = (await connections()).find(item => item.label === label);
  check(connection, 'saved_connection_missing');
  return connection;
}
function connectionRow(label) {
  return page.locator('#credentials > li').filter({ has: page.locator('strong', { hasText: label }) });
}
async function saveConnection({ service, type, label, account, operations, secret }) {
  await page.getByLabel('Service', { exact: true }).selectOption(service);
  await page.getByLabel('Credential type', { exact: true }).selectOption(type);
  await page.getByLabel('Label', { exact: true }).fill(label);
  await page.getByLabel('Account alias', { exact: true }).fill(account);
  if (secret !== undefined) await page.getByLabel('Secret', { exact: true }).fill(secret);
  for (const operation of operations) await page.getByLabel(operation, { exact: true }).check();
  await page.getByRole('button', { name: 'Review connection', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm and save', exact: true }).waitFor();
  const review = await page.locator('#draft-details').innerText();
  check(review.includes(label) && review.includes(service) && operations.every(item => review.includes(item)), 'draft_review_incomplete');
  check(!review.includes(password), 'secret_in_review');
  await page.getByRole('button', { name: 'Confirm and save', exact: true }).click();
  await connectionRow(label).waitFor();
  return findConnection(label);
}
async function executeInput(connection, operation_id) {
  return { request_id: await ticket(operation_id), connection_id: connection.id, operation_id, expected_record_version: connection.record_version, args: {} };
}
async function approveBrowser(pending, operation) {
  await page.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
  const row = page.locator(`#browser-approvals > li[data-pending-id="${pending.pending_id}"]`);
  await row.waitFor();
  const text = await row.innerText();
  check(text.includes('execution:local') && text.includes('synthetic-login') && text.includes(pending.connection_id)
    && text.includes(operation) && text.includes('http://127.0.0.1:43122'), 'approval_card_binding_missing');
  const responsePromise = page.waitForResponse(response => new URL(response.url()).pathname === `/management/browser/approvals/${pending.pending_id}` && response.request().method() === 'POST');
  await row.getByRole('button', { name: operation === 'browser_fill' ? 'Approve fill once' : 'Approve login submit once', exact: true }).click();
  const response = await responsePromise;
  check(response.ok(), 'ui_approval_denied');
  check((await call('browser_approval_status', { pending_id: pending.pending_id })).data.state === 'approved', 'approval_not_applied');
}
async function stopProcess(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise(resolve => child.once('exit', resolve));
  child.kill('SIGTERM');
  await Promise.race([exited, delay(3000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL');
    await Promise.race([exited, delay(1000)]);
  }
}

try {
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  stage = 'synthetic_fixtures';
  demo = await startSyntheticBrowserDemo({ username, password, port: 43122 });
  for (const provider of ['github', 'google']) {
    fixtures.push(await startOAuthSimulator({ provider, redirectUri: `${origin}/management/oauth/callback/${provider}`, tokenLifetimeSeconds, googleScopeAliases: provider === 'google' }));
  }
  fs.writeFileSync(privateConfig, JSON.stringify({
    mode: 'synthetic', browser: { enabled: true, executablePath: '/usr/bin/chromium', headless: true },
    providers: { github: { endpoints: fixtures[0].endpoints }, google: { endpoints: fixtures[1].endpoints } },
  }), { mode: 0o600, flag: 'wx' });
  stage = 'actual_cli_initialization';
  await initializeThroughPty();
  checks.push('actual CLI init with controlling PTY; hidden passphrase input');
  stage = 'actual_cli_server';
  app = spawn(process.execPath, [cli, 'serve', '--data-dir', directory, '--port', String(port), '--product-config', privateConfig], {
    cwd: root, env: isolatedEnv, stdio: ['ignore', 'pipe', 'pipe'],
  });
  app.stdout.on('data', safeText); app.stderr.on('data', safeText);
  app.on('error', () => {});
  await waitForServer(origin);
  checks.push('built default CLI serve with private explicit synthetic product configuration');

  stage = 'chromium_management_login';
  browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, chromiumSandbox: true,
    args: ['--disable-dev-shm-usage', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-first-run'], env: isolatedEnv });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  const allowedOrigins = new Set([origin, demo.origin, ...fixtures.map(item => item.origin)]);
  await context.route('**/*', async route => {
    if (!allowedOrigins.has(new URL(route.request().url()).origin)) { unexpectedNetwork++; await route.abort(); return; }
    await route.continue();
  });
  page = await context.newPage();
  page.setDefaultTimeout(10_000);
  page.on('pageerror', () => { pageErrors++; });
  page.on('dialog', dialog => {
    // These two actions are deliberate, distinct management approvals.
    if (dialog.type() === 'confirm' && /^(Revoke OAuth access for |Approve submitting the login form for )/.test(dialog.message())) void dialog.accept();
    else { pageErrors++; void dialog.dismiss(); }
  });
  await page.goto(origin);
  await page.getByLabel('Administrator passphrase', { exact: true }).fill(passphrase);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).waitFor();
  await page.getByLabel('Unlock passphrase', { exact: true }).fill(passphrase);
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
  await page.getByRole('button', { name: 'Lock vault', exact: true }).waitFor();
  checks.push('Chromium management S0 to S1 login and separate S1 to S2 unlock');

  stage = 'official_stdio_mcp';
  client = new Client({ name: 'v1-product-acceptance', version: '1.0.0' });
  transport = new StdioClientTransport({ command: process.execPath, args: [cli, 'bridge', '--origin', origin, '--credential-file', path.join(directory, 'execution.key')], cwd: root, env: isolatedEnv, stderr: 'pipe' });
  transport.stderr?.on('data', safeText);
  await client.connect(transport);
  const toolNames = (await client.listTools()).tools.map(item => item.name);
  check(['execute_operation', 'browser_open_session', 'browser_request_approval', 'browser_fill', 'browser_submit', 'browser_session_status'].every(name => toolNames.includes(name)), 'required_mcp_tools_missing');
  checks.push('official SDK Client and StdioClientTransport launch the built CLI bridge');

  for (const [index, provider] of ['github', 'google'].entries()) {
    stage = `${provider}_ui_client_configuration`;
    const fixture = fixtures[index];
    const name = provider === 'github' ? 'GitHub' : 'Google';
    const row = page.locator(`#oauth-providers > li[data-provider="${provider}"]`);
    await row.waitFor();
    check((await row.innerText()).includes('client_not_configured'), 'provider_not_disabled_initially');
    check(await row.getByLabel('Client secret', { exact: true }).getAttribute('type') === 'password', 'client_secret_not_secure_input');
    await row.getByLabel('Client ID', { exact: true }).fill(fixture.clientId);
    await row.getByLabel('Client secret', { exact: true }).fill(fixture.clientSecret);
    await row.getByRole('button', { name: 'Save provider client', exact: true }).click();
    await row.getByRole('button', { name: 'Replace provider client', exact: true }).waitFor();
    check(await row.getByLabel('Client secret', { exact: true }).inputValue() === '', 'client_secret_not_cleared');

    stage = `${provider}_ui_connection_review`;
    const label = `${name} synthetic product OAuth`;
    const operation = provider === 'github' ? 'github.current_user' : 'google.userinfo';
    let connection = await saveConnection({ service: provider, type: 'oauth', label, account: `synthetic_${provider}_account`, operations: [operation] });
    stage = `${provider}_actual_authorize_callback`;
    await connectionRow(label).locator('form.oauth-actions input[name="consent"]').check();
    await connectionRow(label).getByRole('button', { name: 'Authorize', exact: true }).click();
    const link = connectionRow(label).getByRole('link', { name: `Continue to ${name} simulator`, exact: true });
    await link.waitFor();
    const authorization = new URL(await link.getAttribute('href'));
    check(authorization.origin === fixture.origin && authorization.pathname === '/authorize'
      && authorization.searchParams.get('redirect_uri') === fixture.redirectUri, 'authorization_target_mismatch');
    await link.click();
    await page.waitForURL(url => url.origin === origin && url.pathname === '/');
    await connectionRow(label).waitFor();
    connection = await findConnection(label);
    check(connection.status === 'active' && fixture.counts.authorize === 1 && fixture.counts.exchange === 1 && fixture.counts.callback === 0, 'protected_product_callback_not_completed');

    stage = `${provider}_initial_stdio_execution`;
    const first = await call('execute_operation', await executeInput(connection, operation));
    check(first.data.operation.state === 'succeeded' && fixture.counts.refresh === 0, 'initial_oauth_execution_failed');
    const beforeConcurrent = { ...fixture.counts };
    const inputs = await Promise.all([executeInput(connection, operation), executeInput(connection, operation)]);
    // Real time expiry, without changing the server or fixture clocks.
    await delay(tokenLifetimeSeconds * 1000 + 200);
    stage = `${provider}_concurrent_expiry_refresh`;
    const concurrent = await Promise.all(inputs.map(input => call('execute_operation', input)));
    check(concurrent.every(item => item.data.operation.state === 'succeeded'), 'concurrent_oauth_execution_failed');
    check(fixture.counts.refresh === beforeConcurrent.refresh + 1 && fixture.counts.identity === beforeConcurrent.identity + 2, 'concurrent_refresh_not_coalesced');

    stage = `${provider}_ui_revoke`;
    await connectionRow(label).getByRole('button', { name: 'Revoke OAuth', exact: true }).click();
    await page.waitForFunction(labelValue => [...document.querySelectorAll('#credentials > li')].some(item => item.querySelector('strong')?.textContent === labelValue && item.textContent.includes(' · revoked · ')), label);
    const countsAfterRevoke = { ...fixture.counts };
    const denied = await call('execute_operation', await executeInput(connection, operation), true);
    check(denied.denied && fixture.counts.identity === countsAfterRevoke.identity && fixture.counts.refresh === countsAfterRevoke.refresh && fixture.counts.revoke === 1, 'revoked_oauth_not_denied');
    oauthEvidence[provider] = { fixture: 'independent loopback protocol simulator', scopes: provider === 'github' ? ['read:user'] : ['openid', 'email'],
      clientConfiguredViaUI: true, reviewedConnectionSavedViaUI: true, authorizeNavigationAndProtectedCallback: true,
      fixedOperationViaStdio: true, realClockExpirySeconds: tokenLifetimeSeconds, concurrentCalls: 2, refreshRequestsForConcurrentCalls: 1,
      revokedViaUI: true, executionDeniedAfterRevoke: true, counts: { ...fixture.counts } };
  }
  checks.push('GitHub and Google separately: UI client and reviewed save, browser authorize and protected callback, fixed stdio operation, real expiry with two calls and one refresh, UI revoke and no-hit denial');

  stage = 'browser_ui_password_save';
  const connection = await saveConnection({ service: 'synthetic-login', type: 'password', label: 'Synthetic product browser login', account: username,
    operations: ['browser_fill', 'login_submit'], secret: password });
  const sites = (await call('browser_sites')).data;
  check(sites.supported === true && sites.sites.some(item => item.site_id === 'synthetic-login' && item.origin === demo.origin), 'controlled_site_unavailable');
  const session = (await call('browser_open_session', { site_id: 'synthetic-login' })).data;
  const binding = { browser_session_id: session.browser_session_id, connection_id: connection.id, expected_record_version: connection.record_version };
  stage = 'browser_unapproved_fill_rejected';
  const fill = (await call('browser_request_approval', { ...binding, operation: 'browser_fill' })).data;
  const unapproved = await call('browser_fill', { pending_id: fill.pending_id }, true);
  check(unapproved.denied && unapproved.data.error === 'approval_invalid' && demo.stats.submissions === 0, 'unapproved_fill_not_rejected');
  stage = 'browser_ui_fill_approval';
  await approveBrowser(fill, 'browser_fill');
  const filled = (await call('browser_fill', { pending_id: fill.pending_id })).data;
  check(filled.status === 'filled' && filled.submitted === false && demo.stats.submissions === 0 && demo.stats.authenticated === 0, 'fill_submitted_form');
  check((await call('browser_session_status', { browser_session_id: session.browser_session_id })).data.status === 'filled', 'host_did_not_record_fill');

  stage = 'browser_ui_separate_submit_approval';
  const submit = (await call('browser_request_approval', { ...binding, operation: 'login_submit' })).data;
  const request_id = await ticket('login_submit');
  const submitInput = { ...binding, pending_id: submit.pending_id, request_id };
  const unapprovedSubmit = await call('browser_submit', submitInput, true);
  check(unapprovedSubmit.denied && demo.stats.submissions === 0, 'fill_authorized_submit');
  await approveBrowser(submit, 'login_submit');
  const submitted = (await call('browser_submit', submitInput)).data.operation;
  check(submitted.state === 'succeeded' && demo.stats.submissions === 1 && demo.stats.authenticated === 1, 'approved_login_not_authenticated');
  stage = 'browser_cookie_session_reuse';
  const status = (await call('browser_session_status', { browser_session_id: session.browser_session_id })).data;
  check(status.status === 'session_reused' && status.authenticated === true && status.http_status === 200 && demo.stats.sessionVisits === 1 && demo.stats.submissions === 1, 'browser_cookie_reuse_failed');
  checks.push('password reviewed and saved through Chromium; stdio opens controlled session; unapproved fill denied; UI card binds execution:local/site/record/action; approved fill makes zero submissions');
  checks.push('submit requested and separately approved in UI; actual fixture accepts filled credentials once; stdio status reuses authenticated cookie');

  // Keep a valid pending browser approval across lock to exercise actual epoch invalidation.
  stage = 'browser_pending_before_lock';
  const lockSession = (await call('browser_open_session', { site_id: 'synthetic-login' })).data;
  const lockFill = (await call('browser_request_approval', { browser_session_id: lockSession.browser_session_id, connection_id: connection.id,
    expected_record_version: connection.record_version, operation: 'browser_fill' })).data;
  await approveBrowser(lockFill, 'browser_fill');
  stage = 'locked_stdio_rejection';
  await page.getByRole('button', { name: 'Lock vault', exact: true }).click();
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).waitFor();
  const locked = await call('browser_fill', { pending_id: lockFill.pending_id }, true);
  check(locked.denied && locked.data.error === 'vault_locked' && demo.stats.submissions === 1, 'locked_fill_not_rejected');
  check((await call('list_connections', {}, true)).denied, 'locked_mcp_metadata_not_denied');
  await page.getByLabel('Unlock passphrase', { exact: true }).fill(passphrase);
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
  await page.getByRole('button', { name: 'Lock vault', exact: true }).waitFor();
  const stale = await call('browser_fill', { pending_id: lockFill.pending_id }, true);
  check(stale.denied && demo.stats.submissions === 1, 'prelock_approval_survived');
  checks.push('UI lock causes stdio vault_locked denial; unlocking does not revive the prior browser approval');

  stage = 'sanitized_evidence';
  await page.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
  await page.getByText('No pending browser approvals.', { exact: true }).waitFor();
  const secrets = [passphrase, password, ...fixtures.map(item => item.clientSecret), fs.readFileSync(path.join(directory, 'execution.key'), 'utf8').trim()];
  const visible = await page.locator('body').innerText();
  const inputs = await page.locator('input[type="password"]').evaluateAll(elements => elements.map(element => element.value));
  for (const secret of secrets) check(!visible.includes(secret) && !diagnostics.includes(secret) && !protocol.includes(secret) && !inputs.includes(secret), 'secret_exposure_detected');
  check(pageErrors === 0 && unexpectedNetwork === 0, 'browser_or_network_errors');
  checks.push('synthetic secrets absent from management text, cleared password inputs, CLI diagnostics and MCP output; management browser made only allowed loopback requests');
  fs.mkdirSync(evidence, { recursive: true });
  await page.screenshot({ path: path.join(evidence, 'v1-product-acceptance.png'), fullPage: true });
  fs.writeFileSync(path.join(evidence, 'v1-product-acceptance.json'), JSON.stringify({
    started, completed: new Date().toISOString(), result: 'passed', synthetic: true,
    entrypoints: { initialize: 'node dist/src/cli.js init --data-dir <scratch>/vault --synthetic true (PTY)',
      serve: 'node dist/src/cli.js serve --data-dir <scratch>/vault --port <free> --product-config <private JSON>',
      execution: 'official SDK StdioClientTransport -> node dist/src/cli.js bridge --origin <loopback> --credential-file <scratch>/vault/execution.key' },
    browser: 'sandboxed system Chromium via Playwright; separate product-controlled Chromium host', checks, oauth: oauthEvidence,
    controlledBrowser: { fixedSite: 'synthetic-login', fixtureSubmissions: demo.stats.submissions, authenticatedSubmissions: demo.stats.authenticated,
      cookieSessionVisits: demo.stats.sessionVisits, fillAutoSubmitted: false, submitSeparatelyApproved: true, unapprovedFillDenied: true,
      unapprovedSubmitDenied: true, lockedFillDenied: true, priorApprovalInvalidAfterUnlock: true },
    pageErrors, unexpectedManagementBrowserNetworkRequests: unexpectedNetwork,
    limitations: ['local synthetic protocol and site evidence only', 'real provider client registration and account authorization remain unverified',
      'five-agent built-in browser integration remains unverified', 'no external deployment or optional model invocation']
  }, null, 2) + '\n', { mode: 0o600 });
  process.stdout.write('Built CLI + Chromium UI + official stdio MCP product acceptance passed.\n');
} catch {
  // Never print assertion values, Playwright diagnostics, callback URLs or provider messages.
  process.stderr.write(`Product acceptance failed at ${stage}. No raw diagnostics retained.\n`);
  process.exitCode = 1;
} finally {
  await client?.close().catch(() => {});
  await transport?.close().catch(() => {});
  await browser?.close().catch(() => {});
  await stopProcess(app);
  await Promise.allSettled(fixtures.map(item => item.close()));
  await demo?.close().catch(() => {});
  fs.rmSync(root, { recursive: true, force: true });
}
