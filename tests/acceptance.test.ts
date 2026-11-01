import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { chromium } from 'playwright-core';
import { initialize } from '../src/vault.js';
import { createServer } from '../src/server.js';
import { startMock } from '../src/mock.js';

const project = process.cwd();
const passphrase = 'synthetic acceptance passphrase 2026';
const token = 'synthetic_browser_acceptance_token_123';
const replacement = 'synthetic_browser_replacement_token_456';
const toolNames = ['list_connections', 'list_operations', 'prepare_request', 'get_connection_status', 'get_operation_status', 'execute_operation'].sort();

test('current acceptance: Chromium management confirmation → official SDK stdio MCP → fixed mock', { timeout: 120_000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-v1-acceptance-')); const directory = path.join(root, 'vault');
  await initialize(directory, passphrase);
  const server = await createServer(directory, 0); const mock = await startMock();
  const evidence = path.join(project, 'docs/evidence'); fs.mkdirSync(evidence, { recursive: true });
  const browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, chromiumSandbox: true, args: ['--disable-dev-shm-usage'], env: { ...process.env, HEADLESS: '1' } });
  const page = await browser.newPage(); const pageErrors: string[] = []; page.on('pageerror', error => pageErrors.push(error.message));
  const client = new Client({ name: 'v1-acceptance', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: ['dist/src/cli.js', 'bridge', '--origin', server.origin, '--credential-file', path.join(directory, 'execution.key')], cwd: project, env: { PATH: process.env.PATH!, HOME: root, TMPDIR: root, NODE_ENV: 'test' }, stderr: 'pipe' });
  let diagnostics = ''; let protocol = ''; transport.stderr?.on('data', chunk => { diagnostics += String(chunk); });
  const call = async (name: string, args: Record<string, unknown> = {}) => { const result = await client.callTool({ name, arguments: args }); protocol += JSON.stringify(result); return result; };
  const data = (result: Awaited<ReturnType<typeof call>>): any => JSON.parse((result.content as { text: string }[])[0]!.text);
  const execution = async (connection: any, request_id?: string) => {
    const ticket = request_id ?? data(await call('prepare_request', { operation_name: 'mock.account_summary' })).request_id;
    return { ticket, result: await call('execute_operation', { request_id: ticket, connection_id: connection.id, operation_id: 'mock.account_summary', expected_record_version: connection.record_version, args: {} }) };
  };
  const connectionList = async () => data(await call('list_connections')).connections;
  const review = async (secret: string, label: string) => {
    await page.getByLabel('Label', { exact: true }).fill(label);
    await page.getByLabel('Account alias', { exact: true }).fill('synthetic-account');
    await page.getByLabel('Secret', { exact: true }).fill(secret);
    await page.getByLabel('mock.account_summary', { exact: true }).check();
    await page.getByRole('button', { name: /Review (connection|replacement)/, exact: true }).click();
    await page.getByRole('button', { name: 'Confirm and save', exact: true }).waitFor();
    assert.equal(await page.locator('#token').inputValue(), '');
    assert(!(await page.locator('body').innerText()).includes(secret));
  };
  const confirm = async (label: string) => { await page.getByRole('button', { name: 'Confirm and save', exact: true }).click(); await page.locator('#credentials').getByText(label, { exact: true }).waitFor(); };
  try {
    await t.test('official SDK initialized over stdio exposes exactly six execution tools; no management tools', async () => {
      await client.connect(transport);
      const tools = await client.listTools(); assert.deepEqual(tools.tools.map(tool => tool.name).sort(), toolNames);
      protocol += JSON.stringify(tools);
      assert.equal((await call('list_connections')).isError, true);
      const unknown = await call('unlock', { passphrase: 'synthetic-never-real' }); assert.equal(unknown.isError, true);
    });
    await t.test('actual UI signs in to S1 separately then unlocks to S2', async () => {
      await page.goto(server.origin);
      await page.getByLabel('Administrator passphrase', { exact: true }).fill(passphrase);
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await page.getByRole('button', { name: 'Unlock vault', exact: true }).waitFor();
      assert.equal(server.vault.unlocked, false); assert.equal(await page.locator('#login-passphrase').inputValue(), '');
      assert.equal((await call('list_connections')).isError, true);
      await page.getByLabel('Unlock passphrase', { exact: true }).fill(passphrase);
      const unlockResponse = page.waitForResponse(response => response.url().endsWith('/management/unlock'));
      await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
      const unlocked = await unlockResponse; assert.equal(unlocked.status(), 200, await unlocked.text());
      await page.getByRole('button', { name: 'Lock vault', exact: true }).waitFor();
      assert.equal(server.vault.unlocked, true); assert.equal(await page.locator('#passphrase').inputValue(), '');
    });
    let connection: any;
    await t.test('draft cancel never saves; confirm saves; labels render as text without XSS', async () => {
      await review(token, 'Cancelled connection'); assert.equal(server.vault.list().length, 0);
      await page.getByRole('button', { name: 'Cancel draft', exact: true }).click();
      await page.getByRole('button', { name: 'Review connection', exact: true }).waitFor(); assert.equal(server.vault.list().length, 0);
      const label = '<img src=x onerror=window.xss=true>';
      await review(token, label); assert.equal(server.vault.list().length, 0); await confirm(label);
      assert.equal(await page.evaluate(() => (window as any).xss), undefined); assert.equal(await page.locator('img').count(), 0);
      connection = (await connectionList())[0]; assert.equal(connection.record_version, 1); assert(!JSON.stringify(connection).includes(token));
      await page.screenshot({ path: path.join(evidence, 'v1-management-confirmed.png'), fullPage: true });
    });
    await t.test('actual UI retains only save ticket across reload and recovers committed metadata', async () => {
      const requestId = await page.locator('#save-request-id').inputValue(); assert(requestId.length > 20);
      await page.reload(); await page.getByRole('button', { name: 'Lock vault', exact: true }).waitFor();
      assert.equal(await page.locator('#save-request-id').inputValue(), requestId);
      await page.locator('#save-recovery-panel summary').click();
      await page.getByRole('button', { name: 'Recover save result', exact: true }).click();
      await page.getByText(/Save completed: .*saved record version 1\. No new save was performed\./).waitFor();
      assert.equal(server.vault.list().length, 1); assert.equal(server.vault.list()[0]!.record_version, 1);
      assert(!(await page.locator('#save-recovery-result').innerText()).includes(token));
    });
    await t.test('MCP ticket, metadata/status and actual whitelisted redacted upstream result; same ticket never dispatches twice', async () => {
      const operations = data(await call('list_operations')).operations; assert(operations.some((operation: any) => operation.id === 'mock.account_summary'));
      assert.equal(data(await call('get_connection_status', { connection_id: connection.id })).connection.id, connection.id);
      const beforeHits = mock.getHits();
      const first = await execution(connection); assert(!first.result.isError); assert.equal(mock.getHits(), beforeHits + 1);
      const completed = data(first.result).operation; assert.equal(completed.state, 'succeeded'); assert.equal(completed.operation_status_version, 3);
      assert.equal(completed.result.account.name, 'Synthetic account [REDACTED]'); assert.equal(completed.result.notices[0].message, 'Nested reflection: [REDACTED]');
      assert.deepEqual(Object.keys(completed.result).sort(), ['account', 'notices', 'plan']); assert.deepEqual(Object.keys(completed.result.account).sort(), ['id', 'name']);
      const replay = await execution(connection, first.ticket); assert.deepEqual(data(replay.result).operation, completed); assert.equal(mock.getHits(), beforeHits + 1);
      assert.deepEqual(data(await call('get_operation_status', { request_id: first.ticket, operation_name: 'mock.account_summary' })).operation, completed);
      const forged = await call('execute_operation', { request_id: 'client-generated-ticket-that-is-invalid', connection_id: connection.id, operation_id: 'mock.account_summary', expected_record_version: 1, args: {} }); assert.equal(forged.isError, true);
      assert.equal((await call('prepare_request', { operation_name: 'unknown_operation' })).isError, true);
      for (const args of [{ url: 'http://169.254.169.254/latest/meta-data/' }, { headers: { authorization: 'injected' } }, { path: '/arbitrary' }, { script: 'return process.env' }]) {
        const result = await call('execute_operation', { request_id: first.ticket, connection_id: connection.id, operation_id: 'mock.account_summary', expected_record_version: 1, args }); assert.equal(result.isError, true);
      }
    });
    await t.test('actual UI pause denies MCP; replacement preserves independent versions; delete JSON body works', async () => {
      await page.getByRole('button', { name: 'Pause', exact: true }).click(); await page.getByRole('button', { name: 'Activate', exact: true }).waitFor();
      assert.equal((await execution(connection)).result.isError, true);
      await page.getByRole('button', { name: 'Activate', exact: true }).click(); await page.getByRole('button', { name: 'Pause', exact: true }).waitFor();
      await page.getByRole('button', { name: 'Replace', exact: true }).click();
      await review(replacement, 'Browser replacement'); await confirm('Browser replacement');
      const previous = connection; connection = (await connectionList())[0]; assert.equal(connection.record_version, 2); assert.equal(connection.status_version, 4);
      assert.equal((await execution(previous)).result.isError, true); assert.equal(data((await execution(connection)).result).operation.state, 'succeeded');
      await page.getByRole('button', { name: 'Delete', exact: true }).click(); await page.getByText('No connections yet.', { exact: true }).waitFor();
      assert.equal((await execution(connection)).result.isError, true); assert.equal(server.vault.list().length, 0);
    });
    await t.test('actual UI pending OAuth approval and replacement require no token entry', async () => {
      await page.getByLabel('Service', { exact: true }).selectOption('github');
      await page.getByLabel('Credential type', { exact: true }).selectOption('oauth');
      await page.getByLabel('Label', { exact: true }).fill('Pending GitHub OAuth'); await page.getByLabel('Account alias', { exact: true }).fill('synthetic-github');
      await page.getByLabel('github.current_user', { exact: true }).check();
      assert.equal(await page.locator('#secret-field').isVisible(), false);
      await page.getByRole('button', { name: 'Review connection', exact: true }).click(); await page.getByRole('button', { name: 'Confirm and save', exact: true }).waitFor(); await confirm('Pending GitHub OAuth');
      let oauth = (await connectionList())[0]; assert.equal(oauth.status, 'needs_user_action'); assert.equal(oauth.can_execute, false);
      await page.getByRole('button', { name: 'Replace', exact: true }).click();
      assert.equal(await page.locator('#credential-type').inputValue(), 'oauth'); assert.equal(await page.locator('#secret-field').isVisible(), false);
      await page.getByLabel('Label', { exact: true }).fill('Replaced pending OAuth');
      await page.getByRole('button', { name: 'Review replacement', exact: true }).click(); await page.getByRole('button', { name: 'Confirm and save', exact: true }).waitFor(); await confirm('Replaced pending OAuth');
      oauth = (await connectionList())[0]; assert.equal(oauth.record_version, 2); assert.equal(oauth.status, 'needs_user_action');
      await page.getByRole('button', { name: 'Delete', exact: true }).click(); await page.getByText('No connections yet.', { exact: true }).waitFor();
    });
    await t.test('actual UI lock rotates to S1, MCP denies; unlock restores; signout reaches S0', async () => {
      await page.getByRole('button', { name: 'Lock vault', exact: true }).click(); await page.getByRole('button', { name: 'Unlock vault', exact: true }).waitFor();
      assert.equal(server.vault.unlocked, false); assert.equal((await call('list_connections')).isError, true);
      await page.getByLabel('Unlock passphrase', { exact: true }).fill(passphrase); await page.getByRole('button', { name: 'Unlock vault', exact: true }).click();
      await page.getByRole('button', { name: 'Lock vault', exact: true }).waitFor(); assert(!(await call('list_connections')).isError);
      await page.locator('#logout-button').click(); await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
      assert.equal(server.vault.unlocked, false); assert.equal((await call('list_connections')).isError, true);
      await page.screenshot({ path: path.join(evidence, 'v1-management-signed-out.png'), fullPage: true });
    });
    await t.test('bridge denies missing/unsafe execution key without stdout contamination; no plaintext stored or logged', () => {
      const unsafe = path.join(root, 'unsafe.key'); fs.writeFileSync(unsafe, 'a'.repeat(64), { mode: 0o600 }); fs.chmodSync(unsafe, 0o644);
      for (const filename of [path.join(root, 'missing.key'), unsafe]) assert.throws(() => execFileSync(process.execPath, ['dist/src/cli.js', 'bridge', '--origin', server.origin, '--credential-file', filename], { cwd: project, env: { PATH: process.env.PATH, HOME: root }, timeout: 5000, stdio: 'pipe' }), (error: any) => { assert.equal(error.stdout.toString(), ''); return true; });
      for (const entry of fs.readdirSync(directory)) { assert.equal(fs.statSync(path.join(directory, entry)).mode & 0o777, 0o600); const bytes = fs.readFileSync(path.join(directory, entry)); for (const secret of [token, replacement, passphrase]) assert(!bytes.includes(Buffer.from(secret))); }
      for (const secret of [token, replacement, passphrase]) { assert(!protocol.includes(secret)); assert(!diagnostics.includes(secret)); }
      assert.deepEqual(pageErrors, []);
    });
  } finally {
    await client.close(); await transport.close(); await browser.close(); await server.app.close();
    await new Promise<void>(resolve => mock.close(() => resolve())); fs.rmSync(root, { recursive: true, force: true });
  }
});
