import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright-core';
import { browserVaultCapabilities, createControlledBrowserHost } from './browser.js';
import { startSyntheticBrowserDemo } from './browser-demo.js';
import { initialize, Vault } from './vault.js';
import type { Authority, SavePayload } from './contracts.js';

/** Runnable standalone demonstration; only creates a new temporary vault and synthetic identity.
 * The explicit trusted control calls stand in for the local manager's approval buttons. */
export async function runSyntheticBrowserDemo() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-browser-demo-'));
  const username = 'synthetic_demo_user';
  const password = `synthetic_demo_${randomUUID()}`;
  const passphrase = `synthetic_demo_passphrase_${randomUUID()}`;
  const demo = await startSyntheticBrowserDemo({ username, password, port: 43122 });
  let vault: Vault | undefined;
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let host: ReturnType<typeof createControlledBrowserHost> | undefined;
  try {
    await initialize(directory, passphrase);
    vault = new Vault(directory); await vault.unlock(passphrase);
    const admin: Authority = { owner_id: 'local', principal_id: 'synthetic-manager', client_id: 'synthetic-manager', session_id: 'synthetic-admin' };
    const agent: Authority = { owner_id: 'local', principal_id: 'synthetic-browser-agent', client_id: 'synthetic-browser-agent' };
    const payload: SavePayload = { mode: 'create', label: 'Synthetic browser demonstration', service_id: 'synthetic-login', credential_type: 'password', account_alias: username,
      secret: password, origin: demo.origin, environment: 'local', granted_operations: ['browser_fill', 'login_submit'] };
    const draft = vault.createDraft(admin, payload), approved = vault.approveDraft(admin, draft.draft_id, draft.draft_version);
    const credential = vault.saveApproved(admin, { request_id: vault.prepareRequest(admin, 'save_connection'), draft_id: draft.draft_id, draft_version: draft.draft_version, approval_token: approved.approval_token, payload });
    browser = await chromium.launch({ executablePath: '/usr/bin/chromium', headless: true, chromiumSandbox: true,
      args: ['--disable-background-networking', '--disable-component-update', '--disable-sync', '--no-first-run'] });
    host = createControlledBrowserHost({ browser, rules: [demo.rules], ...browserVaultCapabilities(vault,
      (auth, metadata, operation) => auth.principal_id === agent.principal_id && vault!.get(metadata.id).granted_operations.includes(operation)) });
    const session = await host.execution.openSession(agent, demo.rules.id);
    const binding = { browser_session_id: session.browser_session_id, connection_id: credential.id, expected_record_version: credential.record_version };
    const fillApproval = await host.control.approveFill(agent, binding);
    const fill = await host.execution.fill(agent, { ...binding, approval_id: fillApproval.approval_id });
    const submissionsAfterFill = demo.stats.submissions;
    const submitApproval = await host.control.approveSubmit(agent, binding);
    const page = host.control.page(agent, session.browser_session_id);
    const submit = await host.execution.submit(agent, { ...binding, approval_id: submitApproval.approval_id, request_id: vault.prepareRequest(agent, 'login_submit') });
    await page.waitForURL(`${demo.origin}/session`, { waitUntil: 'load' });
    const account = await page.goto(`${demo.origin}/account`);
    const summary = { chromium: browser.version(), fill: fill.status, submissions_after_fill: submissionsAfterFill, separately_approved_submit: submit.state,
      accepted_submissions: demo.stats.authenticated, host_session_reused: account?.status() === 200, synthetic_only: true, temporary_vault_removed_on_exit: true };
    if (summary.submissions_after_fill !== 0 || summary.separately_approved_submit !== 'succeeded' || summary.accepted_submissions !== 1 || !summary.host_session_reused) throw new Error('synthetic_browser_demo_failed');
    return summary;
  } finally { await host?.control.close(); await browser?.close(); vault?.close(); await demo.close(); fs.rmSync(directory, { recursive: true, force: true }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runSyntheticBrowserDemo().then(result => { process.stdout.write(`${JSON.stringify(result)}\n`); }).catch(() => { process.stderr.write('synthetic_browser_demo_failed\n'); process.exitCode = 1; });
}
