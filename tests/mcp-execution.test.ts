import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { initialize } from '../src/vault.js';
import { createServer } from '../src/server.js';
import { startMock } from '../src/mock.js';

const passphrase = 'synthetic MCP fault acceptance passphrase';

test('official MCP failure journal, no-hit refusals, replay and restart recovery use actual local HTTP', { timeout: 30_000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-mcp-faults-')); const directory = path.join(root, 'vault');
  await initialize(directory, passphrase); let server = await createServer(directory, 0); const mock = await startMock();
  let cookie = ''; let csrf = ''; let diagnostics = ''; let protocol = '';
  let client: Client | undefined; let transport: StdioClientTransport | undefined;
  const management = async (url: string, method = 'GET', body?: unknown) => {
    const response = await fetch(`${server.origin}${url}`, { method, headers: { ...(cookie ? { cookie } : {}), ...(method === 'GET' ? {} : { origin: server.origin, 'x-csrf-token': csrf, 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const set = response.headers.get('set-cookie'); if (set) cookie = set.split(';')[0]!; const data = await response.json() as any; if (data.csrf) csrf = data.csrf;
    assert.equal(response.status, 200, JSON.stringify(data)); return data;
  };
  const unlock = async () => { await management('/management/session'); await management('/management/login', 'POST', { passphrase }); await management('/management/unlock', 'POST', { passphrase }); };
  const connect = async () => {
    client = new Client({ name: 'mcp-fault-acceptance', version: '1.0.0' });
    transport = new StdioClientTransport({ command: process.execPath, args: ['dist/src/cli.js', 'bridge', '--origin', server.origin, '--credential-file', path.join(directory, 'execution.key')], cwd: process.cwd(), env: { PATH: process.env.PATH!, HOME: root, TMPDIR: root }, stderr: 'pipe' });
    transport.stderr?.on('data', chunk => { diagnostics += String(chunk); }); await client.connect(transport);
  };
  const call = async (name: string, args: Record<string, unknown> = {}) => { const result = await client!.callTool({ name, arguments: args }); protocol += JSON.stringify(result); return { error: result.isError, data: JSON.parse((result.content as { text: string }[])[0]!.text) }; };
  const ticket = async () => (await call('prepare_request', { operation_name: 'mock.account_summary' })).data.request_id;
  const tokens = ['synthetic_redirect_mcp_123', 'synthetic_oversize_mcp_123', 'synthetic_timeout_mcp_123', 'synthetic_mcp_success_123'];
  const auth = { owner_id: 'local' as const, principal_id: 'admin', client_id: 'management', session_id: 'trusted-test-session' };
  const save = (secret: string, suffix: string) => {
    const payload = { mode: 'create' as const, label: suffix, service_id: 'synthetic-mock', credential_type: 'api_key' as const, account_alias: suffix, secret, origin: 'http://127.0.0.1:43121', environment: 'local' as const, granted_operations: ['mock.account_summary'] };
    const draft = server.vault.createDraft(auth, payload); const approval = server.vault.approveDraft(auth, draft.draft_id, draft.draft_version);
    return server.vault.saveApproved(auth, { request_id: server.vault.prepareRequest(auth, 'save_connection'), draft_id: draft.draft_id, draft_version: draft.draft_version, approval_token: approval.approval_token, payload });
  };
  try {
    await unlock(); await connect();
    for (const [index, secret] of tokens.slice(0, 3).entries()) {
      const connection = save(secret, `failure-${index}`); const request_id = await ticket(); const input = { request_id, connection_id: connection.id, operation_id: 'mock.account_summary', expected_record_version: 1, args: {} };
      const hits = mock.getHits(); const result = await call('execute_operation', input);
      assert.equal(result.error, undefined); assert.equal(result.data.operation.state, 'outcome_unknown'); assert.equal(mock.getHits(), hits + 1);
      assert.equal((await call('execute_operation', input)).data.operation.state, 'outcome_unknown'); assert.equal(mock.getHits(), hits + 1);
      assert.equal((await call('get_operation_status', { request_id, operation_name: input.operation_id })).data.operation.state, 'outcome_unknown');
    }
    const connection = save(tokens[3]!, 'success'); const request_id = await ticket(); const input = { request_id, connection_id: connection.id, operation_id: 'mock.account_summary', expected_record_version: 1, args: {} };
    const canary = 'synthetic_MCP_malformed_input_canary_2026';
    await t.test('actual stdio malformed keys, values and unknown tool names return generic errors with no echo or upstream hit', async () => {
      const before = mock.getHits();
      const validArguments: Record<string, Record<string, unknown>> = {
        list_connections: {}, list_operations: {}, prepare_request: { operation_name: 'mock.account_summary' },
        get_connection_status: { connection_id: connection.id },
        get_operation_status: { request_id, operation_name: 'mock.account_summary' }, execute_operation: input,
      };
      for (const [name, args] of Object.entries(validArguments)) {
        const denied = await call(name, { ...args, [canary]: canary });
        assert.equal(denied.error, true); assert.deepEqual(denied.data, { error: 'invalid_tool_request' });
      }
      for (const [name, args] of [
        [canary, { [canary]: canary }],
        ['execute_operation', { ...input, args: { [canary]: canary } }],
        ['execute_operation', { ...input, expected_record_version: canary }],
        ['get_connection_status', { connection_id: canary }],
        ['prepare_request', { operation_name: { [canary]: canary } }],
      ] as Array<[string, Record<string, unknown>]>) {
        const denied = await call(name, args);
        assert.equal(denied.error, true); assert.deepEqual(denied.data, { error: 'invalid_tool_request' });
      }
      assert.equal(mock.getHits(), before); assert(!protocol.includes(canary)); assert(!diagnostics.includes(canary));
    });
    let hits = mock.getHits(); const first = await call('execute_operation', input); assert.equal(first.data.operation.state, 'succeeded'); assert.equal(mock.getHits(), hits + 1);
    hits = mock.getHits();
    assert.equal((await call('execute_operation', { ...input, operation_id: 'unknown' })).error, true); assert.equal(mock.getHits(), hits);
    assert.equal((await call('execute_operation', { ...input, request_id: await ticket(), expected_record_version: 2 })).error, true); assert.equal(mock.getHits(), hits);
    server.vault.setStatus(auth, connection.id, 'revoked', 1);
    assert.equal((await call('execute_operation', { ...input, request_id: await ticket() })).error, true); assert.equal(mock.getHits(), hits);
    server.vault.setStatus(auth, connection.id, 'active', 2);
    await management('/management/lock', 'POST', {});
    assert.equal((await call('execute_operation', input)).error, true); assert.equal((await call('list_connections')).error, true); assert.equal(mock.getHits(), hits);
    await management('/management/unlock', 'POST', { passphrase });
    assert.deepEqual((await call('execute_operation', input)).data.operation, first.data.operation); assert.equal(mock.getHits(), hits);
    // Stop/start the actual management server. The SDK reconnects to the new loopback port; same stable execution identity/ticket retains its original result.
    await client!.close(); await transport!.close(); await server.app.close();
    server = await createServer(directory, 0); cookie = ''; csrf = ''; await connect();
    assert.equal((await call('execute_operation', input)).error, true); assert.equal(mock.getHits(), hits);
    await unlock(); assert.deepEqual((await call('execute_operation', input)).data.operation, first.data.operation); assert.equal(mock.getHits(), hits);
    const different = server.vault.list().find(item => item.id !== connection.id)!;
    const conflict = await call('execute_operation', { ...input, connection_id: different.id }); assert.equal(conflict.error, true); assert.equal(mock.getHits(), hits);
    const key = fs.readFileSync(path.join(directory, 'execution.key'), 'utf8').trim();
    for (const secret of [...tokens, passphrase, key]) { assert(!protocol.includes(secret)); assert(!diagnostics.includes(secret)); }
    for (const entry of fs.readdirSync(directory)) for (const secret of tokens) assert(!fs.readFileSync(path.join(directory, entry)).includes(Buffer.from(secret)));
  } finally { await client?.close(); await transport?.close(); await server.app.close(); await new Promise<void>(resolve => mock.close(() => resolve())); fs.rmSync(root, { recursive: true, force: true }); }
});
