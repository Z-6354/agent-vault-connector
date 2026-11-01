import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { readPrivateFile } from './files.js';
import { executionSchema } from './registry.js';
import { z } from 'zod';

export function bridgeOrigin(input: string): string {
  const url = new URL(input);
  if (url.origin !== input || url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Bridge requires exact loopback HTTP origin');
  return input;
}

type ExecutionPath = '/execution/connections' | '/execution/operations' | '/execution/prepare-request' | '/execution/connection-status' | '/execution/operation-status' | '/execution/execute'
  | '/execution/browser/sites' | '/execution/browser/session' | '/execution/browser/session-status' | '/execution/browser/request-approval' | '/execution/browser/approval-status' | '/execution/browser/fill' | '/execution/browser/submit';
export async function startBridge(originInput: string, filename: string): Promise<void> {
  const origin = bridgeOrigin(originInput);
  const bytes = readPrivateFile(filename);
  let credential: string;
  try {
    credential = bytes.toString().trim();
    if (!/^[a-f0-9]{64}$/.test(credential)) throw new Error('Invalid execution credential');
  } finally { bytes.fill(0); }
  const request = async (pathname: ExecutionPath, body?: unknown) => {
    const response = await fetch(`${origin}${pathname}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { authorization: `Bearer ${credential}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(20000),
    });
    const reader = response.body?.getReader();
    if (!reader) throw new Error('vault_unavailable');
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 1024 * 1024) throw new Error('vault_response_too_large');
        chunks.push(value);
      }
      const data = JSON.parse(Buffer.concat(chunks).toString()) as { error?: unknown };
      if (!response.ok) {
        // Only controlled error codes cross the bridge. Raw HTTP/dependency diagnostics never do.
        const error = typeof data.error === 'string' && /^[a-z][a-z0-9_]{0,79}$/.test(data.error) ? data.error : 'vault_unavailable_or_operation_denied';
        throw new Error(error);
      }
      return data;
    } finally { await reader.cancel(); }
  };
  const server = new Server({ name: 'local-agent-vault', version: '1.0.0' }, { capabilities: { tools: {} } });
  const run = async (pathname: ExecutionPath, body?: unknown) => {
    try { return { content: [{ type: 'text' as const, text: JSON.stringify(await request(pathname, body)) }] }; }
    catch (error) {
      const message = error instanceof Error && /^[a-z][a-z0-9_]{0,79}$/.test(error.message) ? error.message : 'vault_unavailable_or_operation_denied';
      return { isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: message }) }] };
    }
  };
  const textField = (minLength: number, maxLength: number) => ({ type: 'string' as const, minLength, maxLength });
  const objectSchema = (properties: Record<string, unknown>) => ({ type: 'object' as const, properties, required: Object.keys(properties), additionalProperties: false });
  const ticketField = textField(20, 1024);
  const operationField = textField(1, 100);
  const connectionField = { type: 'string' as const, format: 'uuid' };
  const pendingField = { type: 'string' as const, format: 'uuid' };
  const sessionField = { type: 'string' as const, format: 'uuid' };
  const versionField = { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER };
  const tools = [
    { name: 'browser_sites', description: 'List explicitly enabled controlled browser sites. Unconfigured hosts are unsupported.', path: '/execution/browser/sites' as const, schema: z.object({}).strict(), inputSchema: objectSchema({}), read: true },
    { name: 'browser_open_session', description: 'Open a dedicated host session for a fixed registered site. Does not authorize credential use.', path: '/execution/browser/session' as const, schema: z.object({ site_id: z.literal('synthetic-login') }).strict(), inputSchema: objectSchema({ site_id: { type: 'string', enum: ['synthetic-login'] } }), read: false },
    { name: 'browser_session_status', description: 'Read safe controlled-session status; after approved login, verify reuse at the fixed account page. No DOM, cookies or secrets.', path: '/execution/browser/session-status' as const, schema: z.object({ browser_session_id: z.string().uuid() }).strict(), inputSchema: objectSchema({ browser_session_id: sessionField }), read: false },
    { name: 'browser_request_approval', description: 'Request human management approval for this principal, exact document, record and action. Fill and submit require separate approval.', path: '/execution/browser/request-approval' as const, schema: z.object({ browser_session_id: z.string().uuid(), connection_id: z.string().uuid(), expected_record_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), operation: z.enum(['browser_fill', 'login_submit']) }).strict(), inputSchema: objectSchema({ browser_session_id: sessionField, connection_id: connectionField, expected_record_version: versionField, operation: { type: 'string', enum: ['browser_fill', 'login_submit'] } }), read: false },
    { name: 'browser_approval_status', description: 'Read your own pending browser approval status. This tool cannot approve.', path: '/execution/browser/approval-status' as const, schema: z.object({ pending_id: z.string().uuid() }).strict(), inputSchema: objectSchema({ pending_id: pendingField }), read: false },
    { name: 'browser_fill', description: 'Consume a human-approved, document-bound fill once. Does not click, press Enter or submit.', path: '/execution/browser/fill' as const, schema: z.object({ pending_id: z.string().uuid() }).strict(), inputSchema: objectSchema({ pending_id: pendingField }), read: false },
    { name: 'browser_submit', description: 'Consume a separate human login-submit approval with a signed request ticket. Unknown outcomes require reconciliation.', path: '/execution/browser/submit' as const, schema: z.object({ pending_id: z.string().uuid(), browser_session_id: z.string().uuid(), connection_id: z.string().uuid(), expected_record_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), request_id: z.string().min(20).max(1024) }).strict(), inputSchema: objectSchema({ pending_id: pendingField, browser_session_id: sessionField, connection_id: connectionField, expected_record_version: versionField, request_id: ticketField }), read: false },
    { name: 'list_connections', description: 'List redacted connection metadata and current versions. Requires a human-authenticated, unlocked vault.', path: '/execution/connections' as const, schema: z.object({}).strict(), inputSchema: objectSchema({}), read: true },
    { name: 'list_operations', description: 'List fixed registered operations, origins and side-effect semantics. No secrets or arbitrary destinations.', path: '/execution/operations' as const, schema: z.object({}).strict(), inputSchema: objectSchema({}), read: true },
    { name: 'prepare_request', description: 'Obtain a server-issued request ticket for a registered operation. Does not dispatch an operation.', path: '/execution/prepare-request' as const, schema: z.object({ operation_name: z.string().min(1).max(100) }).strict(), inputSchema: objectSchema({ operation_name: operationField }), read: false },
    { name: 'get_connection_status', description: 'Read redacted connection status and versions. External references do not imply execution authority.', path: '/execution/connection-status' as const, schema: z.object({ connection_id: z.string().uuid() }).strict(), inputSchema: objectSchema({ connection_id: connectionField }), read: false },
    { name: 'get_operation_status', description: 'Read persisted state in this execution principal scope. Reconcile unknown outcomes before retrying.', path: '/execution/operation-status' as const, schema: z.object({ request_id: z.string().min(20).max(1024), operation_name: z.string().min(1).max(100) }).strict(), inputSchema: objectSchema({ request_id: ticketField, operation_name: operationField }), read: false },
    { name: 'execute_operation', description: 'Execute a fixed operation with server ticket and expected record version. No URL, headers, path or scripts; replays do not dispatch.', path: '/execution/execute' as const, schema: executionSchema, inputSchema: objectSchema({ request_id: ticketField, connection_id: connectionField, operation_id: operationField, expected_record_version: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }, args: objectSchema({}) }), read: false },
  ];
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) }));
  server.setRequestHandler(CallToolRequestSchema, async input => {
    const denied = () => ({ isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: 'invalid_tool_request' }) }] });
    // Parse inside our controlled handler: high-level SDK validation includes unrecognized
    // property names in diagnostics, which can reflect caller-supplied secrets.
    try {
      const tool = tools.find(item => item.name === input.params.name);
      if (!tool || input.params.task) return denied();
      const parsed = tool.schema.safeParse(input.params.arguments ?? {});
      if (!parsed.success) return denied();
      return run(tool.path, tool.read ? undefined : parsed.data);
    } catch { return denied(); }
  });
  // Official SDK stdio transport owns stdout. Local HTTP is an internal authenticated bridge,
  // not a Streamable HTTP MCP endpoint or substitute for client OAuth support.
  await server.connect(new StdioServerTransport());
}
