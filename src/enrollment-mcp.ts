import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { Authority, Metadata, SaveRequest } from './contracts.js';
import { savePayloadSchema } from './registry.js';

const saveRequestSchema = z.object({
  request_id: z.string().min(20).max(2048), draft_id: z.string().uuid(),
  draft_version: z.number().int().positive(), approval_token: z.string().min(1).max(256), payload: savePayloadSchema,
}).strict();

/** Private enrollment channel for a trusted submitter, never the model or execution bridge.
 * The complete secret-bearing request travels via actual MCP in memory, with no stdio/body logging.
 * Authentication is a server-side authority closure; no caller-supplied principal or confirmed flag exists.
 * currentAuthority must check current administrator session/epoch/permission on every call.
 * User confirmation is independently enforced by Vault.saveApproved against its immutable approval.
 */
export async function createTrustedEnrollmentMcp(options: {
  currentAuthority: () => Authority;
  saveApproved: (authority: Authority, request: SaveRequest) => Metadata;
}) {
  const server = new McpServer({ name: 'trusted-vault-enrollment', version: '1.0.0' });
  server.registerTool('save_credential', {
    description: 'Trusted enrollment submitter only. Save an immutable, explicitly administrator-approved draft; not a model approval tool.',
    inputSchema: saveRequestSchema,
  }, async () => ({ isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: 'enrollment_denied' }) }] }));
  // Keep registered discovery/schema, but parse inside a controlled handler. SDK's default
  // validation formats unrecognized field names into errors, which can itself disclose a secret.
  server.server.setRequestHandler(CallToolRequestSchema, async request => {
    const denied = () => ({ isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error: 'enrollment_denied' }) }] });
    try {
      if (request.params.name !== 'save_credential' || request.params.task) return denied();
      const parsed = saveRequestSchema.safeParse(request.params.arguments);
      if (!parsed.success) return denied();
      const authority = options.currentAuthority();
      if (!authority.session_id) return denied();
      const connection = options.saveApproved(structuredClone(authority), parsed.data);
      return { content: [{ type: 'text' as const, text: JSON.stringify({ connection }) }] };
    } catch { return denied(); }
  });
  const client = new Client({ name: 'trusted-local-draft-submitter', version: '1.0.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  try { await client.connect(clientTransport); }
  catch (error) { await server.close(); throw error; }
  return {
    /** Kept in trusted orchestration code. Do not expose this capability to inference. */
    client,
    async save(request: SaveRequest): Promise<Metadata> {
      const result = await client.callTool({ name: 'save_credential', arguments: structuredClone(request) as unknown as Record<string, unknown> });
      if (result.isError) throw new Error('enrollment_denied');
      const content = result.content as Array<{ type: string; text?: string }>;
      if (!Array.isArray(content) || content.length !== 1 || content[0]?.type !== 'text' || !content[0].text) throw new Error('enrollment_denied');
      const output = JSON.parse(content[0].text) as { connection: Metadata };
      return output.connection;
    },
    async close(): Promise<void> { await client.close(); await server.close(); },
  };
}
