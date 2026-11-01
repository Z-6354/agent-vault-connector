# Authoritative Hermes MCP configuration reference

Research date: 2026-11-01. Requested and successfully retrieved through `WebFetch`:

https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference

Actual tool input:

```json
{
  "url": "https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference",
  "prompt": "Extract authoritative MCP configuration options, CLI config set syntax, stdio servers, tool discovery, auth env configuration, runtime restart and security boundaries. Do not treat documentation as proof of agent integration."
}
```

Status: **documentation content returned**. A numeric HTTP status, response headers, and full raw response were not supplied by this tool and were not separately collected for this URL. The following is a summary of that returned evidence, not a transcript of native runtime execution.

- Native definitions use `mcp_servers` keyed by server name. Stdio definitions use `command`, `args`, `env`; remote definitions use `url` and optional `headers`.
- Configuration options include `enabled`, timeouts, `protocol`, `transport`, lifecycle, tool inclusion/exclusion, and lazy connection. Lazy schema reuse requires a previous live connection; this task did not create one.
- Native registered tool identifiers follow `mcp__<server>__<tool>` with identifier normalization. Tool filters use original MCP tool names.
- `${VAR}` / `${env:VAR}` substitution uses active-profile secret sources with process-environment fallback. This is a documented configuration mechanism, not authorization to inspect those sources.
- Remote authentication supports headers and `auth: oauth`; OAuth credentials persist per profile and may refresh. TLS configuration includes certificate verification and client certificate/key options.
- `/reload-mcp` reloads MCP servers. `hermes mcp login protected_api --flow device` is documented for device authorization. Neither command was executed.
- The retrieved text did not contain `hermes config set` assignment syntax. The user's requirement to use that command remains binding; no hand-edited profile was substituted.
- `enabled: false` disables connection/discovery/registration. Untrusted server approvals and server-supplied read-only hints are policy settings, not independently verified safety guarantees.

The reference is authoritative for configuration research. It proves neither installation of an MCP server nor schema discovery, token migration, actual agent task execution, or compatibility with this project's retained experimental vault. See [Hermes source/isolation evidence](hermes.md) for why native runtime discovery remained blocked.
