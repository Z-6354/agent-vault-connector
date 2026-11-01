# Hermes evidence

Date: 2026-11-01. **Native runtime validation: BLOCKED by source isolation review.** This task performed installed-source reads/searches and public official-documentation fetches only. No Hermes launcher, Hermes Python module, model client, password-manager CLI, MCP server, or account action was executed. No existing runtime config, auth, dotenv, token, vault, or credential file was opened. No isolated profile was configured and no project implementation was changed.

## Installation identity and check status

- Supplied prior observation (not re-run here): CLI `/path/to/home/.local/bin/hermes`; installation `/path/to/home/.hermes/hermes-agent`; version brief `v0.22.5`, local commit `bf0203a794a0`.
- Source metadata read: `/path/to/home/.hermes/hermes-agent/.git/HEAD:1` contains `bf0203a794a07aac3ff764972ab9087baa4e4f4e`.
- Source version search below found the packaging placeholder `version = "0.0.0"` and release date `2026.9.24`. Neither establishes the current `hermes --version` output. The lazy version accessor resolves an installation stamp rather than a fixed version constant (`hermes_cli/__init__.py:10-39`). No installation stamp was opened.

| Check | Status / actual output |
| --- | --- |
| Installed launcher source | READ, as quoted below |
| `hermes --version` | NOT RUN; startup and update-check concerns below |
| `hermes --help`, `hermes mcp --help`, `hermes config --help` | NOT RUN; parser source inspected only |
| `hermes config set ...` in new `HERMES_HOME` | BLOCKED; CLI loads the installed checkout's dotenv path |
| Native MCP discovery / registry schema retrieval | BLOCKED; no configuration bypass, module import, or SDK-only substitute |
| Synthetic MCP server / project bridge through Hermes | NOT RUN |
| `hermes chat` / actual agent task | NOT RUN; no approved model endpoint; independent blocker |
| Native vault lookup, unlock, password fill, login reuse | SOURCE/DOCS ONLY; no credentials accessed or website actions attempted |

## Why a new home is insufficient

Every source path in this section is under `/path/to/home/.hermes/hermes-agent/` unless explicitly absolute. These are source observations, not claims that a forbidden read or write occurred.

1. `/path/to/home/.local/bin/hermes:1-2` forwards to the installation's inner launcher:

   ```sh
   #!/bin/sh
   exec /path/to/home/.hermes/hermes-agent/.hermes/bin/hermes "$@"
   ```

   The inner launcher `/path/to/home/.hermes/hermes-agent/.hermes/bin/hermes:2-6` invokes the managed Python with `-I` and inserts the installed source root. Lines 114-132 import `hermes_bootstrap` before `hermes_cli.main`. Thus the normal CLI does not consist of argparse alone. The launcher's recovery fallback itself contains installation writes and removals (lines 52-73); it was read as code and never invoked.

2. `hermes_bootstrap.py:511-558` runs interrupted-update recovery on import. It calls `restore_interrupted_pull(_root)` at line 540, invokes that wrapper at line 544, and may relaunch. Lines 577-621 activate the startup package machinery before normal command dispatch:

   ```python
   _launch_python = prepare_launch(_root, sys.argv[1:])  # 588
   # ...
   recover_if_needed(_root)                            # 612
   activate_dependencies(_root)                       # 613
   ```

   `hermes_cli/venv_sync.py:343-459` explains and implements possible checkout adoption, source-update completion, dependency synchronization, launcher publication, and interpreter relaunch. It has skip conditions, including metadata flags and `HERMES_DISABLE_LAZY_INSTALLS` (lines 367-377), but those do not remove the separate recovery and dotenv paths. A custom temporary home can also create its own dependency environment (`venv_sync.py:462-471`). No startup-skip flags were experimentally tried.

3. `hermes_cli/main.py:423` fixes `PROJECT_ROOT` to the installed source root. After profile resolution, lines 708-716 explicitly load that root's dotenv:

   ```python
   from hermes_cli.config import get_hermes_home
   from hermes_cli.env_loader import load_hermes_dotenv
   load_hermes_dotenv(project_env=PROJECT_ROOT / ".env")  # 716
   ```

   `hermes_cli/env_loader.py:549-573` checks, sanitizes and loads this supplied path even with a new profile home:

   ```python
   if project_env_path and project_env_path.exists():
       _sanitize_env_file_if_needed(project_env_path)     # 556-557
   # ... user home and .op.env handling ...
   if project_env_path and project_env_path.exists():
       _load_dotenv_with_fallback(project_env_path, override=not loaded, load_pass=load_pass)
       loaded.append(project_env_path)                   # 571-573
   ```

   An isolated `HOME`, `HERMES_HOME`, XDG directories, `TMPDIR`, scratch cwd and cleared environment do not redirect this code-root fallback. This is sufficient to block help/config execution without probing whether the production dotenv exists or contains secrets. No such probe was made.

4. Additional boundaries: `hermes_cli/main.py:593-669` can follow a sticky profile before imports; `hermes_constants.py:93-101,188-195` defines home/root resolution. `hermes_cli/managed_scope.py:30-59` defaults managed configuration to `/etc/hermes`, with a `HERMES_MANAGED_DIR` override; `env_loader.py:597-599,629-644` can load external sources and managed dotenv. These would also require isolation. `hermes_cli/_startup_fast.py:187-240` calls `check_for_updates(passive=True)` at line 228, so `--version` is not assumed to be network-free. It also calls install-method detection at lines 205-214.

Decision: **do not run the normal launcher, help, config writer, or native discovery.** No production config inspection, source monkeypatch, hand-written profile configuration, direct writer bypass, or installation mutation was used to get around this blocker. Consequently there is no cleared-environment runtime command to report: the source gate stopped before creating or launching an isolated runtime. Any future permitted run would need a Python `subprocess` environment built from explicit constants only, with fresh `HOME`, `HERMES_HOME`, XDG config/cache/data, `TMPDIR`, safe `PATH`, and scratch cwd; inheriting `os.environ` would not satisfy the authorization.

## Native MCP and CLI help: source evidence only

- `hermes_cli/subcommands/mcp.py:9-70` declares `hermes mcp` as client connection management, with `add`, `remove`, `list`, `test`, `configure`, `login`, `reauth`, and catalog commands. Its parser text says running Hermes itself as an MCP server requires the `mcp-serve` plugin (lines 13-16). These are not captured help outputs.
- `hermes_cli/subcommands/config.py:27-34` declares `config set <key> <value> [--force]`. Required isolated MCP configuration via this CLI was not attempted because of the startup blocker.
- Native client implementation `tools/mcp_tool.py:1-10` describes discovering configured servers and registering into Hermes's tool registry. The actual entry point located is `tools/mcp_tool_discovery.py:604-658`, `discover_mcp_tools(allowed_mcp_names=None)`. It loads configuration, imports the optional SDK, and calls `register_mcp_servers`. No successful import/re-export from the `mcp_tool` facade is asserted.
- `tools/mcp_tool_config.py:690-718` loads `mcp_servers` via `hermes_cli.config.load_config()`, calls `load_hermes_dotenv()` (without a project argument at this particular seam), and can add portable MCP servers. This narrower source path was not used to bypass the required CLI configuration step.
- `tools/registry.py:994` defines `get_schema(name)`. Reading that source or a static schema is not native runtime discovery, a tool call, or an actual agent task. None of those runtime results is claimed here.

## Existing native credential and login reuse

The installed source already provides a native browser-vault feature. This is separate from attaching a generic MCP bridge.

- `tools/browser_vault_tool.py:588-612` defines `BROWSER_VAULT_SCHEMA` with actions `list`, `fill`, `save_login`, `enter_code`, `unlock`; lines 657-664 register `browser_vault` in toolset `browser`. Lines 40-48 gate availability on browser support. `hermes_cli/subcommands/vault.py:8-16` describes encrypted autofill with model-visible handles/identifiers and server-side password injection.
- `agent/vault_backends/base.py:103-135` detects `op` / `bw` and enables installed managers unless `vault.<manager>.enabled` is explicitly false. `agent/vault_backends/__init__.py:1-13` describes local, `op:` and `bw:` handles and session unlocking.
- `agent/vault_backends/onepassword.py:75-102,105-150` unlocks through `op signin --raw` with stdin, lists Login items, resolves passwords via `op item get ... --reveal`, and retrieves OTP through `--otp`. A configured service-account token can avoid the interactive unlock path. No manager CLI was run here.
- `agent/vault_backends/bitwarden.py:1-7,58-86,88-132` distinguishes personal/org Password Manager `bw` from Secrets Manager `bws`; it unlocks with `--passwordenv` in the child environment, lists login items, and resolves password/TOTP. No manager CLI was run here.
- `tools/browser_vault_tool.py:451-478` requires exact saved origins; lines 504-568 resolve a secret server-side, register redaction, inject via supervised browser evaluation, and return counts/metadata. The secret-bearing evaluation refuses the argv-based fallback (`118-166`). These are implementation observations, not end-to-end security guarantees or successful sign-ins.

Official live documentation fetched successfully through `WebFetch` (public documentation only, 2026-11-01):

| Official URL | Status and relevant finding |
| --- | --- |
| https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference | FETCHED. Describes stdio / remote MCP, `mcp_servers`, environment-secret interpolation and per-profile OAuth token reuse. This page alone does not establish `browser_vault` or password-manager website-login support. |
| https://hermes-agent.nousresearch.com/docs/user-guide/features/credential-vault | FETCHED. Describes saved-login reuse, auto-detection of installed/signed-in `op` or `bw`, masked unlock, exact-origin fills, TOTP, and headless limitations. Native tool identity additionally established by installed source above. |
| https://hermes-agent.nousresearch.com/docs/user-guide/secrets/onepassword | FETCHED. Separate `secrets.onepassword` startup provider-key mappings using `op://...` and `op read`, disabled by default. Does not establish website login behavior. |
| https://hermes-agent.nousresearch.com/docs/user-guide/secrets/bitwarden | FETCHED. Separate `secrets.bitwarden` startup provider-key integration using `bws`, a machine-account token and project; disabled by default. Distinct from website-login `bw`. |

Installed documentation source corroboration: `website/docs/user-guide/features/credential-vault.md:8-11,32-65,87-108` describes previously saved logins, local encrypted credentials, manager login reuse, exact stored origins, and unavailable/missing-login errors in headless sessions. `website/docs/user-guide/secrets/onepassword.md:3-19,107-120` describes API-key startup hydration and defaults. `website/docs/user-guide/secrets/bitwarden.md:3-18` describes API-key hydration via `bws`. Live documentation may advance beyond this checkout; source claims above refer to the installed commit.

Practical implication: evaluate native `browser_vault` before assuming Hermes needs a custom credential-reuse MCP server. Provider API-key hydration, saved website credentials, and remote MCP OAuth reuse are three different documented capabilities. Existing browser cookies/session reuse was not tested or inferred from password-vault support. Local native behavior and compatibility with this project's bridge remain unvalidated.

## Exact read-only evidence commands and selected outputs

Tools used were `Read` for the source excerpts above, `WebFetch` for the four official URLs, and `Bash` for source searches. No command below invokes Hermes. Searches exited 0 unless otherwise noted; paths refer only to code or source metadata.

```sh
rg -n 'load_hermes_dotenv\(project_env|project_env_path.*exists|_sanitize_env_file_if_needed\(project_env_path|_load_dotenv_with_fallback\(project_env_path|_DEFAULT_MANAGED_DIR =|_setttle_interrupted_update|_settle_interrupted_update\(\)|_launch_python = prepare_launch|recover_if_needed\(_root\)|activate_dependencies\(_root\)|check_for_updates\(passive=True\)' /path/to/home/.hermes/hermes-agent/hermes_cli/main.py /path/to/home/.hermes/hermes-agent/hermes_cli/env_loader.py /path/to/home/.hermes/hermes-agent/hermes_cli/managed_scope.py /path/to/home/.hermes/hermes-agent/hermes_bootstrap.py /path/to/home/.hermes/hermes-agent/hermes_cli/_startup_fast.py
```

Selected exact output:

```text
/path/to/home/.hermes/hermes-agent/hermes_cli/main.py:716:load_hermes_dotenv(project_env=PROJECT_ROOT / ".env")
/path/to/home/.hermes/hermes-agent/hermes_cli/env_loader.py:556:    if project_env_path and project_env_path.exists():
/path/to/home/.hermes/hermes-agent/hermes_cli/env_loader.py:557:        _sanitize_env_file_if_needed(project_env_path)
/path/to/home/.hermes/hermes-agent/hermes_cli/env_loader.py:571:    if project_env_path and project_env_path.exists():
/path/to/home/.hermes/hermes-agent/hermes_cli/env_loader.py:572:        _load_dotenv_with_fallback(project_env_path, override=not loaded, load_pass=load_pass)
/path/to/home/.hermes/hermes-agent/hermes_cli/managed_scope.py:31:_DEFAULT_MANAGED_DIR = Path("/etc/hermes")
/path/to/home/.hermes/hermes-agent/hermes_bootstrap.py:544:_settle_interrupted_update()
/path/to/home/.hermes/hermes-agent/hermes_bootstrap.py:588:        _launch_python = prepare_launch(_root, sys.argv[1:])
/path/to/home/.hermes/hermes-agent/hermes_bootstrap.py:612:        recover_if_needed(_root)
/path/to/home/.hermes/hermes-agent/hermes_bootstrap.py:613:        activate_dependencies(_root)
/path/to/home/.hermes/hermes-agent/hermes_cli/_startup_fast.py:228:        status = check_for_updates(passive=True)
```

```sh
rg -n '^(version|__version__|VERSION|dynamic)\s*=' /path/to/home/.hermes/hermes-agent/pyproject.toml /path/to/home/.hermes/hermes-agent/hermes_cli/__init__.py
```

Exact output:

```text
/path/to/home/.hermes/hermes-agent/pyproject.toml:7:version = "0.0.0"
```

```sh
rg -n '^def discover_mcp_tools|^    def get_schema|^    name="browser_vault"|^    toolset="browser"|^            "action":|^version =|^__release_date__' /path/to/home/.hermes/hermes-agent/tools/mcp_tool_discovery.py /path/to/home/.hermes/hermes-agent/tools/registry.py /path/to/home/.hermes/hermes-agent/tools/browser_vault_tool.py /path/to/home/.hermes/hermes-agent/pyproject.toml /path/to/home/.hermes/hermes-agent/hermes_cli/__init__.py
```

Exact output entries (ordering normalized for readability):

```text
/path/to/home/.hermes/hermes-agent/tools/mcp_tool_discovery.py:604:def discover_mcp_tools(allowed_mcp_names: Optional[list[str]] = None) -> list[str]:
/path/to/home/.hermes/hermes-agent/tools/registry.py:994:    def get_schema(self, name: str) -> Optional[dict]:
/path/to/home/.hermes/hermes-agent/tools/browser_vault_tool.py:606:            "action": {"type": "string", "enum": ["list", "fill", "save_login", "enter_code", "unlock"]},
/path/to/home/.hermes/hermes-agent/tools/browser_vault_tool.py:658:    name="browser_vault",
/path/to/home/.hermes/hermes-agent/tools/browser_vault_tool.py:659:    toolset="browser",
/path/to/home/.hermes/hermes-agent/pyproject.toml:7:version = "0.0.0"
/path/to/home/.hermes/hermes-agent/hermes_cli/__init__.py:5:__release_date__ = "2026.9.24"
```

File creation precondition checked with `test ! -e /path/to/workspace/agent-vault-connector/docs/evidence/hermes.md` (exit 0, no output). This new evidence file is the Hermes research subtask's only intentional project write; the coordinator separately updated project documentation, build handling, and synthetic test mechanics. No existing files were deleted.
