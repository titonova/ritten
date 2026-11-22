# Ritten

Ritten is a local-first MCP server that lets AI clients request access to selected files, approved websites, and explicitly authorized local commands. The server runs on the owner's computer; the owner controls its configuration, approval flow, and credentials.

> **Status: pre-release.** Ritten is under active development and has not been certified for production use or for any particular hosted AI platform. Review the security limitations below before exposing a server through a public HTTPS tunnel.

## What it provides

- MCP over HTTP using the official TypeScript SDK.
- OAuth authorization-code flow with PKCE, public-client registration, local consent, short-lived access tokens, and refresh-token rotation.
- A separate loopback-only owner console for approvals, client management, access controls, and audit review.
- Default-deny, ordered policy rules and per-credential tool, path, and domain scopes.
- Filesystem, coding, web-fetch, and synchronous process toolsets.
- Optional local custom toolsets and configured external stdio MCP servers.
- Redacted JSON Lines audit logs with retention and size limits.

Ritten is not a filesystem sandbox. Filesystem checks and working-directory rules do not reduce the operating-system permissions of Ritten or its child processes. See [Security model](docs/security-model.md).

## Requirements

- Node.js 22 or later.
- A supported OS credential store for owner authentication.
- For remote clients: an HTTPS tunnel or reverse proxy that forwards only the MCP listener.

## Build and first run

From a clone of this repository:

```sh
npm ci
npm run build
node dist/cli/index.js setup
```

Setup creates the local configuration and asks for an owner passphrase. It does not grant tool access. Find the configuration and data locations with:

```sh
node dist/cli/index.js paths
```

Edit the generated configuration to add an existing filesystem root and explicit policy rules. [examples/config.yaml](examples/config.yaml) shows the supported configuration shape; replace its example project path with a folder you own. Validate and start Ritten:

```sh
node dist/cli/index.js config validate
node dist/cli/index.js start --foreground
```

The default MCP endpoint is `http://127.0.0.1:7337/mcp`; the owner console is `http://127.0.0.1:7338/local`. Keep the foreground process running while clients use the server. On Windows, `start.bat` launches the same server with a live audit display after checking the configured ports and any existing Ritten lock.

## Connect a remote client

Ritten does not start or manage a tunnel. Configure an HTTPS tunnel to forward **only** the MCP listener on port `7337`; keep the owner console on its loopback port. Set `server.public_url` to the public HTTPS origin without `/mcp`, validate the config, and restart Ritten. Point the client at `<public-origin>/mcp`.

Clients discover Ritten's OAuth metadata and register as public clients. Approve new connections locally in the owner console or with:

```sh
node dist/cli/index.js approvals list
node dist/cli/index.js approvals approve REQUEST_ID
```

OAuth consent only creates a client credential. Tool calls still need an enabled toolset, credential scope, an authorized filesystem root or domain, and a matching policy rule. Path scopes are captured when an OAuth token is issued and are updated on token refresh; reconnect a client to apply a new scope immediately.

## Toolsets

Toolsets are disabled unless listed in `toolsets.enabled`. Adding a toolset does not authorize its operations; credentials and policy must also grant them.

| Toolset      | Tools                                                                                                          | Notes                                                                                                                                        |
| ------------ | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `ritten`     | `ritten.health`                                                                                                | Reports public health and enabled toolsets.                                                                                                  |
| `filesystem` | `filesystem.read_file`, `list_directory`, `stat`, `search`, `write_file`, `create_directory`, `move`, `delete` | Roots and read/write access are configured explicitly. Reads are bounded; delete is non-recursive.                                           |
| `coding`     | `coding.read`, `grep`, `glob`, `edit`, `write`                                                                 | Line-aware file access, literal search, glob, exact-text edit, and bounded write.                                                            |
| `web`        | `web.fetch`                                                                                                    | HTTPS GET to explicitly allowed public domains. No cookies or authorization headers are forwarded.                                           |
| `process`    | `process.list_allowed`, `run`, `run_task`                                                                      | Disabled by default. Direct executable plus argument-array execution; named tasks come from owner config. Calls are synchronous and bounded. |
| Custom       | Owner-defined                                                                                                  | Local TypeScript/JavaScript tools loaded from configured directories. Treat tool code as trusted code.                                       |
| External     | Owner-defined                                                                                                  | Explicitly configured stdio MCP servers, invoked through the common authorization pipeline.                                                  |

The process toolset does not provide a persistent shell or process session. Shell interpretation is never implicit. Child processes run with Ritten's operating-system account permissions.

## Access and approvals

Ritten's policy default is `deny`. Rules are evaluated in order and match tool names and, where applicable, client IDs, paths, domains, executable paths, and task names. Use `allow` for operations that can proceed, `ask` to require local owner approval, and `deny` to block. An approval that expires is denied.

A filesystem root is a maximum access boundary for Ritten's filesystem tools; a read-only root cannot be made writable by policy. Credential scopes narrow access further. A configured `cwd` is not process isolation and does not prevent a child process from accessing other files permitted to the operating-system account.

See [Quickstart](docs/QUICKSTART.md), [toolsets](docs/toolsets.md), and [process tools](docs/process-tools.md) for configuration examples.

## Owner console and audit logs

Open `http://127.0.0.1:7338/local` on the machine running Ritten and unlock it with the owner passphrase. The console shows approvals, OAuth clients, configured access, tool events, and recent audit records. It also provides pause, panic, restore, and client-revocation controls.

Audit records include requests and outcomes. Tool results are omitted by default; enable `logging.include_results` to record bounded, redacted results. Redaction cannot identify every secret in arbitrary file contents or command output, so enable result logging only when appropriate. Logs rotate according to `logging.max_file_size` and `logging.retention`.

## CLI reference

Run `node dist/cli/index.js --help` for the complete command list. Common commands:

```text
setup
paths
config path
config validate
config show --effective
tools list
status
approvals list | approve ID | deny ID
clients list | revoke ID | revoke-all
tokens list | create JSON | revoke ID | revoke-all
logs tail
pause | resume | panic
setup access --restore
stop
```

`start --foreground` runs in the current terminal. `stop` and owner mutations require local owner authentication. `panic` revokes credentials and pauses access; restore does not revive old credentials or resume access automatically.

## Security notes

- Public clients are untrusted. Do not give them broader tool, path, or domain scopes than needed.
- Forward only the MCP listener. Never expose the owner console through a public tunnel.
- Process and custom tools run with the Ritten process's operating-system permissions; Ritten does not contain malicious code.
- Do not store credentials in the repository or expose them through a tool root.
- Review audit output before sharing it; logs can include user-provided text and tool results if enabled.

Read the full [security model](docs/security-model.md) before enabling remote access or process execution.

## Development

```sh
npm ci
npm run format:check
npm run typecheck
npm test
```

The CI workflow runs these checks on Node.js 22 and 24 across Windows, macOS, and Linux. CI configuration is not a substitute for release verification on each target platform or with each hosted MCP client.

## License

Apache-2.0. See [LICENSE](LICENSE).
