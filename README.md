# Ritten

**A permissioned MCP gateway for your own machine.**

Ritten turns a computer you control into a secure, auditable MCP server. An AI
assistant can use the tools you explicitly expose—such as reading an approved
folder, fetching an approved website, or running a carefully gated command—while
you retain final authority on the machine.

Ritten follows one rule above all others: remote clients may request less access,
but they can never grant themselves more.

> [!WARNING]
> Ritten can expose capabilities on your computer to remote AI clients. Start
> with read-only tools, keep scopes narrow, review approval prompts, and enable
> raw command execution only when you understand the consequences.

## Contents

- [Why Ritten](#why-ritten)
- [Features](#features)
- [Requirements and installation](#requirements-and-installation)
- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Built-in toolsets](#built-in-toolsets)
- [Policy and approvals](#policy-and-approvals)
- [Authentication](#authentication)
- [Configuration](#configuration)
- [Tunnel providers](#tunnel-providers)
- [Command-line reference](#command-line-reference)
- [Custom toolsets](#custom-toolsets)
- [External MCP servers](#external-mcp-servers)
- [Results and audit logging](#results-and-audit-logging)
- [Security model](#security-model)
- [Operations and troubleshooting](#operations-and-troubleshooting)
- [Development contract](#development-contract)
- [Version 1 boundaries](#version-1-boundaries)
- [License](#license)

## Why Ritten

Hosted AI platforms can connect to remote MCP servers, but many useful actions
need to happen on a user's own computer. Ritten provides that bridge without a
central relay, command queue, or shared Ritten cloud.

The important safety decisions remain local:

- You choose which toolsets load.
- You choose which paths, domains, commands, and clients are allowed.
- Every tool call is allowed, denied, or held for local approval.
- New toolsets are discovered but never enabled automatically.
- Sensitive capabilities can only be enabled from the machine itself.
- Every request and result is recorded by default.
- You can pause access or revoke every credential immediately.

Ritten is single-owner and single-machine by design. Run one instance on each
computer you want to expose.

### What Ritten is not

- **Not a relay or queue.** Requests go directly to the running machine. If the
  computer is asleep, offline, or Ritten is stopped, the request fails.
- **Not multi-tenant.** One instance represents one computer and one owner.
- **Not a custom protocol.** Ritten uses MCP, OAuth, JSON Schema, HTTPS, and
  standard HTTP errors.
- **Not a sandbox.** Version 1 tools run with the operating-system permissions
  of the Ritten process. Custom tools are trusted code.
- **Not remote administration by default.** Raw shell access starts disabled.

## Features

- MCP over Streamable HTTP using the official TypeScript SDK.
- OAuth 2.1 with PKCE and dynamic client registration.
- Optional bearer tokens for scripts and clients that support headers.
- Local consent for every new OAuth connection.
- Ordered, deterministic `allow`, `ask`, and `deny` policy rules.
- Argument-level scopes for filesystem paths, web domains, and commands.
- Local approval flow with automatic denial on timeout.
- Pluggable tunnels, with Tailscale Funnel as the default.
- Built-in filesystem, web, health, and raw-shell tools.
- File- or folder-based TypeScript and JavaScript custom tools.
- Wrapping of local external MCP servers over standard input/output.
- Structured results, configurable caps, and chunked file reads.
- Request deduplication and MCP support for long-running tasks.
- JSON Lines audit logs with rotation; optional SQLite storage.
- Pause, credential revocation, and panic-lock controls.
- No analytics or remote telemetry.

## Requirements and installation

Requirements:

- Node.js 22 or newer.
- Windows 10/11, macOS 13 or newer, or a current Linux distribution.
- A tunnel provider or your own HTTPS reverse proxy.
- Tailscale 1.70 or newer when using the default Funnel adapter.
- A computer configured to remain awake while access is needed.

Ritten listens on loopback only and does not open a router port.

Install the command globally:

```bash
npm install --global ritten-mcp
ritten --version
ritten doctor
```

Default configuration locations:

| Platform | Configuration |
| --- | --- |
| Windows | `%APPDATA%\Ritten\config.yaml` |
| macOS | `~/Library/Application Support/Ritten/config.yaml` |
| Linux | `$XDG_CONFIG_HOME/ritten/config.yaml` or `~/.config/ritten/config.yaml` |

Run `ritten paths` to print the exact configuration, data, log, and toolset paths
for the current machine. Settings and custom tools live outside the npm package,
so upgrades do not overwrite them.

## Quickstart

### 1. Run setup

```bash
ritten setup
```

The wizard creates a safe default configuration, sets the local consent
passphrase, configures and verifies a tunnel, enables only health and approved
read-only tools, and prints the public connector URL.

The local passphrase is never sent to a remote client. It protects consent and
approval actions performed on the machine.

### 2. Start Ritten

For an interactive first run:

```bash
ritten start --foreground
```

Or install the operating-system service:

```bash
ritten daemon install
ritten start
ritten status
```

Example status:

```text
Ritten 1.0.0
State:          running
Local MCP:      http://127.0.0.1:7337/mcp
Public MCP:     https://my-device.example.ts.net/mcp
Tunnel:         tailscale (healthy)
Authentication: oauth, bearer
Toolsets:       ritten, filesystem
Policy:         active (default deny)
Paused:         no
```

### 3. Connect a client

Add the public MCP address to the AI platform:

```text
https://my-device.example.ts.net/mcp
```

The client discovers Ritten's OAuth metadata and opens an authorization request.
Approve it from the loopback-only local page or terminal:

```bash
ritten approvals list
ritten approvals approve <request-id>
```

The first tool call should be `ritten.health`. It returns the version, enabled
toolsets, their fingerprints, basic system information, and the owner's
configured instructions.

For clients that cannot perform OAuth, create a scoped bearer token:

```bash
ritten tokens create \
  --name backup-script \
  --scope filesystem.read_file \
  --path C:/Backups/**
```

The token secret is displayed once. Send it in an `Authorization: Bearer ...`
header, never in a URL.

## How it works

```text
AI client
   |
   | HTTPS + OAuth or bearer token
   v
Tunnel provider
   |
   | forwards to a loopback listener
   v
Ritten HTTP/MCP server
   |
   +--> authentication
   +--> rate limit and request deduplication
   +--> deterministic policy and scope checks
   +--> optional local approval
   +--> tool executor
   +--> result cap and redaction
   +--> audit log
   |
   v
Structured MCP result
```

The tunnel is transport, not authority. Ritten enforces its own authentication
and policy even when the tunnel provider has additional access controls.

The local listener defaults to `127.0.0.1:7337`. Forwarded host, scheme, and
client-address headers are honored only from explicitly trusted proxies.

### Public endpoints

| Endpoint | Purpose |
| --- | --- |
| `/mcp` | MCP Streamable HTTP endpoint |
| `/.well-known/oauth-protected-resource` | Protected resource metadata |
| `/.well-known/oauth-authorization-server` | OAuth server metadata |
| `/oauth/register` | Dynamic client registration |
| `/oauth/authorize` | Authorization request |
| `/oauth/token` | Code and refresh-token exchange |
| `/oauth/revoke` | Token revocation |
| `/local` | Loopback-only owner console |

Ritten rejects non-loopback requests to `/local`, even if a reverse proxy is
misconfigured.

## Built-in toolsets

Tool names use `toolset.tool` notation.

### `ritten`

- `ritten.health` — version, health, basic system information, owner's
  instructions, and enabled toolset fingerprints.

The health response excludes secrets, full configuration, policy rules, and
complete tool schemas.

### `filesystem`

- `filesystem.read_file`
- `filesystem.list_directory`
- `filesystem.stat`
- `filesystem.search`
- `filesystem.write_file`
- `filesystem.create_directory`
- `filesystem.move`
- `filesystem.delete`

`read_file` accepts `offset` and `length`. Ritten resolves symlinks and
junctions before policy evaluation and rejects any path that escapes an approved
root. Write, move, and delete operations default to `ask` or `deny`.

### `web`

- `web.fetch`

Rules restrict schemes, hosts, ports, methods, redirects, response size, and
private-network access. DNS is checked before connection and after redirects to
reduce server-side request forgery risk.

### `raw_shell`

- `raw_shell.run`

The tool accepts a command, optional working directory, environment allowlist,
and timeout. Results separate standard output, standard error, exit code,
duration, timeout state, and truncation state.

Raw shell is disabled on fresh installations. Enabling it requires an explicit
local action and passphrase confirmation:

```bash
ritten toolsets enable raw_shell
```

No remote request, OAuth client, bearer token, or remotely supplied configuration
can enable it.

## Policy and approvals

Every call passes through the policy engine. Decisions are:

- `allow` — execute when every scope matches.
- `ask` — wait for the owner to approve locally.
- `deny` — reject without execution.

Rules are evaluated from top to bottom; the first match wins. The shipped default
is `deny`. Specific denials should appear above broad allows.

```yaml
policy:
  default: deny
  approval_timeout: 60s
  rules:
    - id: block-sensitive-files
      match:
        tools: [filesystem.*]
        paths:
          - **/.env
          - **/.ssh/**
          - **/*credential*
      decision: deny

    - id: allow-project-reading
      match:
        clients: [primary-assistant]
        tools:
          - filesystem.read_file
          - filesystem.list_directory
          - filesystem.stat
          - filesystem.search
        paths: [C:/Projects/**]
      decision: allow

    - id: approve-project-writing
      match:
        clients: [primary-assistant]
        tools:
          - filesystem.write_file
          - filesystem.create_directory
          - filesystem.move
        paths: [C:/Projects/**]
      decision: ask

    - id: deny-shell
      match:
        tools: [raw_shell.*]
      decision: deny
```

Explain a decision before granting access:

```bash
ritten policy check filesystem.read_file --arg path=C:/Projects/demo/README.md
```

An `ask` decision records the client, tool, normalized arguments, matched rule,
risk annotations, and expiry. Answer it locally:

```bash
ritten approvals list
ritten approvals show <request-id>
ritten approvals approve <request-id> --once
ritten approvals deny <request-id>
```

Approvals are one-time by default. A timeout is always a denial.

Pause all tool execution without stopping the service:

```bash
ritten pause
ritten resume
```

Immediately revoke clients and tokens, cancel pending work, and stop the tunnel:

```bash
ritten panic
```

Recovery after panic lock requires the local consent passphrase.

## Authentication

### OAuth

OAuth is the preferred door. Ritten implements OAuth 2.1 authorization code flow
with PKCE `S256`, dynamic client registration, exact redirect URI matching,
short-lived access tokens, rotating refresh tokens, and revocation.

Approving a new connection requires a local consent action. The public browser
page cannot accept the owner's passphrase, so discovering the public address does
not let a stranger authorize themselves.

```bash
ritten clients list
ritten clients show <client-id>
ritten clients revoke <client-id>
```

### Bearer tokens

Bearer tokens are secondary credentials for scripts and clients that can send
headers. Secrets are shown once and stored only as cryptographic hashes.

| Limit | Default | Meaning |
| --- | ---: | --- |
| Maximum shelf life | 24 hours | Longest lifetime counted from first use |
| Maximum idle life | 1 hour | Expires after no use for this duration |
| Unused expiry | 24 hours | Expires if never used |

```bash
ritten tokens list
ritten tokens show <token-id>
ritten tokens revoke <token-id>
ritten tokens revoke-all
```

Credentials in query strings are not supported. A GET-with-secret mode is
deliberately absent because URLs leak into histories, logs, and proxy records.

## Configuration

Ritten uses one YAML configuration file. Unknown keys and invalid combinations
are startup errors rather than silently ignored settings.

```yaml
version: 1

server:
  host: 127.0.0.1
  port: 7337
  public_url: null
  trusted_proxies: []
  request_timeout: 30s
  result_limit: 200KB

owner:
  instructions: |
    This is the owner's development machine.
    Prefer reading before writing.
    Never modify deployment credentials.

tunnel:
  provider: tailscale
  tailscale:
    public_port: 443
    reset_on_stop: false

auth:
  oauth:
    enabled: true
    access_token_lifetime: 15m
    refresh_token_lifetime: 30d
    dynamic_registration: true
  bearer:
    enabled: true
    max_shelf_life: 24h
    max_idle_life: 1h
    unused_expiry: 24h
  attempts:
    limit: 10
    window: 1m
    lockout: 15m

rate_limits:
  global: 60/minute
  per_client: 60/minute
  concurrent_calls: 4

toolsets:
  directories:
    - ${RITTEN_CONFIG_DIR}/toolsets
  enabled:
    - ritten
    - filesystem
    - web
  settings:
    filesystem:
      roots:
        - path: C:/Projects
          access: read-write
        - path: C:/Users/example/Documents
          access: read-only
      follow_symlinks: false
    web:
      allowed_domains:
        - docs.example.com
        - api.example.com
      allow_private_networks: false
      max_redirects: 5

external_servers: []

policy:
  default: deny
  approval_timeout: 60s
  rules:
    - id: allow-project-reads
      match:
        tools:
          - filesystem.read_file
          - filesystem.list_directory
          - filesystem.stat
          - filesystem.search
        paths: [C:/Projects/**]
      decision: allow

    - id: ask-project-writes
      match:
        tools:
          - filesystem.write_file
          - filesystem.create_directory
          - filesystem.move
        paths: [C:/Projects/**]
      decision: ask

    - id: allow-approved-web
      match:
        tools: [web.fetch]
        domains: [docs.example.com, api.example.com]
      decision: allow

logging:
  enabled: true
  format: jsonl
  directory: ${RITTEN_DATA_DIR}/logs
  max_file_size: 25MB
  retention: 30d
  include_results: true
  result_limit: 32KB
  redact:
    headers: [authorization, cookie, set-cookie]
    keys: [password, passphrase, token, secret, api_key]
```

Validate changes before restart:

```bash
ritten config validate
ritten config show --effective
```

`config show --effective` redacts secrets and identifies the source of each
overridden value.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `RITTEN_CONFIG` | Use a different configuration file |
| `RITTEN_TOOLSET_PATHS` | Prepend custom toolset directories |
| `RITTEN_LOG_LEVEL` | Set `error`, `warn`, `info`, `debug`, or `trace` |
| `RITTEN_NO_COLOR` | Disable terminal colors |

`RITTEN_TOOLSET_PATHS` takes priority over configured directories. When several
directories contain the same toolset name, the first wins and Ritten logs a
warning. Built-in names are reserved and cannot be overridden.

Credentials, signing keys, and the consent passphrase hash are kept in the
operating-system credential store, not YAML or logs.

## Tunnel providers

Ritten's tunnel interface is replaceable. The MCP server and policy engine do not
depend on a specific provider.

| Provider | Best for | Important considerations |
| --- | --- | --- |
| Tailscale Funnel | Default personal setup | Stable tailnet address; TLS terminates on the user's machine; supported public ports are provider-controlled |
| Cloudflare named tunnel | Existing Cloudflare domain | Stable hostname; Cloudflare normally terminates TLS and can inspect plaintext traffic |
| ngrok | Development and evaluation | Easy setup; free-tier request and transfer quotas may be restrictive |
| Manual | Existing reverse proxy or tunnel | You own TLS, availability, proxy headers, and DNS |

```bash
ritten tunnel configure
ritten tunnel test
ritten tunnel status
```

For manual mode:

```yaml
tunnel:
  provider: manual
  manual:
    public_url: https://ritten.example.com
```

Use a stable public address. Temporary random URLs are suitable for testing, not
durable connector configuration.

## Command-line reference

### Setup and process

```text
ritten setup                         Guided initial setup
ritten setup access --restore        Restore access after panic lock
ritten doctor                        Check runtime, config, tunnel, and storage
ritten paths                         Print config, data, logs, and toolset paths
ritten start [--foreground]          Start Ritten
ritten stop                          Stop Ritten
ritten restart                       Restart Ritten
ritten status [--json]               Show service and tunnel health
ritten daemon install                Install the OS background service
ritten daemon uninstall              Remove the OS background service
```

On Windows, Ritten installs a Windows service. On macOS it installs a per-user
LaunchAgent. On Linux it installs a user-level systemd service.

### Access control

```text
ritten clients list|show|revoke      Manage OAuth clients
ritten tokens create|list|show       Manage bearer tokens
ritten tokens revoke|revoke-all      Revoke bearer access
ritten approvals list|show           Inspect pending approvals
ritten approvals approve|deny        Answer an approval locally
ritten pause|resume                   Pause or resume tool execution
ritten panic                          Revoke access and stop the tunnel
```

### Tools and policy

```text
ritten tools list                    List loaded tools and schemas
ritten tools describe <name>         Show one tool
ritten tools call <name>             Make a local diagnostic call
ritten toolsets list                 List discovered and enabled toolsets
ritten toolsets enable <name>        Enable a toolset locally
ritten toolsets disable <name>       Disable a toolset locally
ritten toolsets fingerprint <name>   Print a definition fingerprint
ritten policy validate               Validate policy rules
ritten policy check <tool>           Explain a simulated decision
```

### Tunnel, configuration, and logs

```text
ritten tunnel configure|test|status  Manage the tunnel adapter
ritten config path                   Print the active config path
ritten config edit                   Open the active config
ritten config validate               Validate without starting
ritten config show --effective       Print merged, redacted configuration
ritten logs tail [--follow]          View recent audit activity
ritten logs export                   Export a bounded audit range
```

Every command supports `--help`. Security-sensitive mutations require a local
terminal and may request the consent passphrase.

## Custom toolsets

A toolset is a folder. A tool is either a JavaScript/TypeScript file or a folder
with an `index.ts` or `index.js` entry point.

```text
toolsets/
  notes/
    toolset.yaml
    _shared.ts
    search.ts
    create/
      index.ts
      parser.ts
```

This exposes `notes.search` and `notes.create`.

Rules:

- Names come from folders and filenames, never code metadata.
- Valid names contain letters, digits, underscores, and hyphens.
- Entries beginning with `_` are ignored.
- Built-in names cannot be replaced.
- Discovery does not enable a toolset.
- TypeScript loading uses a pinned, supported runtime compiler.
- A toolset may contain its own `package.json` and dependencies.

An optional manifest describes the toolset:

```yaml
description: Search and maintain the owner's notes
required_scopes:
  - filesystem:C:/Users/example/Notes/**
suggested_policy:
  notes.search: allow
  notes.create: ask
```

Example `search.ts`:

```ts
import { Type } from "@sinclair/typebox";
import { defineTool } from "ritten-mcp/toolkit";

export default defineTool({
  description: "Search the owner's approved notes folder",
  inputSchema: Type.Object({
    query: Type.String({ minLength: 1, maxLength: 200 }),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 50 })),
  }),
  outputSchema: Type.Object({
    matches: Type.Array(Type.Object({
      path: Type.String(),
      excerpt: Type.String(),
    })),
  }),
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  async run(input, context) {
    const matches = await context.files.search({
      root: "notes",
      query: input.query,
      limit: input.limit ?? 10,
    });

    return {
      structuredContent: { matches },
      content: [{
        type: "text",
        text: "Found " + matches.length + " matching notes.",
      }],
    };
  },
});
```

The context exposes scoped helpers for files, HTTP, logging, cancellation, task
progress, and redaction. Prefer them over direct Node APIs because they preserve
configured limits and consistent audit records.

Custom toolsets are ordinary code with the full permissions of the Ritten
process. Policy controls whether a tool is called and with which arguments; it
cannot contain malicious plugin code. Install only code you wrote or reviewed.

Restart Ritten after adding or changing tools. Version 1 does not hot reload.

## External MCP servers

Other languages are supported by wrapping an existing local MCP server over
standard input/output:

```yaml
external_servers:
  - name: image-tools
    command: python
    args: [-m, image_tools_mcp]
    working_directory: C:/Tools/image-tools
    environment:
      PYTHONUTF8: "1"
    startup_timeout: 10s
    call_timeout: 60s
    enabled: true
```

The server appears as an `image-tools` namespaced toolset. Its tools pass through
the same authentication, policy, approval, result limits, and audit logging as
built-in tools.

Arbitrary external servers require explicit local configuration. Their processes
are trusted code and receive only the environment keys listed in configuration.

## Results and audit logging

Tool results are structured MCP content. Ritten preserves separate fields rather
than flattening command output into one string.

The default result limit is 200 KB. A capped response includes:

```json
{
  "truncated": true,
  "originalBytes": 384291,
  "returnedBytes": 204800,
  "continuation": {
    "supported": true,
    "offset": 204800
  }
}
```

Tools use chunking, pagination, or continuation for larger data. Every call has a
timeout and abort signal. Long-running tools use MCP's Tasks extension and return
a task identifier that clients can inspect or cancel.

Ritten deduplicates requests by authenticated client and request identifier.
Replaying a state-changing call does not execute it twice.

### Audit events

Audit logging is enabled by default. Each event records:

- timestamp and event identifier;
- authenticated client and credential type;
- remote network metadata;
- tool name and normalized arguments;
- matched rule and policy decision;
- approval identity and timing;
- duration, result summary, and error details;
- truncation, timeout, cancellation, and deduplication state.

Example JSON Lines event:

```json
{"time":"2026-11-02T09:18:44.128Z","event":"tool.completed","requestId":"req_01...","client":{"id":"client_01...","name":"primary-assistant","auth":"oauth"},"tool":"filesystem.read_file","arguments":{"path":"C:/Projects/demo/README.md","offset":0,"length":16384},"policy":{"decision":"allow","rule":"allow-project-reads"},"result":{"ok":true,"bytes":2814,"truncated":false},"durationMs":19}
```

Secrets are redacted before serialization. Redaction covers headers, known
credential formats, configured key names, nested values, and tool-declared
sensitive fields. Large results are stored truncated with an explicit marker.

```bash
ritten logs tail --follow
ritten logs export --since 24h --format jsonl --output audit.jsonl
```

Log rotation and retention are enforced at startup and after every roll. SQLite
is available where searchable, transactional audit storage is required.

## Security model

### Local authority

The owner-controlled machine is the root of trust. Remote requests may select a
subset of an already granted scope, but they cannot:

- enable a toolset;
- widen a path or domain scope;
- change policy;
- approve an `ask` decision;
- reveal a stored credential;
- disable logging;
- resume a paused or panic-locked instance.

### Prompt injection

A legitimate AI client may be manipulated by text from a website, file, or
command output. Credentials do not solve this. Narrow local policy is the primary
defence:

- expose only necessary tools;
- prefer typed operations over raw shell;
- keep writes and destructive actions on `ask`;
- restrict paths and domains;
- treat tool output as untrusted input;
- review normalized arguments in approval prompts.

### Internet exposure

Assume anyone can reach the public tunnel URL. Ritten enforces authentication,
authorization, rate limits, body limits, timeouts, and safe error responses.
Tunnel-level identity is an additional control, not a replacement.

Authentication failures are throttled by source and client identifier. Error
messages do not reveal whether an unknown client identifier exists.

### Filesystem containment

Filesystem scopes use canonical paths. Ritten rejects traversal, unexpected
device paths, alternate data streams where unsupported by policy, symlink
escapes, and case-normalization tricks. A path that cannot be resolved safely is
denied.

### Web requests

The web tool blocks non-HTTP protocols, embedded credentials, disallowed ports,
private networks by default, unsafe redirects, and oversized responses. DNS
rebinding checks occur at connection time.

### Tunnel trust

Providers differ in the metadata and plaintext they can observe. Review current
privacy, TLS, pricing, and retention terms. Provider limits change, so run
`ritten tunnel test` after setup and upgrades.

### Custom code and raw shell

Custom toolsets and external MCP servers are trusted executable code. Read them,
pin dependency versions, and run Ritten under a low-privilege operating-system
account where practical.

Raw shell is the highest-risk built-in capability. Keep it disabled unless typed
tools cannot perform the job. If enabled, use exact command allowlists,
restricted working folders, short timeouts, minimal environment inheritance, and
local approval for state-changing commands.

### Antivirus and endpoint protection

Software that accepts remote requests and can launch commands may trigger
endpoint security products. Install only published, signed packages and verify
checksums. Do not bypass an alert without inspecting the binary, provenance,
configuration, and requested capability.

### Reporting a vulnerability

Do not open a public issue for an exploitable vulnerability. Use the repository's
private security advisory channel and include the affected version, platform,
reproduction steps, impact, and suggested mitigation. Reports are acknowledged
within three business days.

## Operations and troubleshooting

### Keep the computer available

Ritten has no queue. Configure the computer not to sleep while remote access is
needed. If it is offline, clients receive an ordinary connection failure.

### Update

```bash
npm install --global ritten-mcp@latest
ritten doctor
ritten restart
```

Configuration is validated and migrated before the service is replaced. Custom
toolsets, credentials, and logs live outside the npm package.

Pin a version where reproducible deployments matter:

```bash
npm install --global ritten-mcp@1.0.0
```

### Back up

Back up the configuration, custom toolsets, and audit data reported by `ritten
paths`, or use:

```bash
ritten backup create --output ritten-backup.zip
```

Backups are passphrase-encrypted and never include usable bearer token secrets.

### Rotate or remove access

```bash
ritten tokens revoke-all
ritten clients revoke-all
ritten auth rotate-signing-key
```

Signing-key rotation invalidates active access tokens. The previous verification
key remains only for the configured grace period.

To uninstall:

```bash
ritten panic
ritten daemon uninstall
npm uninstall --global ritten-mcp
```

Configuration and logs remain until explicitly removed with `ritten data purge`.
The purge command prints every target, requires local confirmation, and refuses
to delete paths outside Ritten's data directories.

### The client cannot connect

1. Run `ritten status`.
2. Run `ritten doctor`.
3. Confirm the computer is awake and online.
4. Run `ritten tunnel test`.
5. Confirm the connector uses the public `/mcp` URL.
6. Check firewall and endpoint-security events.

### OAuth never completes

- Keep Ritten running during authorization.
- Check `ritten approvals list` locally.
- Confirm the redirect URI exactly matches its registered value.
- Ensure the system clock is accurate.
- Inspect `ritten logs tail --level warn`.

### A tool is missing

```bash
ritten toolsets list
ritten tools list
ritten config validate
```

A discovered toolset is not necessarily enabled. Restart after changing tool
files. Check for invalid names, duplicate toolsets, missing dependencies, or an
entry beginning with `_`.

### A call is unexpectedly denied

```bash
ritten policy check filesystem.read_file --arg path=C:/Projects/demo/file.txt
```

The explanation includes normalized arguments, matching scopes, the winning
rule, and the default decision. Canonical paths may differ from submitted text.

### Tailscale Funnel is unavailable

- Confirm Tailscale is signed in and connected.
- Confirm Funnel is allowed by the tailnet policy.
- Run `tailscale status` and `ritten tunnel test`.
- Check whether the public port is currently supported.
- Switch to Cloudflare, ngrok, or a manual HTTPS endpoint if necessary.

### Output is truncated

Use pagination, `offset`, or continuation fields. Increase the result cap only
after considering model context, tunnel transfer, memory, and audit storage.

## Development contract

Ritten is implemented in Node.js and TypeScript with the official MCP SDK. The
repository keeps trust boundaries explicit:

```text
src/
  auth/             OAuth, bearer tokens, local consent
  cli/              Command-line interface
  config/           Schema, loading, validation, migration
  executor/         Calls, timeouts, deduplication, tasks
  logging/          Audit events, redaction, storage
  policy/           Rules, scopes, approval decisions
  server/           HTTP and MCP transport
  toolsets/         Loader and built-in toolsets
  tunnels/          Tailscale, Cloudflare, ngrok, manual
  ui/               Loopback-only consent and approval pages
tests/
  unit/
  integration/
  e2e/
```

Install and verify:

```bash
git clone https://github.com/ritten-mcp/ritten-mcp.git
cd ritten-mcp
npm ci
npm run typecheck
npm test
npm run build
```

Security-sensitive changes require tests. The minimum release suite covers:

- OAuth, PKCE, registration, expiry, rotation, and revocation;
- all bearer token lifetime transitions;
- deterministic policy ordering and path/domain scoping;
- symlink, traversal, redirect, and private-network containment;
- approval timeout and local-only enforcement;
- tool loading, reserved names, collisions, and fingerprints;
- result caps, cancellation, and request deduplication;
- log redaction, rotation, and retention;
- one full client-to-tool call through a real tunnel.

Before release, verify the currently stable MCP specification and official SDK,
hosted-platform OAuth requirements, and real transfer behavior through every
documented tunnel provider. Pin protocol and provider assumptions and record
compatibility notes in the release.

### Core implementation invariants

The implementation is incomplete if any of these are false:

1. Every network tool call passes authentication, rate limiting, policy, optional
   approval, execution limits, redaction, and audit logging in that order.
2. Remote input can narrow authority but cannot enable tools or widen scopes.
3. Tool annotations influence suggested defaults but never override owner policy.
4. Built-in toolsets cannot be shadowed by user directories.
5. Merely placing code in a toolset directory never enables it.
6. State-changing requests with the same client and request identifier run once.
7. Approval timeout, internal error, and ambiguous path resolution fail closed.
8. Local owner routes cannot be reached through the public connector.
9. Logs never contain raw tokens, passphrases, authorization headers, or cookies.
10. Fresh installation exposes health and only the minimal access chosen locally.

## Version 1 boundaries

Version 1 deliberately does not include:

- a relay, queue, or delayed execution service;
- multi-user or multi-tenant hosting;
- credentials in GET URLs;
- sandboxed execution;
- AI-based risk classification;
- user-defined preprocessor hooks;
- time-of-day policy schedules;
- hot reload of toolsets;
- automatic retries for state-changing calls.

The executor, policy pipeline, and logging interfaces leave room for sandboxing,
preprocessors, richer deterministic policy engines, and tamper-evident audit
chains without changing the public tool model.

## Naming and trademark note

Ritten is the product name. "MCP" describes protocol compatibility. Ritten is not
an official MCP project and is not endorsed by the protocol's maintainers or LF
Projects, LLC. Review the current LF Projects trademark policy before publishing
names, logos, or promotional material.

## License

Ritten is licensed under the Apache License 2.0.

---

Ritten gives an AI useful access to your machine without giving up local control:
small scopes, explicit policy, visible approvals, revocable credentials, and an
audit trail for every action.
