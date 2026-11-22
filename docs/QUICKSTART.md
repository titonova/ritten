# Quickstart

This guide covers building Ritten from source, configuring its first local project, and connecting an MCP client.

## Build and test

```powershell
npm ci
npm run typecheck
npm test
npm run build
node dist/cli/index.js --help
```

Node.js 22 or newer is required. Ritten stores the owner credential in the operating system's credential store.

## Set up

```powershell
node dist/cli/index.js setup
node dist/cli/index.js paths
```

Setup asks for a passphrase twice without echoing it. It stores only a salted scrypt verifier in the OS credential store and refuses to overwrite existing configuration. No tools are authorized by the initial policy. Runtime state and bearer verifiers go in the data directory; usable bearer secrets are never stored.

Edit the configuration printed by `paths`. `examples/config.yaml` shows the supported schema; replace its example project root with an existing owner-controlled directory. Root folders must exist. Unsupported keys are errors.

Resource patterns use forward slashes. `*` matches characters within a path segment; `**` crosses segments. `C:/Projects/example/**` includes children, not the root itself. Add an exact root pattern if clients need to list that directory. Denials match if any affected path matches; allow/ask rules require all affected paths to match. Rules are evaluated in order.

```powershell
node dist/cli/index.js config validate
node dist/cli/index.js start --foreground
```

Leave the foreground process running. The default MCP URL is `http://127.0.0.1:7337/mcp`. The owner console is `http://127.0.0.1:7338/local`. Only the MCP port may be forwarded through a tunnel. `/local` on the MCP listener is always rejected.

## Connect and authorize

For remote clients, configure a stable manual HTTPS tunnel to port 7337 and set `server.public_url` to its origin, such as `https://device.example.com` (no `/mcp` path). Restart Ritten after editing configuration. The connector address is that origin plus `/mcp`.

Clients discover OAuth metadata and register as public clients. The authorization browser page waits while you approve the connection in the local owner console or terminal:

```powershell
node dist/cli/index.js approvals list
node dist/cli/index.js approvals approve REQUEST_ID
```

The terminal asks for the local passphrase. OAuth consent only permits requests: actual tool calls still require enabled tools, valid scopes, and matching policy. Client-specific policy uses the registered client ID, not its display name.

For clients accepting Authorization headers, create a token using the console-authenticated CLI. In PowerShell:

```powershell
$options = '{"name":"dev-client","client":"dev-client","tools":["ritten.health","filesystem.*"],"paths":["C:/Projects/example/**"],"domains":[]}'
node dist/cli/index.js tokens create $options
```

Copy the returned token once and send it only as `Authorization: Bearer TOKEN`. It expires if unused for 24 hours, after 24 hours from first use, or after one hour idle. Never put tokens in URLs. Call `ritten.health` first, then a scoped read. For `ask` rules, review the exact arguments in the owner console and approve before the configured timeout. Approval time must fit within the total call timeout.

## Controls and diagnostics

```powershell
node dist/cli/index.js status
node dist/cli/index.js tools list
node dist/cli/index.js logs tail
node dist/cli/index.js pause
node dist/cli/index.js resume
node dist/cli/index.js tokens revoke-all
node dist/cli/index.js clients revoke-all
node dist/cli/index.js panic
node dist/cli/index.js setup access --restore
node dist/cli/index.js stop
```

Restore leaves access paused and old credentials revoked. Issue new credentials and resume explicitly. Panic cannot stop a separately managed manual tunnel, but it denies tool use persistently. `stop` requires owner authentication; Ctrl+C also shuts down foreground mode.

MCP JSON-RPC IDs can be reused across stateless HTTP requests. Each call receives a fresh operation ID. Ordinary calls have no automatic retry deduplication: after a timeout or lost response, inspect the resource before retrying a mutation. Clients that support custom headers can send an `Idempotency-Key` header (1?128 letters, digits, `.`, `_`, `~`, or `-`) unique per mutation. Repeating the same key and arguments returns the saved result; changing arguments or authority is rejected. Failed or interrupted keyed mutations remain indeterminate and are not replayed. Keys are scoped to the authenticated client and must not be reused for another operation.

`doctor` checks runtime/config/credential-store availability and reports the configured public origin. It does not claim live provider or hosted-client compatibility. `policy check TOOL JSON` simulates policy matching; it is not a replacement for live credential and canonical-path checks.

For isolated state, set local environment variables `RITTEN_CONFIG` and `RITTEN_DATA_DIR` before setup/start. One process owns each data directory via an exclusive lock. After a crash, verify the old process is gone before manually removing `instance.lock`. Never delete a lock for a running process.

## Additional built-ins

`web.fetch` accepts `{url}`. Enable `web`, add exact `allowed_domains` under `toolsets.settings.web`, grant credential domain scopes, and add a matching policy rule. Only HTTPS GET on port 443 is implemented. Private/special DNS addresses, embedded credentials, excessive redirects, and responses above 128KB are rejected.

The replacement `process.run` and `process.run_task` tools are documented in [process-tools.md](process-tools.md). They remain disabled until `process` is added to `toolsets.enabled`; each call also needs a default-deny policy rule that names an authorized folder and canonical executable path. No legacy `raw_shell` permission is carried over.

See `docs/security-model.md` for filesystem and process limitations, `docs/compatibility.md` for protocol notes, and `docs/toolsets.md` for custom TypeScript/JavaScript and external stdio tools. Ritten does not install itself as an operating-system service or manage tunnel providers. Persistent process sessions, SQLite logging, and backup/restore are not implemented.

## Owner console and live monitoring

Open `http://127.0.0.1:7338/local` and unlock it with the owner passphrase. The console refreshes status, approvals, OAuth clients, tool events, paths, and recent audit records together using one authenticated request. The interval is configurable in the console from 2 to 300 seconds (default 5 seconds) and saved in the browser; **Refresh now** updates immediately. Polling does not create an audit entry. A failed refresh is reported in the console and retried at the chosen interval.

The event monitor displays recorded tool audit events. Select an event to inspect the available request and result in formatted or JSON form. Request content and secrets are redacted, and output is available only when `logging.include_results` was enabled for that call; earlier events or records outside the recent audit tail may have incomplete details. The active Ritten configuration currently enables `logging.include_results: true`, with audit results bounded by `logging.result_limit`. JSON in event details, approval arguments, and audit lines is syntax-highlighted. The Logs section shows the recent audit JSON lines, not a separate process console log. The dashboard displays up to the latest 100 lines of the current audit file.

The Clients section lists registered OAuth clients and allows revocation. An active status means the client has an unexpired access token; it does not prove a network connection is currently open. Individual bearer tokens remain managed by the CLI. The control page's Owner session lifetime selector sets a fixed lifetime of 15 minutes, 1 hour, or 24 hours; saving a change resets existing active owner sessions from that moment. On Windows, selecting a folder opens it in File Explorer and selecting the config file opens it with its default app. Pause, resume, panic lock, restore and approval controls require the unlocked owner session.

The Access Envelope panel shows the loaded global roots and their maximum access modes, enabled toolsets, default policy, and ordered policy rules with their configured match conditions. These are configuration details, not a simulation of a particular client's effective permissions; credentials and first-match policy evaluation still apply.

## Windows one-click start and live audit

From a regular signed-in Windows desktop session, run `start.bat` in the project root. It reads the active config and paths through the Ritten CLI, validates the configuration, checks any existing lock PID against the actual Ritten command before stopping it, confirms configured ports are free, starts the foreground server, and displays the MCP and owner URLs. It then follows newly appended JSONL audit entries in the same window, including file rotation, polling every 400 ms. Press Ctrl+C to stop the started server and return to the prompt. It does not manage or stop ngrok. If the lock PID cannot be verified or a configured port belongs to another process, it stops and leaves that process and lock untouched.

## Coding tools

Enable `coding` and policy rules for the chosen filesystem roots. `coding.read` accepts `path`, `start_line` (1-based, default 1), and `max_lines` (default 200, maximum 500). `coding.grep` accepts `path`, literal `query`, `case_sensitive` (default false), and `max_results` (default 100, maximum 500). `coding.glob` accepts `path`, relative `pattern` using `*`, `**`, and `?`, and `max_results`. Searches visit at most 5000 entries, skip symlinks, and check credential and policy on every visited path. They report truncation. Grep uses literal matching and skips files over 1 MB or invalid UTF-8.

`coding.edit` accepts `path`, `old_text`, `new_text`, and `replace_all` (default false). A missing or ambiguous match fails. `coding.write` accepts `path`, `content`, and `create_only` (default true); set `create_only` to false to overwrite. Writes use a temporary file; edits recheck file contents immediately before replacement, but this is not a fully atomic compare-and-swap against concurrent external writers. Existing local path race limitations apply. Mutations remain subject to policies, approvals, and optional idempotency keys. File content in edit/write arguments is redacted from audit logs.
