# Process tools: first usable slice

Ritten currently exposes two synchronous process tools through the same MCP executor, credential scopes, default-deny policy, owner approvals, cancellation, and audit pipeline used by its other built-ins:

- `process.list_allowed` takes `{}` and reports only executable permissions and configured tasks effective for the authenticated client. Executable entries include the effective `working_directories` because a path-scoped executable rule does not grant access in every folder. The tool omits permissions it cannot establish safely and does not return unrelated policy rules or other clients' permissions.
- `process.run` accepts an executable, argument array, authorized `cwd`, optional bounded timeout/output limit, and a small allowlist of environment overrides.
- `process.run_task` accepts only a task name. Its executable, arguments, working folder, and optional timeout come from owner configuration.

The process toolset is off by default. Enabling it does not grant execution. A winning policy rule must match the tool, authorized working folder, and the executable's canonical absolute path using `match.executables`. A task additionally needs its exact name in `match.tasks`. Use `ask` to require owner approval each time. Process arguments and environment overrides are omitted from audit records; output is returned to the calling agent and is not included in audit logs by default.

## Enable a direct process call

Add `process` to `toolsets.enabled`, then add an explicit policy rule. For example, on Windows:

```yaml
toolsets:
  enabled: [ritten, filesystem, coding, process]
  settings:
    process:
      max_concurrent: 4
      default_timeout: 30s
      max_runtime: 30m
      max_output_bytes: 65536
      tasks: {}
policy:
  default: deny
  rules:
    - id: process-self-introspection
      match:
        tools: [process.list_allowed]
      decision: allow
    - id: process-node-in-project
      match:
        tools: [process.run]
        paths: [C:/Projects/example, 'C:/Projects/example/**']
        executables: [C:/Program Files/nodejs/node.exe]
      decision: ask
```

`process.list_allowed` still requires both a client tool scope for `process.list_allowed` and an explicit policy rule such as `process-self-introspection` above. Its executable entries are derived from explicit, resolvable executable paths in `process.run` policy rules. Each entry includes `path`, effective `decision` (`allow` or `ask`), and the concrete configured-root scopes in `working_directories`. Its task entries include only configured tasks that match the authenticated client's tool/path scopes and an effective `process.run_task` policy rule; each includes `name`, canonical `executable`, configured `args`, `cwd`, and `decision`. Denied, unresolved, out-of-scope, or ambiguous entries are omitted.

Example response:

```json
{
  "executables": [
    {
      "path": "C:/Program Files/nodejs/node.exe",
      "decision": "ask",
      "working_directories": ["C:/Projects/example", "C:/Projects/example/**"]
    }
  ],
  "tasks": []
}
```

Policy arrays are exact names/paths except `*` and `**` glob patterns. Confirm the executable's canonical path on the host. The agent can then call `process.run` with `{ "executable": "C:/Program Files/nodejs/node.exe", "args": ["--version"], "cwd": "C:/Projects/example" }`.

Configured tasks use the same executable and folder authorization and require a named task match:

```yaml
toolsets:
  settings:
    process:
      tasks:
        test:
          executable: C:/Program Files/nodejs/node.exe
          args: [node_modules/typescript/bin/tsc, -p, tsconfig.json]
          cwd: C:/Projects/example
          timeout: 2m
policy:
  rules:
    - id: approved-project-test
      match:
        tools: [process.run_task]
        tasks: [test]
        paths: [C:/Projects/example, 'C:/Projects/example/**']
        executables: [C:/Program Files/nodejs/node.exe]
      decision: allow
```

`process.run_task` does not accept command overrides. Task names and definitions are validated at config load; cwd is revalidated against configured filesystem roots and the caller's credential scope each time.

## Limits of this slice

Calls are synchronous and bounded by the server request timeout. Persistent `start`/`poll`/stdin/termination, process inspection/listing, output cursors, dashboard process controls, OS resource quotas, and restart recovery are still in progress. A cwd check does not sandbox a child: launched programs retain Ritten's operating-system account permissions. Direct shell script files (`.cmd`, `.bat`, `.ps1`) are rejected. No shell is invoked implicitly; a shell executable such as `powershell.exe` can be run only when its canonical path is explicitly named in process policy, and then inherits that rule's decision and approval requirement.

Legacy `raw_shell` settings and permissions are not translated. `raw_shell.run` is no longer advertised to MCP clients. Remove the legacy toolset entry and create narrow `process.*` rules only for the executable paths and tasks you intend to authorize.
